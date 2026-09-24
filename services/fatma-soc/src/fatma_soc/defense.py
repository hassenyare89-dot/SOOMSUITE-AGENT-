"""Defensive-action workflow: recommend → approve → execute (→ expire/revert).

* FATMA (the model or the engine) can only *recommend*. Recommendations become ``waf_actions``
  rows in RECOMMENDED state.
* Anything executable requires an approval record from the approval service whose payload hash
  matches the exact action; the approval is consumed (single use) immediately before execution.
* Tenants start in ``recommend_only`` mode. In ``preapproved_low_risk`` mode, only narrowly
  scoped, time-boxed, single-target low-risk actions with high-confidence evidence are
  auto-approved — by the approval service's policy, not by FATMA.
* High-risk actions (country blocks, account disablement, credential rotation, firewall/DNS/
  infrastructure changes, shutdowns, data deletion, network isolation) always need a human.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from platform_core.db.models import Integration, Tenant, WafAction
from platform_core.errors import Conflict, NotFound, UpstreamUnavailable, ValidationFailed
from platform_core.schemas.enums import (
    LOW_RISK_DEFENSE_ACTIONS,
    DefenseActionStatus,
    DefenseActionType,
    FatmaMode,
)
from platform_core.security.crypto import canonical_json, sha256_hex

log = logging.getLogger(__name__)
MAX_TTL = {True: 3600, False: 7 * 86400}  # low-risk / high-risk


def action_payload(tenant_id: uuid.UUID, action: WafAction) -> dict[str, Any]:
    """The exact, canonical payload that approvals are bound to."""
    return {"tenant_id": str(tenant_id), "action_type": f"defense.{action.action_type}",
            "waf_action_id": str(action.id), "provider": action.provider, "target": action.target,
            "params": action.params, "ttl_seconds": action.ttl_seconds,
            "confidence": action.params.get("confidence", 0)}


def validate_target(action_type: DefenseActionType, target: str) -> str:
    if action_type in (DefenseActionType.CHALLENGE_IP, DefenseActionType.TEMP_BLOCK_IP):
        net = ipaddress.ip_network(target, strict=False)
        if not net.is_global:
            raise ValidationFailed("refusing to act on a non-public address")
        if net.num_addresses > (256 if net.version == 4 else 2**64):
            raise ValidationFailed("target range too broad")
        return str(net) if net.num_addresses > 1 else str(net.network_address)
    if action_type is DefenseActionType.BLOCK_COUNTRY:
        if not (len(target) == 2 and target.isalpha()):
            raise ValidationFailed("country must be an ISO-3166 alpha-2 code")
        return target.upper()
    if action_type is DefenseActionType.RATE_LIMIT_PATH:
        if not target.startswith("/") or len(target) > 200:
            raise ValidationFailed("path must start with /")
        return target
    if not target or len(target) > 200:
        raise ValidationFailed("invalid target")
    return target


# ------------------------------------------------------------------------ providers
class DefenseProvider(Protocol):
    name: str

    async def apply(self, action: WafAction) -> str: ...

    async def revert(self, action: WafAction) -> None: ...


class ManualProvider:
    """No automation configured: approval produces a runbook task for a human."""

    name = "none"

    async def apply(self, action: WafAction) -> str:
        return "manual-runbook"

    async def revert(self, action: WafAction) -> None:
        return None


class CloudflareProvider:
    """Cloudflare IP Access Rules (zone scope). Token needs only Zone:Firewall Services:Edit."""

    name = "cloudflare"
    api = "https://api.cloudflare.com/client/v4"
    MODES = {DefenseActionType.TEMP_BLOCK_IP: "block",
             DefenseActionType.CHALLENGE_IP: "managed_challenge",
             DefenseActionType.BLOCK_COUNTRY: "block"}

    def __init__(self, token: str, zone_id: str, client: httpx.AsyncClient | None = None) -> None:
        self._headers = {"Authorization": f"Bearer {token}"}
        self._zone = zone_id
        self._http = client or httpx.AsyncClient(timeout=15)

    async def apply(self, action: WafAction) -> str:
        at = DefenseActionType(action.action_type)
        if at not in self.MODES:
            return "manual-runbook"
        is_country = at is DefenseActionType.BLOCK_COUNTRY
        target_kind = "country" if is_country else (
            "ip_range" if "/" in action.target else
            "ip6" if ":" in action.target else "ip")
        resp = await self._http.post(
            f"{self.api}/zones/{self._zone}/firewall/access_rules/rules", headers=self._headers,
            json={"mode": self.MODES[at], "configuration": {"target": target_kind,
                                                             "value": action.target},
                  "notes": f"FATMA {action.id} approval {action.approval_id} "
                           f"expires {action.expires_at.isoformat() if action.expires_at else ''}"})
        if resp.status_code not in (200, 201):
            raise UpstreamUnavailable("cloudflare rule creation failed")
        return str(resp.json()["result"]["id"])

    async def revert(self, action: WafAction) -> None:
        if not action.provider_ref or action.provider_ref == "manual-runbook":
            return
        resp = await self._http.delete(
            f"{self.api}/zones/{self._zone}/firewall/access_rules/rules/{action.provider_ref}",
            headers=self._headers)
        if resp.status_code not in (200, 404):
            raise UpstreamUnavailable("cloudflare rule removal failed")


class AwsWafProvider:
    """AWS WAFv2 IP set membership (block/challenge rules reference the IP set)."""

    name = "aws_waf"

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config

    def _client(self) -> Any:
        try:
            import boto3  # type: ignore[import-not-found]
        except ImportError as exc:
            raise UpstreamUnavailable("boto3 is not installed in this image") from exc
        return boto3.client("wafv2", region_name=self.config.get("region", "us-east-1"))

    def _update(self, action: WafAction, add: bool) -> None:
        client = self._client()
        kw = {"Name": self.config["ip_set_name"], "Id": self.config["ip_set_id"],
              "Scope": self.config.get("scope", "REGIONAL")}
        current = client.get_ip_set(**kw)
        addrs = set(current["IPSet"]["Addresses"])
        net = str(ipaddress.ip_network(action.target, strict=False))
        addrs = addrs | {net} if add else addrs - {net}
        client.update_ip_set(**kw, Addresses=sorted(addrs), LockToken=current["LockToken"])

    async def apply(self, action: WafAction) -> str:
        if DefenseActionType(action.action_type) not in (DefenseActionType.TEMP_BLOCK_IP,
                                                         DefenseActionType.CHALLENGE_IP):
            return "manual-runbook"
        import asyncio

        await asyncio.to_thread(self._update, action, True)
        return f"ipset:{self.config['ip_set_id']}"

    async def revert(self, action: WafAction) -> None:
        if action.provider_ref and action.provider_ref.startswith("ipset:"):
            import asyncio

            await asyncio.to_thread(self._update, action, False)


class DefenseService:
    def __init__(self, secrets: Any) -> None:
        self.secrets = secrets

    async def provider(self, s: AsyncSession, name: str) -> DefenseProvider:
        if name == "none":
            return ManualProvider()
        integ = await s.scalar(select(Integration).where(Integration.kind == f"defense.{name}",
                                                         Integration.status == "active"))
        if integ is None or not integ.secret_ref and name == "cloudflare":
            return ManualProvider()
        if name == "cloudflare":
            return CloudflareProvider(await self.secrets.get(integ.secret_ref),
                                      integ.config["zone_id"])
        if name == "aws_waf":
            return AwsWafProvider(integ.config)
        return ManualProvider()

    async def default_provider_name(self, s: AsyncSession) -> str:
        kinds = set((await s.scalars(select(Integration.kind).where(
            Integration.kind.like("defense.%"), Integration.status == "active"))).all())
        return "cloudflare" if "defense.cloudflare" in kinds else "aws_waf" \
            if "defense.aws_waf" in kinds else "none"

    async def recommend(self, s: AsyncSession, tenant_id: uuid.UUID, *,
                        incident_id: uuid.UUID | None, action_type: DefenseActionType,
                        target: str, ttl_seconds: int | None, rationale: str, confidence: float,
                        created_by: str, params: dict[str, Any] | None = None) -> WafAction:
        low = action_type in LOW_RISK_DEFENSE_ACTIONS
        target = validate_target(action_type, target)
        ttl = ttl_seconds or (900 if low else None)
        if ttl is not None and not 60 <= ttl <= MAX_TTL[low]:
            raise ValidationFailed("ttl outside the allowed range for this action")
        existing = await s.scalar(select(WafAction).where(
            WafAction.action_type == action_type.value, WafAction.target == target,
            WafAction.status.in_([DefenseActionStatus.RECOMMENDED.value,
                                  DefenseActionStatus.PENDING_APPROVAL.value,
                                  DefenseActionStatus.ACTIVE.value])))
        if existing is not None:
            return existing
        tenant = await s.get(Tenant, tenant_id)
        mode = (tenant.settings or {}).get("fatma_mode", FatmaMode.RECOMMEND_ONLY.value) \
            if tenant else FatmaMode.RECOMMEND_ONLY.value
        action = WafAction(
            id=uuid.uuid4(), tenant_id=tenant_id, incident_id=incident_id,
            provider=await self.default_provider_name(s), action_type=action_type.value,
            target=target, params={**(params or {}), "confidence": round(confidence, 3)},
            payload_hash="0" * 64, risk_level="MEDIUM" if low else "HIGH",
            rationale=rationale[:2000], mode=mode if low else FatmaMode.RECOMMEND_ONLY.value,
            status=DefenseActionStatus.RECOMMENDED.value, ttl_seconds=ttl,
            created_by=created_by)
        action.payload_hash = sha256_hex(canonical_json(action_payload(tenant_id, action)))
        s.add(action)
        await s.flush()
        return action

    async def get(self, s: AsyncSession, action_id: uuid.UUID) -> WafAction:
        action = await s.get(WafAction, action_id)
        if action is None:
            raise NotFound()
        return action

    async def execute(self, s: AsyncSession, action: WafAction, executed_by: str) -> WafAction:
        """Called only after the approval service consumed a matching approval."""
        if action.status not in (DefenseActionStatus.PENDING_APPROVAL.value,
                                 DefenseActionStatus.APPROVED.value):
            raise Conflict("action is not awaiting execution")
        provider = await self.provider(s, action.provider)
        action.status = DefenseActionStatus.EXECUTING.value
        await s.flush()
        try:
            action.provider_ref = await provider.apply(action)
        except UpstreamUnavailable as exc:
            action.status = DefenseActionStatus.FAILED.value
            action.error = exc.message
            return action
        now = datetime.now(UTC)
        action.executed_at = now
        action.executed_by = executed_by
        action.expires_at = now + timedelta(seconds=action.ttl_seconds) if action.ttl_seconds \
            else None
        action.status = DefenseActionStatus.ACTIVE.value
        return action

    async def revert(self, s: AsyncSession, action: WafAction, *, expired: bool) -> WafAction:
        if action.status != DefenseActionStatus.ACTIVE.value:
            raise Conflict("action is not active")
        provider = await self.provider(s, action.provider)
        await provider.revert(action)
        action.status = (DefenseActionStatus.EXPIRED if expired
                         else DefenseActionStatus.REVERTED).value
        return action


def describe(action: WafAction) -> str:
    return json.dumps({"type": action.action_type, "target": action.target,
                       "ttl": action.ttl_seconds})
