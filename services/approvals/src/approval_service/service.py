from __future__ import annotations

import base64
import ipaddress
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from approval_service.policies import ApprovalPolicy, policy_for
from platform_core.db.models import ApprovalRequest, Tenant
from platform_core.errors import Conflict, Forbidden, NotFound, ValidationFailed
from platform_core.schemas.enums import ApprovalStatus, FatmaMode
from platform_core.security.crypto import canonical_json, sha256_hex
from platform_core.security.service_auth import ServiceIdentity

PREAPPROVAL_ACTOR = "policy:tenant-preapproved-low-risk"


def payload_hash(payload: dict[str, Any]) -> str:
    return sha256_hex(canonical_json(payload))


def _policy(action_type: str) -> ApprovalPolicy:
    pol = policy_for(action_type)
    if pol is None:
        raise ValidationFailed("unknown action type")
    return pol


class ApprovalService:
    def __init__(self, identity: ServiceIdentity) -> None:
        self.identity = identity

    def _sign(self, req: ApprovalRequest) -> str:
        message = canonical_json({"id": str(req.id), "tenant_id": str(req.tenant_id),
                                  "action_type": req.action_type,
                                  "payload_hash": req.payload_hash,
                                  "expires_at": req.expires_at.isoformat(),
                                  "approved_by": req.approved_by})
        return base64.b64encode(self.identity.sign(message)).decode()

    async def create(self, s: AsyncSession, tenant_id: uuid.UUID, *, action_type: str,
                     payload: dict[str, Any], reason: str, target_type: str | None,
                     target_id: uuid.UUID | None, requested_by: str, requested_by_type: str,
                     requested_via: str) -> ApprovalRequest:
        pol = _policy(action_type)
        if payload.get("tenant_id") != str(tenant_id) or payload.get("action_type") != action_type:
            raise ValidationFailed("payload must embed its tenant_id and action_type")
        now = datetime.now(UTC)
        req = ApprovalRequest(
            id=uuid.uuid4(), tenant_id=tenant_id, action_type=action_type, action_payload=payload,
            payload_hash=payload_hash(payload), target_type=target_type, target_id=target_id,
            requested_by=requested_by, requested_by_type=requested_by_type,
            requested_via=requested_via, requested_at=now, reason=reason[:2000],
            risk_level=pol.risk.value, expires_at=now + pol.ttl,
            status=ApprovalStatus.PENDING.value)
        s.add(req)
        await s.flush()
        return req

    async def preapprove(self, s: AsyncSession, tenant_id: uuid.UUID, *, action_type: str,
                         payload: dict[str, Any], reason: str, target_type: str | None,
                         target_id: uuid.UUID | None, requested_by: str) -> ApprovalRequest:
        """Tenant pre-approval for narrowly defined low-risk, time-boxed, single-target actions."""
        pol = _policy(action_type)
        tenant = await s.get(Tenant, tenant_id)
        mode = (tenant.settings or {}).get("fatma_mode") if tenant else None
        allowed_actions = set((tenant.settings or {}).get("preapproved_actions", [])) if tenant \
            else set()
        if mode != FatmaMode.PREAPPROVED_LOW_RISK.value:
            raise Forbidden("tenant is in recommend-only mode")
        if not pol.preapprovable or action_type not in allowed_actions:
            raise Forbidden("action type is not pre-approved for this tenant")
        ttl = int(payload.get("ttl_seconds") or 0)
        if not (60 <= ttl <= pol.max_preapproved_ttl_seconds):
            raise Forbidden("pre-approved actions must be time-bounded")
        target = str(payload.get("target", ""))
        try:
            net = ipaddress.ip_network(target, strict=False)
            if net.num_addresses != 1:
                raise Forbidden("pre-approved actions must target a single address")
        except ValueError:
            if action_type not in ("defense.rate_limit_path", "defense.revoke_app_session"):
                raise Forbidden("pre-approved actions must target a single address") from None
        if float(payload.get("confidence", 0)) < 0.9:
            raise Forbidden("pre-approval requires verified malicious evidence (confidence ≥ 0.9)")
        req = await self.create(s, tenant_id, action_type=action_type, payload=payload,
                                reason=reason, target_type=target_type, target_id=target_id,
                                requested_by=requested_by, requested_by_type="agent",
                                requested_via="fatma-soc")
        req.status = ApprovalStatus.APPROVED.value
        req.approved_by = PREAPPROVAL_ACTOR
        req.approved_at = datetime.now(UTC)
        req.decision_comment = "auto-approved under tenant low-risk pre-approval policy"
        req.approval_signature = self._sign(req)
        return req

    async def get(self, s: AsyncSession, approval_id: uuid.UUID) -> ApprovalRequest:
        req = await s.get(ApprovalRequest, approval_id)
        if req is None:
            raise NotFound()
        return req

    async def decide(self, s: AsyncSession, approval_id: uuid.UUID, *, approve: bool,
                     approver: str, echoed_hash: str, comment: str | None) -> ApprovalRequest:
        req = await self.get(s, approval_id)
        if req.status != ApprovalStatus.PENDING:
            raise Conflict("approval request is not pending")
        if req.expires_at <= datetime.now(UTC):
            req.status = ApprovalStatus.EXPIRED.value
            raise Conflict("approval request has expired")
        if echoed_hash != req.payload_hash:
            raise Conflict("the reviewed payload does not match the request (it may have changed)")
        if approver == req.requested_by:
            raise Forbidden("requesters cannot approve their own requests")
        req.status = (ApprovalStatus.APPROVED if approve else ApprovalStatus.REJECTED).value
        req.approved_by = approver
        req.approved_at = datetime.now(UTC)
        req.decision_comment = (comment or "")[:1000] or None
        if approve:
            req.approval_signature = self._sign(req)
        return req

    async def consume(self, s: AsyncSession, approval_id: uuid.UUID, *, action_type: str,
                      payload: dict[str, Any], consumer: str) -> ApprovalRequest:
        """Single-use redemption: only the exact approved payload, only once, only in time."""
        req = await self.get(s, approval_id)
        if req.action_type != action_type or payload_hash(payload) != req.payload_hash:
            raise Forbidden("action parameters differ from the approved payload")
        result = await s.execute(
            update(ApprovalRequest)
            .where(ApprovalRequest.id == approval_id,
                   ApprovalRequest.status == ApprovalStatus.APPROVED.value,
                   ApprovalRequest.expires_at > func.now())
            .values(status=ApprovalStatus.EXECUTED.value, consumed_at=func.now(),
                    consumed_by=consumer)
            .returning(ApprovalRequest.id))
        if result.scalar_one_or_none() is None:
            raise Conflict("approval is not valid for execution (pending, used, or expired)")
        await s.refresh(req)
        return req

    async def cancel(self, s: AsyncSession, approval_id: uuid.UUID, actor: str) -> ApprovalRequest:
        req = await self.get(s, approval_id)
        if req.status != ApprovalStatus.PENDING:
            raise Conflict("only pending requests can be cancelled")
        if req.requested_by != actor:
            raise Forbidden()
        req.status = ApprovalStatus.CANCELLED.value
        return req

    async def expire_all(self, db) -> int:  # noqa: ANN001
        async with db.system_session() as s:
            return int(await s.scalar(text("SELECT app_expire_approvals()")) or 0)
