"""Scan authorization gate and orchestration."""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from platform_core.db.models import Asset, Finding, ScanJob
from platform_core.errors import Conflict, Forbidden, NotFound, RateLimited, ValidationFailed
from platform_core.schemas.enums import AssetVerificationStatus, ScanProfile, ScanStatus
from platform_core.security.principal import ActorType
from platform_core.security.rbac import P
from platform_core.security.service_auth import RequestContext

TICKET = re.compile(r"^[A-Za-z0-9._#/-]{3,64}$")
SCANNERS = {"nuclei", "zap"}


@dataclass(frozen=True)
class GateResult:
    passed: bool
    checks: dict[str, bool]

    def raise_if_failed(self) -> None:
        if not self.passed:
            failed = [k for k, v in self.checks.items() if not v]
            raise Forbidden("scan authorization requirements not met",
                            details={"failed_checks": failed})


def evaluate_gate(ctx: RequestContext, policy: Any, asset: Asset, *, ticket: str,
                  profile: str, now: datetime | None = None) -> GateResult:
    """All seven pre-conditions, evaluated deterministically (the approval is check 6 and is
    enforced separately by consuming it before the workflow can start)."""
    now = now or datetime.now(UTC)
    checks = {
        "1_authenticated_security_engineer": ctx.principal.actor_type is ActorType.USER
        and policy.check(ctx, P.SCAN_REQUEST).allowed,
        "2_customer_authorization": bool(asset.customer_authorization_ref)
        and asset.customer_authorization_expires_at is not None
        and asset.customer_authorization_expires_at > now,
        "3_domain_ownership_verified": asset.verification_status
        == AssetVerificationStatus.VERIFIED.value and asset.verified_until is not None
        and asset.verified_until > now,
        "4_target_allowlisted": asset.allowlisted and asset.deleted_at is None,
        "5_authorization_ticket": bool(TICKET.fullmatch(ticket or "")),
        "7_scan_profile_selected": profile in {p.value for p in ScanProfile},
    }
    return GateResult(all(checks.values()), checks)


def approval_payload(tenant_id: uuid.UUID, job: ScanJob) -> dict[str, Any]:
    return {"tenant_id": str(tenant_id), "action_type": "scan.execute",
            "scan_job_id": str(job.id), "asset_id": str(job.asset_id),
            "target_url": job.target_url, "profile": job.profile,
            "scanners": sorted(job.scanners), "authorization_ticket": job.authorization_ticket,
            "customer_authorization_ref": job.customer_authorization_ref,
            "requested_by": job.requested_by, "timeout_seconds": job.timeout_seconds}


class ScanService:
    def __init__(self, *, max_per_day: int, max_concurrent: int) -> None:
        self.max_per_day = max_per_day
        self.max_concurrent = max_concurrent

    async def asset(self, s: AsyncSession, asset_id: uuid.UUID) -> Asset:
        asset = await s.get(Asset, asset_id)
        if asset is None or asset.deleted_at is not None:
            raise NotFound()
        return asset

    async def create_job(self, s: AsyncSession, ctx: RequestContext, policy: Any, *,
                         asset_id: uuid.UUID, profile: str, ticket: str,
                         scanners: list[str], idempotency_key: str,
                         scheduled_for: datetime | None, timeout_seconds: int) -> ScanJob:
        existing = await s.scalar(select(ScanJob).where(ScanJob.idempotency_key == idempotency_key))
        if existing is not None:
            if existing.asset_id != asset_id or existing.profile != profile:
                raise Conflict("idempotency key reused with different parameters")
            return existing
        asset = await self.asset(s, asset_id)
        evaluate_gate(ctx, policy, asset, ticket=ticket, profile=profile).raise_if_failed()
        if not scanners or not set(scanners) <= SCANNERS:
            raise ValidationFailed("unsupported scanner")
        todays = await s.scalar(select(func.count()).select_from(ScanJob).where(
            ScanJob.created_at > datetime.now(UTC) - timedelta(days=1)))
        if (todays or 0) >= self.max_per_day:
            raise RateLimited(retry_after=3600)
        if scheduled_for and scheduled_for > datetime.now(UTC) + timedelta(days=30):
            raise ValidationFailed("scans can be scheduled at most 30 days ahead")
        job = ScanJob(
            id=uuid.uuid4(), tenant_id=ctx.tenant_id, asset_id=asset.id,
            target_url=f"https://{asset.canonical_target}/", requested_by=ctx.principal.subject,
            authorization_ticket=ticket,
            customer_authorization_ref=asset.customer_authorization_ref or "",
            profile=profile, scanners=sorted(set(scanners)),
            status=ScanStatus.PENDING_APPROVAL.value, idempotency_key=idempotency_key,
            scheduled_for=scheduled_for, timeout_seconds=timeout_seconds)
        s.add(job)
        await s.flush()
        return job

    async def get(self, s: AsyncSession, job_id: uuid.UUID) -> ScanJob:
        job = await s.get(ScanJob, job_id)
        if job is None:
            raise NotFound()
        return job

    async def ensure_capacity(self, s: AsyncSession) -> None:
        running = await s.scalar(select(func.count()).select_from(ScanJob).where(
            ScanJob.status.in_([ScanStatus.QUEUED.value, ScanStatus.RUNNING.value])))
        if (running or 0) >= self.max_concurrent:
            raise RateLimited(retry_after=300)

    async def persist_findings(self, s: AsyncSession, tenant_id: uuid.UUID, job_id: uuid.UUID,
                               runs: list[dict[str, Any]]) -> int:
        job = await self.get(s, job_id)
        count = 0
        now = datetime.now(UTC)
        for run in runs:
            for f in run.get("findings", [])[:5000]:
                stmt = insert(Finding).values(
                    id=uuid.uuid4(), tenant_id=tenant_id, scan_job_id=job.id, asset_id=job.asset_id,
                    scanner=f["scanner"], rule_id=f["rule_id"], title=f["title"],
                    description=f.get("description", ""), category=f.get("category",
                                                                         "vulnerability"),
                    severity=f["severity"], cwe=f.get("cwe"), url=f.get("url"),
                    evidence_redacted=f.get("evidence", {}), remediation=f.get("remediation"),
                    fingerprint=f["fingerprint"], first_seen=now, last_seen=now,
                ).on_conflict_do_update(index_elements=["tenant_id", "fingerprint"],
                                        set_={"last_seen": now, "scan_job_id": job.id})
                await s.execute(stmt)
                count += 1
        job.findings_count = count
        job.scanner_log = [line for run in runs for line in run.get("log", [])][-200:]
        errors = [r.get("error") for r in runs if r.get("error")]
        job.status = ScanStatus.SUCCEEDED.value if not errors else ScanStatus.FAILED.value
        job.error = "; ".join(e for e in errors if e)[:1000] or None
        job.finished_at = now
        return count

    async def set_status(self, s: AsyncSession, job_id: uuid.UUID, status: str,
                         error: str | None) -> ScanJob:
        job = await self.get(s, job_id)
        terminal = {ScanStatus.SUCCEEDED.value, ScanStatus.FAILED.value,
                    ScanStatus.CANCELLED.value, ScanStatus.TIMED_OUT.value}
        if job.status in terminal and status != job.status:
            return job
        job.status = status
        if status == ScanStatus.RUNNING.value:
            job.started_at = datetime.now(UTC)
        if status in terminal:
            job.finished_at = datetime.now(UTC)
            job.error = error
        return job
