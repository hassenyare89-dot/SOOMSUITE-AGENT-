from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from platform_core.app import RuntimeDep, ServiceRuntime, internal_caller
from platform_core.db.models import Asset, AssetVerification, ScanJob
from platform_core.errors import Conflict, NotFound, ValidationFailed
from platform_core.schemas.common import Page, StrictModel
from platform_core.schemas.enums import AssetVerificationStatus, ScanProfile, ScanStatus
from platform_core.security.principal import Principal
from platform_core.security.rbac import P
from platform_core.security.service_acl import FATMA_SOC, GATEWAY_ADMIN
from platform_core.security.service_auth import RequestContext
from platform_core.security.ssrf import validate_hostname
from scanner_controller import verification
from scanner_controller.service import ScanService, approval_payload, evaluate_gate

router = APIRouter(prefix="/internal")
AdminCtx = Annotated[RequestContext, Depends(internal_caller(GATEWAY_ADMIN))]
ReadCtx = Annotated[RequestContext, Depends(internal_caller(GATEWAY_ADMIN, FATMA_SOC))]


def _svc(rt: ServiceRuntime) -> ScanService:
    return rt.extras["scans"]


class AssetOut(BaseModel):
    id: uuid.UUID
    name: str
    asset_type: str
    canonical_target: str
    environment: str
    criticality: int
    owner: str | None
    tags: list[str]
    allowlisted: bool
    verification_status: str
    verified_until: datetime | None
    customer_authorization_ref: str | None
    customer_authorization_expires_at: datetime | None
    created_at: datetime


class AssetIn(StrictModel):
    name: str = Field(min_length=2, max_length=200)
    asset_type: str = Field("website", pattern="^(website|api|host|dns|cdn_zone|application)$")
    canonical_target: str = Field(max_length=253)
    environment: str = Field("production", pattern="^(production|staging|development)$")
    criticality: int = Field(3, ge=1, le=5)
    owner: str | None = Field(default=None, max_length=200)
    tags: list[str] = Field(default_factory=list, max_length=20)


class AssetPatch(StrictModel):
    name: str | None = Field(default=None, min_length=2, max_length=200)
    criticality: int | None = Field(default=None, ge=1, le=5)
    owner: str | None = Field(default=None, max_length=200)
    customer_authorization_ref: str | None = Field(default=None, pattern=r"^[A-Za-z0-9._#/-]{3,64}$")
    customer_authorization_expires_at: datetime | None = None


@router.get("/assets", response_model=list[AssetOut])
async def list_assets(ctx: ReadCtx, rt: RuntimeDep) -> list[AssetOut]:
    rt.policy.require_any(ctx, {P.ASSET_READ, P.INTERNAL_EXECUTE})
    async with rt.require_db().tenant_session(ctx.tenant_id) as s:
        rows = (await s.scalars(select(Asset).where(Asset.deleted_at.is_(None))
                                .order_by(Asset.name))).all()
        return [AssetOut.model_validate(a, from_attributes=True) for a in rows]


@router.post("/assets", response_model=AssetOut, status_code=201)
async def create_asset(body: AssetIn, ctx: AdminCtx, rt: RuntimeDep) -> AssetOut:
    rt.policy.require(ctx, P.ASSET_MANAGE)
    host = validate_hostname(body.canonical_target)
    async with rt.require_db().tenant_session(ctx.tenant_id, actor=ctx.principal.subject) as s:
        a = Asset(tenant_id=ctx.tenant_id, **{**body.model_dump(), "canonical_target": host})
        s.add(a)
        await s.flush()
        await s.refresh(a)
        out = AssetOut.model_validate(a, from_attributes=True)
    await rt.audit.record(ctx, action="asset.create", result="success", target_type="asset",
                          target_id=out.id, metadata={"target": host})
    return out


@router.patch("/assets/{asset_id}", response_model=AssetOut)
async def update_asset(asset_id: uuid.UUID, body: AssetPatch, ctx: AdminCtx, rt: RuntimeDep
                       ) -> AssetOut:
    rt.policy.require(ctx, P.ASSET_MANAGE)
    async with rt.require_db().tenant_session(ctx.tenant_id, actor=ctx.principal.subject) as s:
        a = await _svc(rt).asset(s, asset_id)
        for k, v in body.model_dump(exclude_unset=True).items():
            setattr(a, k, v)
        await s.flush()
        await s.refresh(a)
        out = AssetOut.model_validate(a, from_attributes=True)
    await rt.audit.record(ctx, action="asset.update", result="success", target_type="asset",
                          target_id=asset_id, metadata=body.model_dump(mode="json",
                                                                       exclude_unset=True))
    return out


class AllowlistIn(StrictModel):
    allowlisted: bool


@router.post("/assets/{asset_id}/allowlist", response_model=AssetOut)
async def allowlist(asset_id: uuid.UUID, body: AllowlistIn, ctx: AdminCtx, rt: RuntimeDep
                    ) -> AssetOut:
    rt.policy.require(ctx, P.ASSET_MANAGE)
    async with rt.require_db().tenant_session(ctx.tenant_id, actor=ctx.principal.subject) as s:
        a = await _svc(rt).asset(s, asset_id)
        now = datetime.now(UTC)
        if body.allowlisted and not (
            a.verification_status == AssetVerificationStatus.VERIFIED.value
            and a.verified_until and a.verified_until > now
            and a.customer_authorization_ref and a.customer_authorization_expires_at
            and a.customer_authorization_expires_at > now
        ):
            raise Conflict("assets must be ownership-verified and have a current customer "
                           "authorization before allowlisting")
        a.allowlisted = body.allowlisted
        await s.flush()
        await s.refresh(a)
        out = AssetOut.model_validate(a, from_attributes=True)
    await rt.audit.record(ctx, action="asset.allowlist", result="success", target_type="asset",
                          target_id=asset_id, risk_level="HIGH",
                          metadata={"allowlisted": body.allowlisted})
    return out


class VerifyIn(StrictModel):
    method: str = Field(pattern="^(dns_txt|http_file)$")


@router.post("/assets/{asset_id}/verifications", status_code=201)
async def start_verification(asset_id: uuid.UUID, body: VerifyIn, ctx: AdminCtx,
                             rt: RuntimeDep) -> dict:
    rt.policy.require(ctx, P.ASSET_MANAGE)
    token, token_hash = verification.new_challenge()
    async with rt.require_db().tenant_session(ctx.tenant_id, actor=ctx.principal.subject) as s:
        a = await _svc(rt).asset(s, asset_id)
        v = AssetVerification(tenant_id=ctx.tenant_id, asset_id=a.id, method=body.method,
                              challenge_token_hash=token_hash, requested_by=ctx.principal.subject,
                              expires_at=datetime.now(UTC) + timedelta(days=7))
        s.add(v)
        if a.verification_status != AssetVerificationStatus.VERIFIED.value:
            a.verification_status = AssetVerificationStatus.PENDING.value
        await s.flush()
        vid, host = v.id, a.canonical_target
    return {"verification_id": vid, "expires_in_days": 7,
            "instructions": verification.instructions(body.method, host, token)}


@router.post("/assets/{asset_id}/verifications/{verification_id}/check")
async def check_verification(asset_id: uuid.UUID, verification_id: uuid.UUID, ctx: AdminCtx,
                             rt: RuntimeDep) -> dict:
    rt.policy.require(ctx, P.ASSET_MANAGE)
    async with rt.require_db().tenant_session(ctx.tenant_id) as s:
        a = await _svc(rt).asset(s, asset_id)
        v = await s.get(AssetVerification, verification_id)
        if v is None or v.asset_id != a.id:
            raise NotFound()
        method, token_hash, host, expires = v.method, v.challenge_token_hash, \
            a.canonical_target, v.expires_at
    if expires <= datetime.now(UTC):
        raise Conflict("verification challenge expired; start a new one")
    checker = rt.extras.get("verifier") or (verification.check_dns if method == "dns_txt"
                                            else verification.check_http)
    ok = await checker(host, token_hash)
    async with rt.require_db().tenant_session(ctx.tenant_id, actor=ctx.principal.subject) as s:
        v = await s.get(AssetVerification, verification_id)
        a = await _svc(rt).asset(s, asset_id)
        v.checked_at = datetime.now(UTC)
        if ok:
            days = rt.settings.verification_validity_days  # type: ignore[attr-defined]
            v.status, v.verified_at = "VERIFIED", datetime.now(UTC)
            a.verification_status = AssetVerificationStatus.VERIFIED.value
            a.verified_until = datetime.now(UTC) + timedelta(days=days)
        else:
            v.status, v.failure_reason = "FAILED", "challenge not found"
    await rt.audit.record(ctx, action="asset.verify", result="success" if ok else "failure",
                          target_type="asset", target_id=asset_id, metadata={"method": method})
    return {"verified": ok}


# ---------------------------------------------------------------------------- scans
class ScanOut(BaseModel):
    id: uuid.UUID
    asset_id: uuid.UUID
    target_url: str
    requested_by: str
    approval_id: uuid.UUID | None
    authorization_ticket: str
    customer_authorization_ref: str
    profile: str
    scanners: list[str]
    status: str
    workflow_id: str | None
    scheduled_for: datetime | None
    started_at: datetime | None
    finished_at: datetime | None
    timeout_seconds: int
    attempt: int
    retry_of_id: uuid.UUID | None
    findings_count: int
    error: str | None
    scanner_log: list
    created_at: datetime


class ScanIn(StrictModel):
    asset_id: uuid.UUID
    profile: ScanProfile
    authorization_ticket: str = Field(pattern=r"^[A-Za-z0-9._#/-]{3,64}$")
    scanners: list[str] = Field(default_factory=lambda: ["nuclei", "zap"], max_length=2)
    idempotency_key: str = Field(min_length=16, max_length=128)
    scheduled_for: datetime | None = None
    timeout_seconds: int = Field(3600, ge=300, le=21600)
    reason: str = Field("Authorized vulnerability assessment", min_length=5, max_length=500)


async def _request_approval(rt: ServiceRuntime, ctx: RequestContext, job: ScanJob,
                            reason: str) -> uuid.UUID:
    payload = approval_payload(ctx.tenant_id, job)
    system = Principal.system(ctx.tenant_id, "scanner-controller")
    approval = await rt.client("approvals").post("/internal/approvals", principal=system,
                                                 request_id=ctx.request_id, json={
        "action_type": "scan.execute", "payload": payload, "reason": reason,
        "target_type": "scan_job", "target_id": str(job.id),
        "on_behalf_of": ctx.principal.subject})
    return uuid.UUID(approval["id"])


@router.post("/scans", response_model=ScanOut, status_code=201)
async def request_scan(body: ScanIn, ctx: AdminCtx, rt: RuntimeDep) -> ScanOut:
    rt.policy.require(ctx, P.SCAN_REQUEST)
    async with rt.require_db().tenant_session(ctx.tenant_id, actor=ctx.principal.subject) as s:
        job = await _svc(rt).create_job(
            s, ctx, rt.policy, asset_id=body.asset_id, profile=body.profile.value,
            ticket=body.authorization_ticket, scanners=body.scanners,
            idempotency_key=body.idempotency_key, scheduled_for=body.scheduled_for,
            timeout_seconds=body.timeout_seconds)
        if job.approval_id is None:
            job.approval_id = await _request_approval(rt, ctx, job, body.reason)
        await s.flush()
        await s.refresh(job)
        out = ScanOut.model_validate(job, from_attributes=True)
    await rt.audit.record(ctx, action="scan.request", result="pending", risk_level="HIGH",
                          target_type="scan_job", target_id=out.id, approval_id=out.approval_id,
                          metadata={"profile": out.profile, "target": out.target_url,
                                    "ticket": out.authorization_ticket})
    return out


@router.post("/scans/{job_id}/start", response_model=ScanOut)
async def start_scan(job_id: uuid.UUID, ctx: AdminCtx, rt: RuntimeDep) -> ScanOut:
    rt.policy.require(ctx, P.SCAN_REQUEST)
    async with rt.require_db().tenant_session(ctx.tenant_id, actor=ctx.principal.subject) as s:
        svc = _svc(rt)
        job = await svc.get(s, job_id)
        if job.status != ScanStatus.PENDING_APPROVAL.value or job.approval_id is None:
            raise Conflict("scan is not awaiting start")
        asset = await svc.asset(s, job.asset_id)
        # Re-evaluate every gate at execution time (authorization may have lapsed).
        evaluate_gate(ctx, rt.policy, asset, ticket=job.authorization_ticket,
                      profile=job.profile).raise_if_failed()
        if job.target_url != f"https://{asset.canonical_target}/":
            raise Conflict("asset target changed since approval")
        await svc.ensure_capacity(s)
        system = Principal.system(ctx.tenant_id, "scanner-controller")
        await rt.client("approvals").post(
            f"/internal/approvals/{job.approval_id}/consume", principal=system,
            request_id=ctx.request_id, json={"action_type": "scan.execute",
                                             "payload": approval_payload(ctx.tenant_id, job)})
        job.status = ScanStatus.QUEUED.value
        job.workflow_id = f"scan-{job.id}"
        await s.flush()
        await s.refresh(job)
        out = ScanOut.model_validate(job, from_attributes=True)
    starter = rt.extras.get("start_workflow")
    if starter is not None:
        await starter(out, asset.canonical_target, ctx.tenant_id)
    await rt.audit.record(ctx, action="scan.start", result="success", risk_level="HIGH",
                          target_type="scan_job", target_id=job_id, approval_id=out.approval_id)
    await rt.realtime.publish(ctx.tenant_id, "fatma", "scan.updated",
                              {"scan_id": job_id, "status": out.status})
    return out


@router.post("/scans/{job_id}/cancel", response_model=ScanOut)
async def cancel_scan(job_id: uuid.UUID, ctx: AdminCtx, rt: RuntimeDep) -> ScanOut:
    rt.policy.require(ctx, P.SCAN_REQUEST)
    async with rt.require_db().tenant_session(ctx.tenant_id, actor=ctx.principal.subject) as s:
        job = await _svc(rt).get(s, job_id)
        if job.status not in (ScanStatus.PENDING_APPROVAL.value, ScanStatus.QUEUED.value,
                              ScanStatus.RUNNING.value):
            raise Conflict("scan is not cancellable")
        workflow_id = job.workflow_id
        job.status = ScanStatus.CANCELLED.value
        job.finished_at = datetime.now(UTC)
        await s.flush()
        await s.refresh(job)
        out = ScanOut.model_validate(job, from_attributes=True)
    if workflow_id and (canceller := rt.extras.get("cancel_workflow")):
        await canceller(workflow_id)
    await rt.audit.record(ctx, action="scan.cancel", result="success", target_type="scan_job",
                          target_id=job_id)
    return out


class RetryIn(StrictModel):
    idempotency_key: str = Field(min_length=16, max_length=128)


@router.post("/scans/{job_id}/retry", response_model=ScanOut, status_code=201)
async def retry_scan(job_id: uuid.UUID, body: RetryIn, ctx: AdminCtx, rt: RuntimeDep) -> ScanOut:
    """A retry is a new job with a new approval: approvals are single-use by design."""
    rt.policy.require(ctx, P.SCAN_REQUEST)
    async with rt.require_db().tenant_session(ctx.tenant_id, actor=ctx.principal.subject) as s:
        old = await _svc(rt).get(s, job_id)
        if old.status not in (ScanStatus.FAILED.value, ScanStatus.TIMED_OUT.value,
                              ScanStatus.CANCELLED.value):
            raise Conflict("only failed, timed-out or cancelled scans can be retried")
        job = await _svc(rt).create_job(
            s, ctx, rt.policy, asset_id=old.asset_id, profile=old.profile,
            ticket=old.authorization_ticket, scanners=old.scanners,
            idempotency_key=body.idempotency_key, scheduled_for=None,
            timeout_seconds=old.timeout_seconds)
        job.retry_of_id, job.attempt = old.id, old.attempt + 1
        job.approval_id = await _request_approval(rt, ctx, job, f"Retry of scan {old.id}")
        await s.flush()
        await s.refresh(job)
        return ScanOut.model_validate(job, from_attributes=True)


@router.get("/scans", response_model=Page[ScanOut])
async def list_scans(ctx: ReadCtx, rt: RuntimeDep, status: Annotated[str | None,
                                                                     Query(max_length=20)] = None,
                     limit: Annotated[int, Query(ge=1, le=200)] = 50,
                     offset: Annotated[int, Query(ge=0)] = 0) -> Page[ScanOut]:
    rt.policy.require_any(ctx, {P.SCAN_READ, P.INTERNAL_EXECUTE})
    async with rt.require_db().tenant_session(ctx.tenant_id) as s:
        stmt = select(ScanJob)
        if status:
            stmt = stmt.where(ScanJob.status == status)
        total = await s.scalar(select(func.count()).select_from(stmt.subquery()))
        rows = (await s.scalars(stmt.order_by(ScanJob.created_at.desc()).limit(limit)
                                .offset(offset))).all()
        return Page(items=[ScanOut.model_validate(j, from_attributes=True) for j in rows],
                    total=int(total or 0), limit=limit, offset=offset)


@router.get("/scans/{job_id}", response_model=ScanOut)
async def get_scan(job_id: uuid.UUID, ctx: ReadCtx, rt: RuntimeDep) -> ScanOut:
    rt.policy.require_any(ctx, {P.SCAN_READ, P.INTERNAL_EXECUTE})
    async with rt.require_db().tenant_session(ctx.tenant_id) as s:
        return ScanOut.model_validate(await _svc(rt).get(s, job_id), from_attributes=True)


@router.post("/scans/gate-check")
async def gate_check(body: ScanIn, ctx: AdminCtx, rt: RuntimeDep) -> dict:
    """Dry run for the UI: shows which of the seven pre-conditions are satisfied."""
    async with rt.require_db().tenant_session(ctx.tenant_id) as s:
        asset = await _svc(rt).asset(s, body.asset_id)
    result = evaluate_gate(ctx, rt.policy, asset, ticket=body.authorization_ticket,
                           profile=body.profile.value)
    if not body.scanners:
        raise ValidationFailed("select at least one scanner")
    return {"passed": result.passed, "checks": result.checks,
            "note": "Check 6 (human approval) is enforced when the scan is started."}
