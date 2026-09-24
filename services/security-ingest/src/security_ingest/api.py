from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Header, Path, Query, Request
from pydantic import BaseModel
from sqlalchemy import func, select

from platform_core.app import RuntimeDep, ServiceRuntime, internal_caller
from platform_core.db.models import MalwareResult
from platform_core.errors import NotFound, PayloadTooLarge, ValidationFailed
from platform_core.schemas.common import Page
from platform_core.security.rbac import P
from platform_core.security.service_acl import GATEWAY_ADMIN, GATEWAY_PUBLIC
from platform_core.security.service_auth import RequestContext
from security_ingest.service import IngestService

router = APIRouter(prefix="/internal")
EdgeCtx = Annotated[RequestContext, Depends(internal_caller(GATEWAY_PUBLIC))]
AdminCtx = Annotated[RequestContext, Depends(internal_caller(GATEWAY_ADMIN))]
FORWARDED = ("x-signature", "x-ingest-token", "x-amz-firehose-access-key", "content-encoding")


def _svc(rt: ServiceRuntime) -> IngestService:
    return rt.extras["ingest"]


@router.post("/ingest/{kind}/{key}")
async def ingest(request: Request, ctx: EdgeCtx, rt: RuntimeDep,
                 kind: Annotated[str, Path(pattern="^[a-z_]{2,20}$")],
                 key: Annotated[str, Path(pattern="^ing_[a-z0-9_]{3,64}$")]) -> dict:
    body = await request.body()
    headers = {h: request.headers[h] for h in FORWARDED if h in request.headers}
    return await _svc(rt).ingest_webhook(kind, key, headers, body, ctx.request_id)


class MalwareOut(BaseModel):
    id: uuid.UUID
    asset_id: uuid.UUID | None
    filename_sanitized: str
    sha256: str
    sha1: str
    md5: str
    size_bytes: int
    mime_declared: str | None
    mime_detected: str | None
    clamav_result: str | None
    clamav_signature: str | None
    yara_matches: list
    archive_info: dict
    verdict: str
    quarantine_status: str
    submitted_by: str
    analyzed_at: datetime | None
    created_at: datetime


@router.post("/malware/submit", response_model=MalwareOut, status_code=202)
async def submit(request: Request, ctx: AdminCtx, rt: RuntimeDep,
                 x_filename: Annotated[str, Header(max_length=255)],
                 x_declared_mime: Annotated[str | None, Header(max_length=100)] = None,
                 asset_id: uuid.UUID | None = None) -> MalwareOut:
    rt.policy.require(ctx, P.MALWARE_SUBMIT)
    limit = rt.settings.max_upload_bytes  # type: ignore[attr-defined]
    data = await request.body()
    if len(data) > limit:
        raise PayloadTooLarge()
    if not data:
        raise ValidationFailed("empty file")
    sample = await _svc(rt).submit_sample(ctx.tenant_id, data=data, filename=x_filename,
                                          declared_mime=x_declared_mime, asset_id=asset_id,
                                          submitted_by=ctx.principal.subject,
                                          request_id=ctx.request_id)
    await rt.audit.record(ctx, action="malware.submit", result="success",
                          target_type="malware_sample", target_id=sample.id,
                          metadata={"sha256": sample.sha256, "size": sample.size_bytes,
                                    "mime_detected": sample.mime_detected})
    async with rt.require_db().tenant_session(ctx.tenant_id) as s:
        return MalwareOut.model_validate(await s.get(MalwareResult, sample.id),
                                         from_attributes=True)


@router.get("/malware", response_model=Page[MalwareOut])
async def list_malware(ctx: Annotated[RequestContext, Depends(internal_caller(GATEWAY_ADMIN))],
                       rt: RuntimeDep, verdict: Annotated[str | None, Query(max_length=20)] = None,
                       limit: Annotated[int, Query(ge=1, le=200)] = 50,
                       offset: Annotated[int, Query(ge=0)] = 0) -> Page[MalwareOut]:
    rt.policy.require(ctx, P.MALWARE_READ)
    async with rt.require_db().tenant_session(ctx.tenant_id) as s:
        stmt = select(MalwareResult)
        if verdict:
            stmt = stmt.where(MalwareResult.verdict == verdict)
        total = await s.scalar(select(func.count()).select_from(stmt.subquery()))
        rows = (await s.scalars(stmt.order_by(MalwareResult.created_at.desc())
                                .limit(limit).offset(offset))).all()
        return Page(items=[MalwareOut.model_validate(r, from_attributes=True) for r in rows],
                    total=int(total or 0), limit=limit, offset=offset)


@router.get("/malware/{sample_id}", response_model=MalwareOut)
async def get_malware(sample_id: uuid.UUID, ctx: AdminCtx, rt: RuntimeDep) -> MalwareOut:
    rt.policy.require(ctx, P.MALWARE_READ)
    async with rt.require_db().tenant_session(ctx.tenant_id) as s:
        row = await s.get(MalwareResult, sample_id)
        if row is None:
            raise NotFound()
        return MalwareOut.model_validate(row, from_attributes=True)


@router.post("/malware/{sample_id}/destroy", response_model=MalwareOut)
async def destroy(sample_id: uuid.UUID, ctx: AdminCtx, rt: RuntimeDep) -> MalwareOut:
    rt.policy.require(ctx, P.DEFENSE_EXECUTE)
    async with rt.require_db().tenant_session(ctx.tenant_id, actor=ctx.principal.subject) as s:
        row = await s.get(MalwareResult, sample_id)
        if row is None:
            raise NotFound()
        row.quarantine_status = "DESTROYED"
        ref = row.storage_ref
    svc = _svc(rt)
    try:
        await svc.quarantine.store.put(ref.removeprefix("fs://"), b"")  # overwrite ciphertext
    except Exception:  # noqa: S110 - best effort; the key-encrypted blob is inert anyway
        pass
    await rt.audit.record(ctx, action="malware.destroy", result="success",
                          target_type="malware_sample", target_id=sample_id, risk_level="MEDIUM")
    async with rt.require_db().tenant_session(ctx.tenant_id) as s:
        return MalwareOut.model_validate(await s.get(MalwareResult, sample_id),
                                         from_attributes=True)
