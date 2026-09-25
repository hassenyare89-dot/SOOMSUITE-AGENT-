from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import func, select

from audit_service.service import AuditStore
from platform_core.app import CallerDep, RuntimeDep, ServiceRuntime, internal_caller
from platform_core.audit import AuditEvent
from platform_core.db.models import AuditLog
from platform_core.errors import NotFound
from platform_core.schemas.common import Page
from platform_core.security.rbac import P
from platform_core.security.service_acl import GATEWAY_ADMIN
from platform_core.security.service_auth import RequestContext

router = APIRouter(prefix="/internal/audit")
AdminCtx = Annotated[RequestContext, Depends(internal_caller(GATEWAY_ADMIN))]


def _store(rt: ServiceRuntime) -> AuditStore:
    return rt.extras["store"]


class AuditOut(BaseModel):
    id: uuid.UUID
    seq: int
    actor_type: str
    actor_id: str
    agent_name: str | None
    agent_run_id: uuid.UUID | None
    service: str
    tool_name: str | None
    action: str
    target_type: str | None
    target_id: str | None
    request_id: str
    source_ip: str | None
    result: str
    risk_level: str | None
    approval_id: uuid.UUID | None
    metadata_redacted: dict
    entry_hash: str
    created_at: datetime


@router.post("/events", status_code=201)
async def append(event: AuditEvent, ctx: CallerDep, rt: RuntimeDep) -> dict:
    # A service can only write audit events for the tenant its token is bound to.
    if event.tenant_id != ctx.tenant_id:
        raise NotFound()
    row = await _store(rt).append(event, writer=ctx.caller)
    return {"id": row.id, "seq": row.seq, "entry_hash": row.entry_hash}


@router.get("/logs", response_model=Page[AuditOut])
async def logs(ctx: AdminCtx, rt: RuntimeDep,
               action: Annotated[str | None, Query(max_length=128)] = None,
               actor_id: Annotated[str | None, Query(max_length=256)] = None,
               result: Annotated[str | None, Query(pattern="^(success|denied|failure|pending)$")] = None,
               agent_name: Annotated[str | None, Query(pattern="^(SAMIIR|FATMA)$")] = None,
               since: datetime | None = None,
               limit: Annotated[int, Query(ge=1, le=500)] = 100,
               offset: Annotated[int, Query(ge=0)] = 0) -> Page[AuditOut]:
    rt.policy.require(ctx, P.AUDIT_READ)
    async with rt.require_db().tenant_session(ctx.tenant_id) as s:
        stmt = select(AuditLog)
        if action:
            stmt = stmt.where(AuditLog.action.startswith(action))
        if actor_id:
            stmt = stmt.where(AuditLog.actor_id == actor_id)
        if result:
            stmt = stmt.where(AuditLog.result == result)
        if agent_name:
            stmt = stmt.where(AuditLog.agent_name == agent_name)
        if since:
            stmt = stmt.where(AuditLog.created_at >= since)
        total = await s.scalar(select(func.count()).select_from(stmt.subquery()))
        rows = (await s.scalars(stmt.order_by(AuditLog.seq.desc()).limit(limit)
                                .offset(offset))).all()
        return Page(items=[AuditOut.model_validate(r, from_attributes=True) for r in rows],
                    total=int(total or 0), limit=limit, offset=offset)


@router.get("/verify")
async def verify(ctx: AdminCtx, rt: RuntimeDep) -> dict:
    rt.policy.require(ctx, P.AUDIT_READ)
    return await _store(rt).verify(ctx.tenant_id)
