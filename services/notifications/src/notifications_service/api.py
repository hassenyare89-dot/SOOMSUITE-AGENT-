from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select, update

from notifications_service.service import CancelIn, NotificationIn, NotificationService
from platform_core.app import RuntimeDep, ServiceRuntime, internal_caller
from platform_core.db.models import Notification
from platform_core.schemas.common import Page
from platform_core.security.rbac import P
from platform_core.security.service_acl import (
    FATMA_SOC,
    GATEWAY_ADMIN,
    SAMIIR_AGENT,
    SCHEDULING,
    WHATSAPP,
)
from platform_core.security.service_auth import RequestContext

router = APIRouter(prefix="/internal")
SenderCtx = Annotated[RequestContext, Depends(internal_caller(SAMIIR_AGENT, SCHEDULING, FATMA_SOC,
                                                              GATEWAY_ADMIN))]
AdminCtx = Annotated[RequestContext, Depends(internal_caller(GATEWAY_ADMIN))]


def _svc(rt: ServiceRuntime) -> NotificationService:
    return rt.extras["notifications"]


class NotificationOut(BaseModel):
    id: uuid.UUID
    channel: str
    template: str
    contact_id: uuid.UUID | None
    status: str
    scheduled_for: object
    sent_at: object | None
    attempts: int
    last_error: str | None
    related_type: str | None
    related_id: uuid.UUID | None
    created_at: object


class StatusIn(BaseModel):
    provider_message_id: str = Field(max_length=200)
    status: str = Field(pattern="^(sent|delivered|read|failed)$")


@router.post("/notifications", status_code=202)
async def enqueue(body: NotificationIn, ctx: SenderCtx, rt: RuntimeDep) -> dict:
    rt.policy.require_any(ctx, {P.INTERNAL_EXECUTE, P.TENANT_SETTINGS_MANAGE})
    nid = await _svc(rt).enqueue(ctx.tenant_id, body, ctx.caller)
    return {"id": nid, "status": "accepted"}


@router.post("/notifications/cancel")
async def cancel(body: CancelIn, ctx: SenderCtx, rt: RuntimeDep) -> dict:
    rt.policy.require(ctx, P.INTERNAL_EXECUTE)
    return {"cancelled": await _svc(rt).cancel_related(ctx.tenant_id, body)}


@router.post("/notifications/status")
async def delivery_status(body: StatusIn, rt: RuntimeDep,
                          ctx: Annotated[RequestContext, Depends(internal_caller(WHATSAPP))]) -> dict:
    rt.policy.require(ctx, P.INTERNAL_EXECUTE)
    mapped = {"sent": "SENT", "delivered": "DELIVERED", "read": "READ", "failed": "FAILED"}
    async with rt.require_db().tenant_session(ctx.tenant_id) as s:
        result = await s.execute(update(Notification).where(
            Notification.provider_message_id == body.provider_message_id).values(
            status=mapped[body.status]))
    return {"updated": result.rowcount or 0}


@router.get("/notifications", response_model=Page[NotificationOut])
async def list_notifications(ctx: AdminCtx, rt: RuntimeDep,
                             channel: Annotated[str | None, Query(max_length=20)] = None,
                             limit: Annotated[int, Query(ge=1, le=200)] = 50,
                             offset: Annotated[int, Query(ge=0)] = 0) -> Page[NotificationOut]:
    rt.policy.require_any(ctx, {P.CHANNEL_READ, P.TENANT_SETTINGS_MANAGE})
    async with rt.require_db().tenant_session(ctx.tenant_id) as s:
        stmt = select(Notification)
        if channel:
            stmt = stmt.where(Notification.channel == channel)
        total = await s.scalar(select(func.count()).select_from(stmt.subquery()))
        rows = (await s.scalars(stmt.order_by(Notification.created_at.desc())
                                .limit(limit).offset(offset))).all()
        return Page(items=[NotificationOut.model_validate(n, from_attributes=True) for n in rows],
                    total=int(total or 0), limit=limit, offset=offset)


@router.get("/templates")
async def templates(ctx: AdminCtx, rt: RuntimeDep) -> list[dict]:
    rt.policy.require_any(ctx, {P.CHANNEL_READ, P.TENANT_SETTINGS_MANAGE})
    from notifications_service.templates import TEMPLATES

    return [{"name": t.name, "category": t.category, "email_subject": t.email_subject,
             "email_body": t.email_body, "whatsapp_text": t.whatsapp_text,
             "whatsapp_template": t.whatsapp_template} for t in TEMPLATES.values()]
