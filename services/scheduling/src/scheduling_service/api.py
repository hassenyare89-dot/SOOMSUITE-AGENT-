from __future__ import annotations

import logging
import uuid
from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import Field
from sqlalchemy import func, select

from platform_core.app import RuntimeDep, ServiceRuntime, internal_caller
from platform_core.db.models import Appointment, AppointmentType
from platform_core.errors import Forbidden, PlatformError
from platform_core.observability import instruments
from platform_core.schemas.common import Page, StrictModel
from platform_core.schemas.enums import PipelineStage
from platform_core.schemas.scheduling import (
    AppointmentOut,
    AvailabilityRequest,
    AvailabilityResponse,
    BookRequest,
    CancelRequest,
    RescheduleRequest,
)
from platform_core.security.principal import Principal
from platform_core.security.rbac import P
from platform_core.security.service_acl import GATEWAY_ADMIN, SAMIIR_AGENT
from platform_core.security.service_auth import RequestContext
from scheduling_service.service import SchedulingService, to_out

log = logging.getLogger(__name__)
router = APIRouter(prefix="/internal")
Ctx = Annotated[RequestContext, Depends(internal_caller(SAMIIR_AGENT, GATEWAY_ADMIN))]
AdminCtx = Annotated[RequestContext, Depends(internal_caller(GATEWAY_ADMIN))]


def _svc(rt: ServiceRuntime) -> SchedulingService:
    return rt.extras["scheduling"]


def _can_manage(rt: ServiceRuntime, ctx: RequestContext) -> bool:
    return rt.policy.check(ctx, P.APPOINTMENT_MANAGE).allowed


def _require_request_or_manage(rt: ServiceRuntime, ctx: RequestContext) -> None:
    if not (_can_manage(rt, ctx) or rt.policy.check(ctx, P.APPOINTMENT_REQUEST).allowed):
        raise Forbidden()


async def _after_change(rt: ServiceRuntime, ctx: RequestContext, appt: AppointmentOut,
                        event: str, type_name: str) -> None:
    """CRM + notification side effects. Each call is idempotent (keys derive from the
    appointment id) so replays after partial failure are safe."""
    system = Principal.system(ctx.tenant_id, "scheduling")
    when = {"starts_at": appt.starts_at.isoformat(), "timezone": appt.timezone,
            "appointment_type": type_name}
    try:
        if event == "booked" and appt.contact_id:
            await rt.client("crm").post("/internal/stage-events", principal=system,
                                        request_id=ctx.request_id, json={
                "contact_id": str(appt.contact_id),
                "opportunity_id": str(appt.opportunity_id) if appt.opportunity_id else None,
                "stage": PipelineStage.APPOINTMENT_BOOKED.value,
                "activity_summary": f"Appointment booked: {type_name}",
                "details": {"appointment_id": str(appt.id), **when}})
        elif appt.contact_id:
            await rt.client("crm").post("/internal/activities", principal=system,
                                        request_id=ctx.request_id, json={
                "contact_id": str(appt.contact_id), "activity_type": f"appointment.{event}",
                "summary": f"Appointment {event}: {type_name}",
                "details": {"appointment_id": str(appt.id), **when}})
    except PlatformError:
        log.warning("crm side effect failed", extra={"ctx": {"appointment": str(appt.id)}})
    notif = rt.client("notifications")
    try:
        if event in ("cancelled", "rescheduled"):
            await notif.post("/internal/notifications/cancel", principal=system,
                             request_id=ctx.request_id,
                             json={"related_type": "appointment", "related_id": str(appt.id)})
        if not appt.contact_id:
            return
        template = {"booked": "customer.appointment_confirmation",
                    "rescheduled": "customer.appointment_rescheduled",
                    "cancelled": "customer.appointment_cancelled"}[event]
        target = appt.id
        for channel in ("email", "whatsapp"):
            await notif.post("/internal/notifications", principal=system,
                             request_id=ctx.request_id, json={
                "template": template, "channel": channel, "contact_id": str(appt.contact_id),
                "variables": when, "idempotency_key": f"appt:{target}:{event}:{channel}",
                "related_type": "appointment", "related_id": str(target)})
        if event in ("booked", "rescheduled"):
            for label, delta in (("24h", timedelta(hours=24)), ("1h", timedelta(hours=1))):
                await notif.post("/internal/notifications", principal=system,
                                 request_id=ctx.request_id, json={
                    "template": "customer.appointment_reminder", "channel": "email",
                    "contact_id": str(appt.contact_id), "variables": when,
                    "scheduled_for": (appt.starts_at - delta).isoformat(),
                    "idempotency_key": f"appt:{target}:reminder:{label}",
                    "related_type": "appointment", "related_id": str(target)})
    except PlatformError:
        log.warning("notification side effect failed",
                    extra={"ctx": {"appointment": str(appt.id)}})


@router.get("/appointment-types")
async def appointment_types(ctx: Ctx, rt: RuntimeDep) -> list[dict]:
    _require_request_or_manage(rt, ctx)
    async with rt.require_db().tenant_session(ctx.tenant_id) as s:
        return await _svc(rt).list_types(s)


@router.post("/availability", response_model=AvailabilityResponse)
async def availability(body: AvailabilityRequest, ctx: Ctx, rt: RuntimeDep) -> AvailabilityResponse:
    _require_request_or_manage(rt, ctx)
    async with rt.require_db().tenant_session(ctx.tenant_id) as s:
        return await _svc(rt).availability(s, ctx.tenant_id, body)


@router.post("/appointments", response_model=AppointmentOut, status_code=201)
async def book(body: BookRequest, ctx: Ctx, rt: RuntimeDep) -> AppointmentOut:
    _require_request_or_manage(rt, ctx)
    p = ctx.principal
    if p.is_customer and p.contact_id and p.contact_id != body.contact_id:
        raise Forbidden()
    async with rt.require_db().tenant_session(ctx.tenant_id, actor=ctx.caller) as s:
        appt, created = await _svc(rt).book(
            s, ctx.tenant_id, slot_token=body.slot_token, contact_id=body.contact_id,
            opportunity_id=body.opportunity_id, conversation_id=body.conversation_id,
            idempotency_key=body.idempotency_key, actor_type=p.actor_type.value,
            actor_id=p.subject, attendee_email=None, notes=body.notes)
        atype = await s.get(AppointmentType, appt.appointment_type_id)
        out = to_out(appt, atype.code if atype else None)
        type_name = atype.name if atype else "Appointment"
    if created:
        instruments().appointments.add(1, {"event": "booked", "provider": out.provider})
        await rt.audit.record(ctx, action="appointment.book", result="success",
                              agent_name="SAMIIR" if ctx.caller == SAMIIR_AGENT else None,
                              target_type="appointment", target_id=out.id, risk_level="MEDIUM",
                              metadata={"starts_at": out.starts_at.isoformat(),
                                        "provider": out.provider})
        await _after_change(rt, ctx, out, "booked", type_name)
        await rt.realtime.publish(ctx.tenant_id, "samiir", "appointment.booked",
                                  {"appointment_id": out.id, "starts_at": out.starts_at})
    return out


async def _owned(rt: ServiceRuntime, ctx: RequestContext, s, appointment_id: uuid.UUID,  # noqa: ANN001
                 conversation_id: uuid.UUID | None) -> Appointment:
    return await _svc(rt).get_owned(s, appointment_id, contact_id=ctx.principal.contact_id,
                                    conversation_id=conversation_id,
                                    is_staff=_can_manage(rt, ctx))


@router.post("/appointments/{appointment_id}/cancel", response_model=AppointmentOut)
async def cancel(appointment_id: uuid.UUID, body: CancelRequest, ctx: Ctx,
                 rt: RuntimeDep) -> AppointmentOut:
    _require_request_or_manage(rt, ctx)
    async with rt.require_db().tenant_session(ctx.tenant_id, actor=ctx.caller) as s:
        appt = await _owned(rt, ctx, s, appointment_id, body.conversation_id)
        appt = await _svc(rt).cancel(s, appt, body.reason)
        atype = await s.get(AppointmentType, appt.appointment_type_id)
        out = to_out(appt, atype.code if atype else None)
        type_name = atype.name if atype else "Appointment"
    await rt.audit.record(ctx, action="appointment.cancel", result="success",
                          target_type="appointment", target_id=out.id,
                          metadata={"reason": body.reason})
    await _after_change(rt, ctx, out, "cancelled", type_name)
    return out


@router.post("/appointments/{appointment_id}/reschedule", response_model=AppointmentOut)
async def reschedule(appointment_id: uuid.UUID, body: RescheduleRequest, ctx: Ctx,
                     rt: RuntimeDep) -> AppointmentOut:
    _require_request_or_manage(rt, ctx)
    async with rt.require_db().tenant_session(ctx.tenant_id, actor=ctx.caller) as s:
        appt = await _owned(rt, ctx, s, appointment_id, body.conversation_id)
        old_id = appt.id
        new = await _svc(rt).reschedule(s, ctx.tenant_id, appt, slot_token=body.slot_token,
                                        idempotency_key=body.idempotency_key,
                                        conversation_id=body.conversation_id,
                                        actor_type=ctx.principal.actor_type.value,
                                        actor_id=ctx.principal.subject)
        atype = await s.get(AppointmentType, new.appointment_type_id)
        out = to_out(new, atype.code if atype else None)
        type_name = atype.name if atype else "Appointment"
    await rt.audit.record(ctx, action="appointment.reschedule", result="success",
                          target_type="appointment", target_id=out.id,
                          metadata={"previous": str(old_id)})
    system = Principal.system(ctx.tenant_id, "scheduling")
    try:
        await rt.client("notifications").post("/internal/notifications/cancel", principal=system,
                                              request_id=ctx.request_id, json={
            "related_type": "appointment", "related_id": str(old_id)})
    except PlatformError:
        log.warning("failed to cancel reminders of rescheduled appointment")
    await _after_change(rt, ctx, out, "rescheduled", type_name)
    return out


@router.get("/appointments", response_model=Page[AppointmentOut])
async def list_appointments(ctx: AdminCtx, rt: RuntimeDep,
                            status: Annotated[str | None, Query(max_length=20)] = None,
                            upcoming: bool = False,
                            limit: Annotated[int, Query(ge=1, le=200)] = 50,
                            offset: Annotated[int, Query(ge=0)] = 0) -> Page[AppointmentOut]:
    rt.policy.require(ctx, P.APPOINTMENT_READ)
    async with rt.require_db().tenant_session(ctx.tenant_id) as s:
        stmt = select(Appointment, AppointmentType.code).join(
            AppointmentType, AppointmentType.id == Appointment.appointment_type_id)
        if status:
            stmt = stmt.where(Appointment.status == status)
        if upcoming:
            stmt = stmt.where(Appointment.starts_at >= func.now())
        total = await s.scalar(select(func.count()).select_from(stmt.subquery()))
        rows = (await s.execute(stmt.order_by(Appointment.starts_at.desc() if not upcoming
                                              else Appointment.starts_at)
                                .limit(limit).offset(offset))).all()
        return Page(items=[to_out(a, code) for a, code in rows], total=int(total or 0),
                    limit=limit, offset=offset)


class AppointmentTypeIn(StrictModel):
    code: str = Field(pattern="^[a-z0-9_-]{2,64}$")
    name: str = Field(min_length=2, max_length=120)
    description: str = Field("", max_length=1000)
    duration_minutes: int = Field(ge=5, le=480)
    buffer_minutes: int = Field(0, ge=0, le=240)
    calendar_integration_id: uuid.UUID | None = None
    calendar_id: str = Field("primary", max_length=320)
    rules: dict = Field(default_factory=dict)


@router.post("/appointment-types", status_code=201)
async def create_type(body: AppointmentTypeIn, ctx: AdminCtx, rt: RuntimeDep) -> dict:
    rt.policy.require(ctx, P.TENANT_SETTINGS_MANAGE)
    async with rt.require_db().tenant_session(ctx.tenant_id, actor=ctx.principal.subject) as s:
        t = AppointmentType(tenant_id=ctx.tenant_id, **body.model_dump())
        s.add(t)
        await s.flush()
        tid = t.id
    await rt.audit.record(ctx, action="scheduling.type.create", result="success",
                          target_type="appointment_type", target_id=tid)
    return {"id": tid}
