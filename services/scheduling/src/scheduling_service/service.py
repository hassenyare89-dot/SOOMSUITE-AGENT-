"""Booking orchestration.

Anti-hallucination design: SAMIIR can only book a slot it was *offered*. Availability returns
HMAC-signed slot tokens bound to tenant, appointment type, calendar, time range and
conversation; booking accepts nothing but such a token. Double-booking is prevented three
ways: a per-calendar transaction advisory lock, a provider free/busy re-check inside the lock,
and a PostgreSQL exclusion constraint as the final guarantee.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from platform_core.db.models import Appointment, AppointmentType, Integration, Tenant
from platform_core.errors import Conflict, NotFound, UpstreamUnavailable, ValidationFailed
from platform_core.schemas.enums import AppointmentStatus
from platform_core.schemas.scheduling import (
    AppointmentOut,
    AvailabilityRequest,
    AvailabilityResponse,
    SlotOffer,
)
from platform_core.security.crypto import sign_token, verify_token
from platform_core.security.secret_manager import SecretManager
from scheduling_service.providers import (
    CalendarProvider,
    EventSpec,
    GoogleCalendarProvider,
    LocalCalendarProvider,
    Microsoft365CalendarProvider,
)
from scheduling_service.slots import BookingRules, candidate_slots, display, spread, zone

log = logging.getLogger(__name__)
PROVIDER_KINDS = {"calendar.google": "google", "calendar.microsoft365": "microsoft365"}


class SchedulingService:
    def __init__(self, slot_key: bytes, secrets: SecretManager, offer_ttl: int = 1800) -> None:
        self._slot_key = slot_key
        self._secrets = secrets
        self._offer_ttl = offer_ttl
        self._provider_cache: dict[uuid.UUID, CalendarProvider] = {}

    async def provider_for(self, s: AsyncSession, atype: AppointmentType) -> CalendarProvider:
        if atype.calendar_integration_id is None:
            return LocalCalendarProvider()
        if cached := self._provider_cache.get(atype.calendar_integration_id):
            return cached
        integ = await s.get(Integration, atype.calendar_integration_id)
        if integ is None or integ.status != "active" or integ.kind not in PROVIDER_KINDS:
            raise UpstreamUnavailable("calendar integration unavailable")
        if not integ.secret_ref:
            raise UpstreamUnavailable("calendar credentials are not configured")
        creds = await self._secrets.get(integ.secret_ref)
        provider: CalendarProvider = (GoogleCalendarProvider(creds)
                                      if integ.kind == "calendar.google"
                                      else Microsoft365CalendarProvider(creds))
        self._provider_cache[integ.id] = provider
        return provider

    async def _type(self, s: AsyncSession, code: str) -> AppointmentType:
        atype = await s.scalar(select(AppointmentType).where(AppointmentType.code == code,
                                                             AppointmentType.active.is_(True)))
        if atype is None:
            raise NotFound("unknown appointment type")
        return atype

    async def _rules(self, s: AsyncSession, tenant_id: uuid.UUID, atype: AppointmentType
                     ) -> BookingRules:
        tenant = await s.get(Tenant, tenant_id)
        tenant_rules = dict((tenant.settings or {}).get("appointment_rules", {})) if tenant else {}
        tenant_rules.setdefault("business_timezone", tenant.timezone if tenant else "UTC")
        return BookingRules.from_dicts(tenant_rules, atype.rules)

    async def _db_busy(self, s: AsyncSession, calendar_id: str, start: datetime, end: datetime,
                       exclude: uuid.UUID | None = None) -> list[tuple[datetime, datetime]]:
        stmt = select(Appointment.starts_at, Appointment.ends_at).where(
            Appointment.calendar_id == calendar_id, Appointment.status == AppointmentStatus.BOOKED,
            Appointment.starts_at < end, Appointment.ends_at > start)
        if exclude:
            stmt = stmt.where(Appointment.id != exclude)
        return [(r[0], r[1]) for r in (await s.execute(stmt)).all()]

    async def list_types(self, s: AsyncSession) -> list[dict[str, Any]]:
        rows = (await s.scalars(select(AppointmentType).where(AppointmentType.active.is_(True))
                                .order_by(AppointmentType.name))).all()
        return [{"code": t.code, "name": t.name, "description": t.description,
                 "duration_minutes": t.duration_minutes} for t in rows]

    # --------------------------------------------------------------- availability
    async def availability(self, s: AsyncSession, tenant_id: uuid.UUID, req: AvailabilityRequest,
                           *, now: datetime | None = None) -> AvailabilityResponse:
        zone(req.timezone)
        now = now or datetime.now(UTC)
        atype = await self._type(s, req.appointment_type)
        rules = await self._rules(s, tenant_id, atype)
        provider = await self.provider_for(s, atype)
        horizon = now + timedelta(days=min(req.days, rules.max_days_ahead))
        busy = await provider.busy(atype.calendar_id, now, horizon)
        busy += await self._db_busy(s, atype.calendar_id, now, horizon)
        slots = spread(candidate_slots(
            rules, duration=timedelta(minutes=atype.duration_minutes),
            buffer=timedelta(minutes=atype.buffer_minutes), now=now, earliest=req.earliest,
            days=req.days, busy=busy), req.max_slots)
        exp = int(now.timestamp()) + self._offer_ttl
        offers = [SlotOffer(
            slot_token=sign_token(self._slot_key, {
                "t": str(tenant_id), "at": str(atype.id), "c": atype.calendar_id,
                "s": s0.isoformat(), "e": s1.isoformat(), "tz": req.timezone,
                "cv": str(req.conversation_id) if req.conversation_id else None, "exp": exp}),
            starts_at=s0, ends_at=s1, display=display(s0, req.timezone)) for s0, s1 in slots]
        return AvailabilityResponse(appointment_type=atype.code, appointment_name=atype.name,
                                    timezone=req.timezone, slots=offers)

    def _verify_slot(self, token: str, tenant_id: uuid.UUID, conversation_id: uuid.UUID | None
                     ) -> dict[str, Any]:
        claims = verify_token(self._slot_key, token)
        if claims is None or claims.get("t") != str(tenant_id):
            raise ValidationFailed("invalid slot selection")
        if int(claims.get("exp", 0)) < int(datetime.now(UTC).timestamp()):
            raise Conflict("this time slot offer has expired; please request availability again")
        if claims.get("cv") and str(conversation_id) != claims["cv"]:
            raise ValidationFailed("slot offer belongs to a different conversation")
        return claims

    # --------------------------------------------------------------------- booking
    async def book(self, s: AsyncSession, tenant_id: uuid.UUID, *, slot_token: str,
                   contact_id: uuid.UUID, opportunity_id: uuid.UUID | None,
                   conversation_id: uuid.UUID | None, idempotency_key: str,
                   actor_type: str, actor_id: str, attendee_email: str | None,
                   notes: str | None) -> tuple[Appointment, bool]:
        existing = await s.scalar(select(Appointment).where(
            Appointment.idempotency_key == idempotency_key))
        if existing is not None:
            claims = verify_token(self._slot_key, slot_token) or {}
            if existing.starts_at.isoformat() != claims.get("s") or existing.contact_id != contact_id:
                raise Conflict("idempotency key reused with a different booking")
            return existing, False
        claims = self._verify_slot(slot_token, tenant_id, conversation_id)
        atype = await s.get(AppointmentType, uuid.UUID(claims["at"]))
        if atype is None or not atype.active:
            raise NotFound("appointment type unavailable")
        starts, ends = datetime.fromisoformat(claims["s"]), datetime.fromisoformat(claims["e"])
        calendar_id = claims["c"]
        await s.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:k, 0))"),
                        {"k": f"{tenant_id}:{calendar_id}"})
        provider = await self.provider_for(s, atype)
        buffer = timedelta(minutes=atype.buffer_minutes)
        busy = await provider.busy(calendar_id, starts - buffer, ends + buffer)
        busy += await self._db_busy(s, calendar_id, starts - buffer, ends + buffer)
        if busy:
            raise Conflict("that time is no longer available; please choose another slot")
        appt = Appointment(
            id=uuid.uuid4(), tenant_id=tenant_id, appointment_type_id=atype.id,
            contact_id=contact_id, opportunity_id=opportunity_id, conversation_id=conversation_id,
            provider=provider.name, calendar_id=calendar_id, starts_at=starts, ends_at=ends,
            timezone=claims.get("tz") or "UTC", status=AppointmentStatus.BOOKED.value,
            idempotency_key=idempotency_key, created_by_type=actor_type, created_by_id=actor_id)
        s.add(appt)
        try:
            await s.flush()
        except IntegrityError as exc:
            raise Conflict("that time is no longer available; please choose another slot") from exc
        spec = EventSpec(event_key=appt.id.hex, summary=atype.name,
                         description=(notes or "Booked via SAMIIR")[:500], starts_at=starts,
                         ends_at=ends, timezone=appt.timezone, attendee_email=attendee_email)
        # Provider write happens inside the DB transaction: if it fails the booking rolls back;
        # if the commit fails after it, the deterministic event id makes a retry idempotent.
        appt.external_event_id = await provider.create_event(calendar_id, spec)
        return appt, True

    async def get_owned(self, s: AsyncSession, appointment_id: uuid.UUID, *,
                        contact_id: uuid.UUID | None, conversation_id: uuid.UUID | None,
                        is_staff: bool) -> Appointment:
        appt = await s.get(Appointment, appointment_id)
        if appt is None:
            raise NotFound()
        if not is_staff:
            owner_ok = (contact_id is not None and appt.contact_id == contact_id) or (
                conversation_id is not None and appt.conversation_id == conversation_id)
            if not owner_ok:
                raise NotFound()  # IDOR-safe: indistinguishable from nonexistent
        return appt

    async def cancel(self, s: AsyncSession, appt: Appointment, reason: str) -> Appointment:
        if appt.status != AppointmentStatus.BOOKED:
            raise Conflict("appointment is not active")
        atype = await s.get(AppointmentType, appt.appointment_type_id)
        provider = await self.provider_for(s, atype) if atype else LocalCalendarProvider()
        if appt.external_event_id:
            await provider.cancel_event(appt.calendar_id, appt.external_event_id)
        appt.status = AppointmentStatus.CANCELLED.value
        appt.cancelled_at = datetime.now(UTC)
        appt.cancellation_reason = reason
        return appt

    async def reschedule(self, s: AsyncSession, tenant_id: uuid.UUID, appt: Appointment, *,
                         slot_token: str, idempotency_key: str, conversation_id: uuid.UUID | None,
                         actor_type: str, actor_id: str) -> Appointment:
        if appt.status != AppointmentStatus.BOOKED:
            raise Conflict("appointment is not active")
        old_event, calendar_id = appt.external_event_id, appt.calendar_id
        appt.status = AppointmentStatus.RESCHEDULED.value
        await s.flush()
        new, _ = await self.book(s, tenant_id, slot_token=slot_token, contact_id=appt.contact_id,
                                 opportunity_id=appt.opportunity_id,
                                 conversation_id=conversation_id or appt.conversation_id,
                                 idempotency_key=idempotency_key, actor_type=actor_type,
                                 actor_id=actor_id, attendee_email=None,
                                 notes="Rescheduled appointment")
        new.rescheduled_from_id = appt.id
        atype = await s.get(AppointmentType, appt.appointment_type_id)
        if old_event and atype:
            await (await self.provider_for(s, atype)).cancel_event(calendar_id, old_event)
        return new


def to_out(appt: Appointment, type_code: str | None = None) -> AppointmentOut:
    out = AppointmentOut.model_validate(appt, from_attributes=True)
    out.appointment_type = type_code
    return out
