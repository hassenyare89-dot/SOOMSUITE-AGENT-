from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field

from platform_core.schemas.common import StrictModel


class AvailabilityRequest(StrictModel):
    appointment_type: str = Field(pattern="^[a-z0-9_-]{2,64}$")
    timezone: str = Field("UTC", max_length=64)
    earliest: datetime | None = None
    days: int = Field(7, ge=1, le=30)
    max_slots: int = Field(5, ge=2, le=5)
    conversation_id: UUID | None = None


class SlotOffer(BaseModel):
    slot_token: str
    starts_at: datetime
    ends_at: datetime
    display: str


class AvailabilityResponse(BaseModel):
    appointment_type: str
    appointment_name: str
    timezone: str
    slots: list[SlotOffer]


class BookRequest(StrictModel):
    slot_token: str = Field(min_length=20, max_length=2000)
    contact_id: UUID
    opportunity_id: UUID | None = None
    conversation_id: UUID | None = None
    idempotency_key: str = Field(min_length=16, max_length=128)
    notes: str | None = Field(default=None, max_length=500)


class AppointmentOut(BaseModel):
    id: UUID
    appointment_type_id: UUID
    appointment_type: str | None = None
    contact_id: UUID | None
    opportunity_id: UUID | None
    starts_at: datetime
    ends_at: datetime
    timezone: str
    status: str
    provider: str
    external_event_id: str | None
    created_at: datetime


class RescheduleRequest(StrictModel):
    slot_token: str = Field(min_length=20, max_length=2000)
    idempotency_key: str = Field(min_length=16, max_length=128)
    conversation_id: UUID | None = None


class CancelRequest(StrictModel):
    reason: str = Field("customer_request", max_length=300)
    conversation_id: UUID | None = None
