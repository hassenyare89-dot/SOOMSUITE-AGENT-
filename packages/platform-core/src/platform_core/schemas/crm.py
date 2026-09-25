from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field

from platform_core.schemas.common import StrictModel
from platform_core.schemas.enums import PipelineStage

PHONE_PATTERN = r"^\+?[1-9]\d{6,14}$"


class Consent(StrictModel):
    contact_processing: bool = True
    marketing: bool = False
    whatsapp: bool = False
    email: bool = True


class CaptureContactRequest(StrictModel):
    """Contact details supplied by a customer (through SAMIIR or the widget form)."""

    full_name: str | None = Field(default=None, max_length=120)
    email: EmailStr | None = None
    phone: str | None = Field(default=None, pattern=PHONE_PATTERN)
    company_name: str | None = Field(default=None, max_length=200)
    preferred_channel: Literal["web", "whatsapp", "email", "phone"] | None = None
    timezone: str | None = Field(default=None, max_length=64)
    consent: Consent = Field(default_factory=Consent)
    source: Literal["web", "whatsapp", "email", "admin", "import"] = "web"
    conversation_id: UUID | None = None
    whatsapp_ref_hash: str | None = Field(default=None, pattern="^[0-9a-f]{64}$")


class ContactRef(BaseModel):
    contact_id: UUID
    opportunity_id: UUID | None = None
    created: bool


class QualifyLeadRequest(StrictModel):
    contact_id: UUID
    service_interest: str = Field(max_length=200)
    company_size: str | None = Field(default=None, max_length=40)
    budget_range: str | None = Field(default=None, max_length=60)
    timeline: str | None = Field(default=None, max_length=60)
    needs_summary: str = Field(default="", max_length=1000)
    conversation_id: UUID | None = None


class QualifyLeadResponse(BaseModel):
    opportunity_id: UUID
    stage: PipelineStage
    qualified: bool
    missing: list[str]


class StageChangeRequest(StrictModel):
    stage: PipelineStage
    reason: str | None = Field(default=None, max_length=500)
    expected_version: int | None = None


class InternalStageEvent(StrictModel):
    """System-originated stage update (e.g. scheduling after a booking)."""

    opportunity_id: UUID | None = None
    contact_id: UUID
    stage: PipelineStage
    activity_summary: str = Field(max_length=500)
    details: dict = Field(default_factory=dict)


class ActivityIn(StrictModel):
    contact_id: UUID | None = None
    opportunity_id: UUID | None = None
    activity_type: str = Field(pattern="^[a-z_.]{3,64}$")
    summary: str = Field(max_length=1000)
    details: dict = Field(default_factory=dict)


class ContactDelivery(BaseModel):
    """Decrypted delivery details, only for the notifications service."""

    contact_id: UUID
    full_name: str | None
    email: str | None
    phone: str | None
    preferred_channel: str | None
    consent: dict
    timezone: str | None


class OpportunityOut(BaseModel):
    id: UUID
    title: str
    stage: str
    contact_id: UUID | None
    company_id: UUID | None
    estimated_value: Decimal | None
    currency: str
    lead_owner_id: UUID | None
    source: str | None
    service_interest: str | None
    next_action: str | None
    next_action_at: datetime | None
    last_interaction_at: datetime | None
    stage_changed_at: datetime
    version: int
    created_at: datetime
