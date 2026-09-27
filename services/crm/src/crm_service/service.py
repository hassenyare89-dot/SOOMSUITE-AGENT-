"""CRM domain logic. PII fields are encrypted at rest; lookups use keyed blind indexes."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from platform_core.db.models import (
    Company,
    Contact,
    CrmActivity,
    CrmNote,
    CrmTask,
    Opportunity,
)
from platform_core.errors import Conflict, NotFound, ValidationFailed
from platform_core.schemas.common import StrictModel
from platform_core.schemas.crm import (
    PHONE_PATTERN,
    CaptureContactRequest,
    ContactDelivery,
    ContactRef,
    QualifyLeadRequest,
    QualifyLeadResponse,
)
from platform_core.schemas.enums import PIPELINE_TRANSITIONS, PipelineStage
from platform_core.security.crypto import FieldEncryptor
from platform_core.security.untrusted import normalize_text

OPEN_STAGES = [s.value for s in PipelineStage if s not in (PipelineStage.WON, PipelineStage.LOST)]


# ------------------------------------------------------------------------------ DTOs
class ContactOut(BaseModel):
    id: uuid.UUID
    company_id: uuid.UUID | None
    full_name: str | None
    email: str | None
    phone: str | None
    preferred_channel: str | None
    timezone: str | None
    consent: dict
    communication_preferences: dict
    source: str | None
    owner_id: uuid.UUID | None
    last_interaction_at: datetime | None
    created_at: datetime


class ContactIn(StrictModel):
    full_name: str | None = Field(default=None, max_length=120)
    email: EmailStr | None = None
    phone: str | None = Field(default=None, pattern=PHONE_PATTERN)
    company_id: uuid.UUID | None = None
    preferred_channel: str | None = Field(default=None, pattern="^(web|whatsapp|email|phone)$")
    timezone: str | None = Field(default=None, max_length=64)
    consent: dict[str, bool] | None = None
    communication_preferences: dict[str, Any] | None = None
    owner_id: uuid.UUID | None = None
    source: str | None = Field(default="admin", max_length=40)


class CompanyIn(StrictModel):
    name: str = Field(min_length=1, max_length=200)
    domain: str | None = Field(default=None, pattern=r"^[a-z0-9.-]{3,253}$")
    industry: str | None = Field(default=None, max_length=100)
    size_band: str | None = Field(default=None, max_length=40)
    owner_id: uuid.UUID | None = None


class CompanyOut(BaseModel):
    id: uuid.UUID
    name: str
    domain: str | None
    industry: str | None
    size_band: str | None
    owner_id: uuid.UUID | None
    created_at: datetime


class OpportunityIn(StrictModel):
    title: str = Field(min_length=2, max_length=200)
    contact_id: uuid.UUID | None = None
    company_id: uuid.UUID | None = None
    estimated_value: Decimal | None = Field(default=None, ge=0, le=Decimal("1e12"))
    currency: str = Field("USD", pattern="^[A-Z]{3}$")
    lead_owner_id: uuid.UUID | None = None
    source: str | None = Field(default="admin", max_length=40)
    service_interest: str | None = Field(default=None, max_length=200)
    next_action: str | None = Field(default=None, max_length=300)
    next_action_at: datetime | None = None


class OpportunityPatch(StrictModel):
    title: str | None = Field(default=None, min_length=2, max_length=200)
    estimated_value: Decimal | None = Field(default=None, ge=0, le=Decimal("1e12"))
    currency: str | None = Field(default=None, pattern="^[A-Z]{3}$")
    lead_owner_id: uuid.UUID | None = None
    next_action: str | None = Field(default=None, max_length=300)
    next_action_at: datetime | None = None
    service_interest: str | None = Field(default=None, max_length=200)
    expected_version: int


class NoteIn(StrictModel):
    contact_id: uuid.UUID | None = None
    opportunity_id: uuid.UUID | None = None
    body: str = Field(min_length=1, max_length=20_000)


class TaskIn(StrictModel):
    title: str = Field(min_length=2, max_length=300)
    contact_id: uuid.UUID | None = None
    opportunity_id: uuid.UUID | None = None
    assignee_id: uuid.UUID | None = None
    due_at: datetime | None = None


class TaskPatch(StrictModel):
    status: str | None = Field(default=None, pattern="^(OPEN|DONE|CANCELLED)$")
    title: str | None = Field(default=None, min_length=2, max_length=300)
    due_at: datetime | None = None
    assignee_id: uuid.UUID | None = None


class CrmService:
    def __init__(self, enc: FieldEncryptor) -> None:
        self.enc = enc

    # ------------------------------------------------------------------ helpers
    def contact_out(self, c: Contact) -> ContactOut:
        return ContactOut(
            id=c.id, company_id=c.company_id, full_name=c.full_name,
            email=self.enc.decrypt(c.email_ciphertext, c.tenant_id),
            phone=self.enc.decrypt(c.phone_ciphertext, c.tenant_id),
            preferred_channel=c.preferred_channel, timezone=c.timezone, consent=c.consent,
            communication_preferences=c.communication_preferences, source=c.source,
            owner_id=c.owner_id, last_interaction_at=c.last_interaction_at,
            created_at=c.created_at)

    async def _contact(self, s: AsyncSession, contact_id: uuid.UUID) -> Contact:
        c = await s.get(Contact, contact_id)
        if c is None or c.deleted_at is not None:
            raise NotFound()
        return c

    async def _opportunity(self, s: AsyncSession, opp_id: uuid.UUID) -> Opportunity:
        o = await s.get(Opportunity, opp_id)
        if o is None or o.deleted_at is not None:
            raise NotFound()
        return o

    async def add_activity(self, s: AsyncSession, tenant_id: uuid.UUID, *, actor_type: str,
                           actor_id: str, activity_type: str, summary: str,
                           contact_id: uuid.UUID | None = None,
                           opportunity_id: uuid.UUID | None = None,
                           details: dict | None = None) -> CrmActivity:
        a = CrmActivity(tenant_id=tenant_id, contact_id=contact_id, opportunity_id=opportunity_id,
                        actor_type=actor_type, actor_id=actor_id, activity_type=activity_type,
                        summary=normalize_text(summary, max_len=1000), details=details or {})
        s.add(a)
        now = datetime.now(UTC)
        if contact_id:
            c = await s.get(Contact, contact_id)
            if c:
                c.last_interaction_at = now
        if opportunity_id:
            o = await s.get(Opportunity, opportunity_id)
            if o:
                o.last_interaction_at = now
        return a

    async def _find_company(self, s: AsyncSession, tenant_id: uuid.UUID,
                            name: str) -> Company:
        existing = await s.scalar(select(Company).where(
            func.lower(Company.name) == name.lower(), Company.deleted_at.is_(None)))
        if existing:
            return existing
        company = Company(tenant_id=tenant_id, name=name)
        s.add(company)
        await s.flush()
        return company

    # --------------------------------------------------------- customer capture (SAMIIR)
    async def capture_contact(self, s: AsyncSession, tenant_id: uuid.UUID,
                              req: CaptureContactRequest, actor: str) -> ContactRef:
        if not (req.email or req.phone or req.whatsapp_ref_hash):
            raise ValidationFailed("an email, phone number or WhatsApp identity is required")
        if not req.consent.contact_processing:
            raise ValidationFailed("consent to process contact details is required")
        email_h = self.enc.blind_index(str(req.email) if req.email else None, tenant_id, "email")
        phone_h = self.enc.blind_index(req.phone, tenant_id, "phone")
        conds = []
        if email_h:
            conds.append(Contact.email_hash == email_h)
        if phone_h:
            conds.append(Contact.phone_hash == phone_h)
        if req.whatsapp_ref_hash:
            conds.append(Contact.whatsapp_hash == req.whatsapp_ref_hash)
        contact = await s.scalar(select(Contact).where(or_(*conds), Contact.deleted_at.is_(None))
                                 .order_by(Contact.created_at).limit(1))
        created = contact is None
        now = datetime.now(UTC)
        consent = req.consent.model_dump() | {"recorded_at": now.isoformat(), "source": req.source}
        if contact is None:
            contact = Contact(tenant_id=tenant_id, source=req.source, consent=consent,
                              source_detail={"conversation_id": str(req.conversation_id)}
                              if req.conversation_id else {})
            s.add(contact)
        # Fill only empty fields: an unauthenticated submitter can never overwrite or read
        # data already on file for an existing contact.
        if req.full_name and not contact.full_name:
            contact.full_name = normalize_text(req.full_name, max_len=120)
        if req.email and not contact.email_ciphertext:
            contact.email_ciphertext = self.enc.encrypt(str(req.email), tenant_id)
            contact.email_hash = email_h
        if req.phone and not contact.phone_ciphertext:
            contact.phone_ciphertext = self.enc.encrypt(req.phone, tenant_id)
            contact.phone_hash = phone_h
        if req.whatsapp_ref_hash and not contact.whatsapp_hash:
            contact.whatsapp_hash = req.whatsapp_ref_hash
        if req.preferred_channel and not contact.preferred_channel:
            contact.preferred_channel = req.preferred_channel
        if req.timezone and not contact.timezone:
            contact.timezone = req.timezone
        if not created:
            history = list(contact.consent.get("history", []))[-20:]
            history.append(consent)
            contact.consent = {**contact.consent, "history": history}
        if req.company_name and contact.company_id is None:
            company = await self._find_company(s, tenant_id, normalize_text(req.company_name, 200))
            contact.company_id = company.id
        contact.last_interaction_at = now
        await s.flush()
        opp = await s.scalar(select(Opportunity).where(
            Opportunity.contact_id == contact.id, Opportunity.stage.in_(OPEN_STAGES),
            Opportunity.deleted_at.is_(None)).order_by(Opportunity.created_at.desc()).limit(1))
        if opp is None:
            opp = Opportunity(tenant_id=tenant_id, contact_id=contact.id,
                              company_id=contact.company_id,
                              title=f"Inbound lead via {req.source}",
                              stage=PipelineStage.NEW_LEAD.value, source=req.source,
                              source_detail={"channel": req.source},
                              last_interaction_at=now)
            s.add(opp)
            await s.flush()
        await self.add_activity(s, tenant_id, actor_type="agent", actor_id=actor,
                                activity_type="contact.captured" if created
                                else "contact.details_submitted",
                                summary="Customer shared contact details",
                                contact_id=contact.id, opportunity_id=opp.id,
                                details={"channel": req.source,
                                         "conversation_id": str(req.conversation_id or "")})
        return ContactRef(contact_id=contact.id, opportunity_id=opp.id, created=created)

    async def qualify(self, s: AsyncSession, tenant_id: uuid.UUID, req: QualifyLeadRequest,
                      actor: str) -> QualifyLeadResponse:
        contact = await self._contact(s, req.contact_id)
        opp = await s.scalar(select(Opportunity).where(
            Opportunity.contact_id == contact.id, Opportunity.stage.in_(OPEN_STAGES),
            Opportunity.deleted_at.is_(None)).order_by(Opportunity.created_at.desc()).limit(1))
        if opp is None:
            opp = Opportunity(tenant_id=tenant_id, contact_id=contact.id,
                              company_id=contact.company_id, title="Inbound lead",
                              source=contact.source or "web")
            s.add(opp)
            await s.flush()
        qualification = {**opp.qualification, **{k: normalize_text(v, max_len=1000) for k, v in {
            "service_interest": req.service_interest, "company_size": req.company_size,
            "budget_range": req.budget_range, "timeline": req.timeline,
            "needs_summary": req.needs_summary}.items() if v}}
        opp.qualification = qualification
        opp.service_interest = qualification.get("service_interest")
        opp.title = f"{qualification.get('service_interest', 'Inbound lead')}"[:200]
        missing = [k for k in ("service_interest", "timeline") if not qualification.get(k)]
        if not (contact.email_hash or contact.phone_hash or contact.whatsapp_hash):
            missing.append("contact_details")
        qualified = not missing
        if qualified and opp.stage == PipelineStage.NEW_LEAD.value:
            self._transition(opp, PipelineStage.QUALIFIED)
        await self.add_activity(s, tenant_id, actor_type="agent", actor_id=actor,
                                activity_type="lead.qualification_updated",
                                summary="Qualification updated "
                                f"({'qualified' if qualified else 'incomplete'})",
                                contact_id=contact.id, opportunity_id=opp.id,
                                details={"missing": missing})
        return QualifyLeadResponse(opportunity_id=opp.id, stage=PipelineStage(opp.stage),
                                   qualified=qualified, missing=missing)

    # ----------------------------------------------------------------- pipeline
    @staticmethod
    def _transition(opp: Opportunity, target: PipelineStage, *, human: bool = False) -> None:
        current = PipelineStage(opp.stage)
        if current == target:
            return
        allowed = PIPELINE_TRANSITIONS[current]
        if target not in allowed and not (human and target not in (PipelineStage.WON,)):
            raise Conflict(f"cannot move from {current} to {target}")
        opp.stage = target.value
        opp.stage_changed_at = datetime.now(UTC)
        opp.version += 1

    async def change_stage(self, s: AsyncSession, tenant_id: uuid.UUID, opp_id: uuid.UUID,
                           stage: PipelineStage, *, actor_type: str, actor_id: str,
                           reason: str | None, expected_version: int | None,
                           human: bool) -> Opportunity:
        opp = await self._opportunity(s, opp_id)
        if expected_version is not None and opp.version != expected_version:
            raise Conflict("opportunity was modified concurrently")
        previous = opp.stage
        self._transition(opp, stage, human=human)
        if stage == PipelineStage.LOST:
            opp.lost_reason = reason
        await self.add_activity(s, tenant_id, actor_type=actor_type, actor_id=actor_id,
                                activity_type="pipeline.stage_changed",
                                summary=f"Stage {previous} → {stage.value}",
                                contact_id=opp.contact_id, opportunity_id=opp.id,
                                details={"from": previous, "to": stage.value, "reason": reason})
        return opp

    async def system_stage_event(self, s: AsyncSession, tenant_id: uuid.UUID,
                                 contact_id: uuid.UUID, opp_id: uuid.UUID | None,
                                 stage: PipelineStage, summary: str, details: dict,
                                 actor: str) -> Opportunity:
        await self._contact(s, contact_id)
        opp = None
        if opp_id:
            opp = await self._opportunity(s, opp_id)
            if opp.contact_id != contact_id:
                raise NotFound()
        if opp is None:
            opp = await s.scalar(select(Opportunity).where(
                Opportunity.contact_id == contact_id, Opportunity.stage.in_(OPEN_STAGES),
                Opportunity.deleted_at.is_(None)).order_by(Opportunity.created_at.desc()).limit(1))
        if opp is None:
            opp = Opportunity(tenant_id=tenant_id, contact_id=contact_id, title="Inbound lead",
                              source="web")
            s.add(opp)
            await s.flush()
        try:
            self._transition(opp, stage)
        except Conflict:
            pass  # e.g. already further along the pipeline; still record the activity
        await self.add_activity(s, tenant_id, actor_type="service", actor_id=actor,
                                activity_type=f"system.{stage.value.lower()}", summary=summary,
                                contact_id=contact_id, opportunity_id=opp.id, details=details)
        return opp

    # ---------------------------------------------------------------- delivery
    async def delivery(self, s: AsyncSession, contact_id: uuid.UUID) -> ContactDelivery:
        c = await self._contact(s, contact_id)
        return ContactDelivery(contact_id=c.id, full_name=c.full_name,
                               email=self.enc.decrypt(c.email_ciphertext, c.tenant_id),
                               phone=self.enc.decrypt(c.phone_ciphertext, c.tenant_id),
                               preferred_channel=c.preferred_channel, consent=c.consent,
                               timezone=c.timezone)

    # ------------------------------------------------------------------- admin
    async def list_contacts(self, s: AsyncSession, tenant_id: uuid.UUID, q: str | None,
                            limit: int, offset: int) -> tuple[list[Contact], int]:
        stmt = select(Contact).where(Contact.deleted_at.is_(None))
        if q:
            email_h = self.enc.blind_index(q, tenant_id, "email")
            phone_h = self.enc.blind_index(q, tenant_id, "phone")
            stmt = stmt.where(or_(Contact.full_name.ilike(f"%{q.replace('%', '')}%"),
                                  Contact.email_hash == email_h, Contact.phone_hash == phone_h))
        total = await s.scalar(select(func.count()).select_from(stmt.subquery()))
        rows = (await s.scalars(stmt.order_by(Contact.last_interaction_at.desc().nulls_last())
                                .limit(limit).offset(offset))).all()
        return list(rows), int(total or 0)

    async def create_contact(self, s: AsyncSession, tenant_id: uuid.UUID, body: ContactIn
                             ) -> Contact:
        email_h = self.enc.blind_index(str(body.email) if body.email else None, tenant_id, "email")
        if email_h and await s.scalar(select(Contact.id).where(Contact.email_hash == email_h,
                                                               Contact.deleted_at.is_(None))):
            raise Conflict("a contact with this email already exists")
        c = Contact(tenant_id=tenant_id, full_name=body.full_name, company_id=body.company_id,
                    email_ciphertext=self.enc.encrypt(str(body.email) if body.email else None,
                                                      tenant_id),
                    email_hash=email_h,
                    phone_ciphertext=self.enc.encrypt(body.phone, tenant_id),
                    phone_hash=self.enc.blind_index(body.phone, tenant_id, "phone"),
                    preferred_channel=body.preferred_channel, timezone=body.timezone,
                    consent=body.consent or {}, source=body.source, owner_id=body.owner_id,
                    communication_preferences=body.communication_preferences or {})
        s.add(c)
        await s.flush()
        return c

    async def update_contact(self, s: AsyncSession, tenant_id: uuid.UUID, cid: uuid.UUID,
                             body: ContactIn) -> Contact:
        c = await self._contact(s, cid)
        data = body.model_dump(exclude_unset=True)
        if "email" in data:
            c.email_ciphertext = self.enc.encrypt(str(body.email) if body.email else None, tenant_id)
            c.email_hash = self.enc.blind_index(str(body.email) if body.email else None,
                                                tenant_id, "email")
        if "phone" in data:
            c.phone_ciphertext = self.enc.encrypt(body.phone, tenant_id)
            c.phone_hash = self.enc.blind_index(body.phone, tenant_id, "phone")
        for key in ("full_name", "company_id", "preferred_channel", "timezone", "consent",
                    "communication_preferences", "owner_id"):
            if key in data:
                setattr(c, key, data[key] if data[key] is not None or key not in
                        ("consent", "communication_preferences") else {})
        await s.flush()
        return c

    async def soft_delete_contact(self, s: AsyncSession, cid: uuid.UUID) -> None:
        c = await self._contact(s, cid)
        c.deleted_at = datetime.now(UTC)
        # Crypto-shred PII on deletion requests (GDPR/erasure); keep the business record.
        c.email_ciphertext = c.phone_ciphertext = None
        c.email_hash = c.phone_hash = c.whatsapp_hash = None
        c.full_name = "[erased]"

    async def pipeline(self, s: AsyncSession) -> list[dict]:
        rows = (await s.execute(select(Opportunity.stage, func.count(),
                                       func.coalesce(func.sum(Opportunity.estimated_value), 0))
                                .where(Opportunity.deleted_at.is_(None))
                                .group_by(Opportunity.stage))).all()
        by_stage = {r[0]: (int(r[1]), r[2]) for r in rows}
        return [{"stage": st.value, "count": by_stage.get(st.value, (0, 0))[0],
                 "value": str(by_stage.get(st.value, (0, Decimal(0)))[1])} for st in PipelineStage]

    async def metrics(self, s: AsyncSession) -> dict:
        since = func.now() - func.make_interval(0, 0, 0, 30)
        new_leads = await s.scalar(select(func.count()).select_from(Opportunity).where(
            Opportunity.created_at >= since))
        won = await s.scalar(select(func.count()).select_from(Opportunity).where(
            Opportunity.stage == "WON", Opportunity.stage_changed_at >= since))
        activities = await s.scalar(select(func.count()).select_from(CrmActivity).where(
            CrmActivity.occurred_at >= since))
        return {"new_leads_30d": new_leads or 0, "won_30d": won or 0,
                "activities_30d": activities or 0, "pipeline": await self.pipeline(s)}


__all__ = ["CompanyIn", "CompanyOut", "ContactIn", "ContactOut", "CrmNote", "CrmService", "CrmTask",
           "NoteIn", "OpportunityIn", "OpportunityPatch", "TaskIn", "TaskPatch"]
