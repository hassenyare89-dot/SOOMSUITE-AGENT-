"""ORM mapping of the platform schema.

The authoritative DDL (RLS policies, grants, triggers, exclusion constraints) lives in the
Alembic migrations under ``packages/database``; ``tests/integration/test_schema_drift.py``
verifies that this mapping and the migrated schema agree.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any

from pgvector.sqlalchemy import Vector
from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    Numeric,
    SmallInteger,
    String,
    Text,
    Uuid,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from platform_core.db.base import Base, CreatedAt, SoftDelete, TenantScoped, Timestamps, UUIDPk

EMBEDDING_DIMENSIONS = 1536
_JSON_OBJ = text("'{}'::jsonb")
_JSON_ARR = text("'[]'::jsonb")


def _fk(target: str, *, nullable: bool = True, ondelete: str | None = None) -> Any:
    return mapped_column(Uuid, ForeignKey(target, ondelete=ondelete), nullable=nullable)


# --------------------------------------------------------------------------- identity & tenancy
class Tenant(UUIDPk, Timestamps, SoftDelete, Base):
    __tablename__ = "tenants"
    name: Mapped[str] = mapped_column(Text, nullable=False)
    slug: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="active")
    timezone: Mapped[str] = mapped_column(Text, nullable=False, server_default="UTC")
    settings: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=_JSON_OBJ)


class User(UUIDPk, TenantScoped, Timestamps, SoftDelete, Base):
    __tablename__ = "users"
    external_subject: Mapped[str] = mapped_column(Text, nullable=False)
    email_ciphertext: Mapped[str | None] = mapped_column(Text)
    email_hash: Mapped[str | None] = mapped_column(String(64))
    display_name: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="active")
    mfa_enforced: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class RoleRow(UUIDPk, Base):
    __tablename__ = "roles"
    name: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    is_system: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")


class PermissionRow(UUIDPk, Base):
    __tablename__ = "permissions"
    name: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, server_default="")


class RolePermission(Base):
    __tablename__ = "role_permissions"
    role_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True)
    permission_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True)


class UserRole(TenantScoped, Base):
    __tablename__ = "user_roles"
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    role_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True)
    granted_by: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False,
                                                 server_default=func.now())


class Integration(UUIDPk, TenantScoped, Timestamps, Base):
    __tablename__ = "integrations"
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    # Public, non-secret routing key (e.g. WhatsApp phone_number_id, ingest key id).
    external_key: Mapped[str | None] = mapped_column(Text)
    secret_ref: Mapped[str | None] = mapped_column(Text)
    config: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=_JSON_OBJ)
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="active")


class WidgetSite(UUIDPk, TenantScoped, Timestamps, Base):
    __tablename__ = "widget_sites"
    public_key: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    allowed_origins: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False)
    theme: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=_JSON_OBJ)
    greeting: Mapped[str] = mapped_column(Text, nullable=False,
                                          server_default="Hi! How can I help you today?")
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")


# --------------------------------------------------------------------------------------- CRM
class Company(UUIDPk, TenantScoped, Timestamps, SoftDelete, Base):
    __tablename__ = "companies"
    name: Mapped[str] = mapped_column(Text, nullable=False)
    domain: Mapped[str | None] = mapped_column(Text)
    industry: Mapped[str | None] = mapped_column(Text)
    size_band: Mapped[str | None] = mapped_column(Text)
    owner_id: Mapped[uuid.UUID | None] = _fk("users.id")


class Contact(UUIDPk, TenantScoped, Timestamps, SoftDelete, Base):
    __tablename__ = "contacts"
    company_id: Mapped[uuid.UUID | None] = _fk("companies.id")
    full_name: Mapped[str | None] = mapped_column(Text)
    email_ciphertext: Mapped[str | None] = mapped_column(Text)
    email_hash: Mapped[str | None] = mapped_column(String(64))
    phone_ciphertext: Mapped[str | None] = mapped_column(Text)
    phone_hash: Mapped[str | None] = mapped_column(String(64))
    whatsapp_hash: Mapped[str | None] = mapped_column(String(64))
    preferred_channel: Mapped[str | None] = mapped_column(Text)
    timezone: Mapped[str | None] = mapped_column(Text)
    communication_preferences: Mapped[dict] = mapped_column(JSONB, nullable=False,
                                                            server_default=_JSON_OBJ)
    consent: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=_JSON_OBJ)
    source: Mapped[str | None] = mapped_column(Text)
    source_detail: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=_JSON_OBJ)
    owner_id: Mapped[uuid.UUID | None] = _fk("users.id")
    last_interaction_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Opportunity(UUIDPk, TenantScoped, Timestamps, SoftDelete, Base):
    __tablename__ = "opportunities"
    contact_id: Mapped[uuid.UUID | None] = _fk("contacts.id")
    company_id: Mapped[uuid.UUID | None] = _fk("companies.id")
    title: Mapped[str] = mapped_column(Text, nullable=False)
    stage: Mapped[str] = mapped_column(Text, nullable=False, server_default="NEW_LEAD")
    lead_owner_id: Mapped[uuid.UUID | None] = _fk("users.id")
    estimated_value: Mapped[Decimal | None] = mapped_column(Numeric(14, 2))
    currency: Mapped[str] = mapped_column(String(3), nullable=False, server_default="USD")
    source: Mapped[str | None] = mapped_column(Text)
    source_detail: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=_JSON_OBJ)
    qualification: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=_JSON_OBJ)
    service_interest: Mapped[str | None] = mapped_column(Text)
    next_action: Mapped[str | None] = mapped_column(Text)
    next_action_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_interaction_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    lost_reason: Mapped[str | None] = mapped_column(Text)
    stage_changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False,
                                                       server_default=func.now())
    version: Mapped[int] = mapped_column(Integer, nullable=False, server_default="1")


class CrmActivity(UUIDPk, TenantScoped, Base):
    __tablename__ = "crm_activities"
    contact_id: Mapped[uuid.UUID | None] = _fk("contacts.id")
    opportunity_id: Mapped[uuid.UUID | None] = _fk("opportunities.id")
    actor_type: Mapped[str] = mapped_column(Text, nullable=False)
    actor_id: Mapped[str] = mapped_column(Text, nullable=False)
    activity_type: Mapped[str] = mapped_column(Text, nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    details: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=_JSON_OBJ)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False,
                                                  server_default=func.now())


class CrmNote(UUIDPk, TenantScoped, CreatedAt, SoftDelete, Base):
    __tablename__ = "crm_notes"
    contact_id: Mapped[uuid.UUID | None] = _fk("contacts.id")
    opportunity_id: Mapped[uuid.UUID | None] = _fk("opportunities.id")
    author_type: Mapped[str] = mapped_column(Text, nullable=False)
    author_id: Mapped[str] = mapped_column(Text, nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)


class CrmTask(UUIDPk, TenantScoped, Timestamps, Base):
    __tablename__ = "crm_tasks"
    contact_id: Mapped[uuid.UUID | None] = _fk("contacts.id")
    opportunity_id: Mapped[uuid.UUID | None] = _fk("opportunities.id")
    assignee_id: Mapped[uuid.UUID | None] = _fk("users.id")
    title: Mapped[str] = mapped_column(Text, nullable=False)
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="OPEN")
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


# ------------------------------------------------------------------------------- scheduling
class AppointmentType(UUIDPk, TenantScoped, Timestamps, Base):
    __tablename__ = "appointment_types"
    code: Mapped[str] = mapped_column(Text, nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    duration_minutes: Mapped[int] = mapped_column(Integer, nullable=False)
    buffer_minutes: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    calendar_integration_id: Mapped[uuid.UUID | None] = _fk("integrations.id")
    calendar_id: Mapped[str] = mapped_column(Text, nullable=False, server_default="primary")
    rules: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=_JSON_OBJ)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")


class Appointment(UUIDPk, TenantScoped, Timestamps, Base):
    __tablename__ = "appointments"
    appointment_type_id: Mapped[uuid.UUID] = _fk("appointment_types.id", nullable=False)
    contact_id: Mapped[uuid.UUID | None] = _fk("contacts.id")
    opportunity_id: Mapped[uuid.UUID | None] = _fk("opportunities.id")
    conversation_id: Mapped[uuid.UUID | None] = _fk("conversations.id")
    provider: Mapped[str] = mapped_column(Text, nullable=False)
    calendar_id: Mapped[str] = mapped_column(Text, nullable=False)
    external_event_id: Mapped[str | None] = mapped_column(Text)
    starts_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ends_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    timezone: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="BOOKED")
    idempotency_key: Mapped[str] = mapped_column(Text, nullable=False)
    rescheduled_from_id: Mapped[uuid.UUID | None] = _fk("appointments.id")
    created_by_type: Mapped[str] = mapped_column(Text, nullable=False)
    created_by_id: Mapped[str] = mapped_column(Text, nullable=False)
    cancelled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cancellation_reason: Mapped[str | None] = mapped_column(Text)


# ---------------------------------------------------------------------------- conversations
class Conversation(UUIDPk, TenantScoped, Timestamps, Base):
    __tablename__ = "conversations"
    contact_id: Mapped[uuid.UUID | None] = _fk("contacts.id")
    channel: Mapped[str] = mapped_column(Text, nullable=False)
    external_ref_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="OPEN")
    assigned_user_id: Mapped[uuid.UUID | None] = _fk("users.id")
    summary: Mapped[str | None] = mapped_column(Text)
    escalation_reason: Mapped[str | None] = mapped_column(Text)
    last_message_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_inbound_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    context: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=_JSON_OBJ)


class Message(UUIDPk, TenantScoped, CreatedAt, Base):
    __tablename__ = "messages"
    conversation_id: Mapped[uuid.UUID] = _fk("conversations.id", nullable=False,
                                             ondelete="CASCADE")
    direction: Mapped[str] = mapped_column(Text, nullable=False)
    sender_type: Mapped[str] = mapped_column(Text, nullable=False)
    sender_id: Mapped[str | None] = mapped_column(Text)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    content_type: Mapped[str] = mapped_column(Text, nullable=False, server_default="text")
    cards: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=_JSON_ARR)
    external_message_id: Mapped[str | None] = mapped_column(Text)
    delivery_status: Mapped[str | None] = mapped_column(Text)
    injection_score: Mapped[float | None] = mapped_column(Numeric(4, 3))
    metadata_: Mapped[dict] = mapped_column("metadata", JSONB, nullable=False,
                                            server_default=_JSON_OBJ)


# -------------------------------------------------------------------------------- knowledge
class KnowledgeDocument(UUIDPk, TenantScoped, Timestamps, SoftDelete, Base):
    __tablename__ = "knowledge_documents"
    lineage_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(Text, nullable=False)
    visibility: Mapped[str] = mapped_column(Text, nullable=False, server_default="internal")
    version: Mapped[int] = mapped_column(Integer, nullable=False, server_default="1")
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="DRAFT")
    structured_data: Mapped[dict | None] = mapped_column(JSONB)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    injection_flags: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=_JSON_ARR)
    created_by: Mapped[uuid.UUID | None] = _fk("users.id")
    approved_by: Mapped[uuid.UUID | None] = _fk("users.id")
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    effective_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    review_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expiration_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class KnowledgeChunk(UUIDPk, TenantScoped, CreatedAt, Base):
    __tablename__ = "knowledge_chunks"
    document_id: Mapped[uuid.UUID] = _fk("knowledge_documents.id", nullable=False,
                                         ondelete="CASCADE")
    chunk_index: Mapped[int] = mapped_column(Integer, nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    embedding: Mapped[list[float] | None] = mapped_column(Vector(EMBEDDING_DIMENSIONS))
    embedding_model: Mapped[str] = mapped_column(Text, nullable=False)


# ----------------------------------------------------------------------------- notifications
class Notification(UUIDPk, TenantScoped, Timestamps, Base):
    __tablename__ = "notifications"
    channel: Mapped[str] = mapped_column(Text, nullable=False)
    template: Mapped[str] = mapped_column(Text, nullable=False)
    contact_id: Mapped[uuid.UUID | None] = _fk("contacts.id")
    recipient_user_id: Mapped[uuid.UUID | None] = _fk("users.id")
    variables: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=_JSON_OBJ)
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="SCHEDULED")
    scheduled_for: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False,
                                                    server_default=func.now())
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    last_error: Mapped[str | None] = mapped_column(Text)
    provider_message_id: Mapped[str | None] = mapped_column(Text)
    idempotency_key: Mapped[str] = mapped_column(Text, nullable=False)
    related_type: Mapped[str | None] = mapped_column(Text)
    related_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    requested_by: Mapped[str] = mapped_column(Text, nullable=False)


# ---------------------------------------------------------------------------------- security
class Asset(UUIDPk, TenantScoped, Timestamps, SoftDelete, Base):
    __tablename__ = "assets"
    name: Mapped[str] = mapped_column(Text, nullable=False)
    asset_type: Mapped[str] = mapped_column(Text, nullable=False, server_default="website")
    canonical_target: Mapped[str] = mapped_column(Text, nullable=False)
    environment: Mapped[str] = mapped_column(Text, nullable=False, server_default="production")
    criticality: Mapped[int] = mapped_column(SmallInteger, nullable=False, server_default="3")
    owner: Mapped[str | None] = mapped_column(Text)
    tags: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False,
                                            server_default=text("'{}'::text[]"))
    allowlisted: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    verification_status: Mapped[str] = mapped_column(Text, nullable=False,
                                                     server_default="UNVERIFIED")
    verified_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    customer_authorization_ref: Mapped[str | None] = mapped_column(Text)
    customer_authorization_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True))


class AssetVerification(UUIDPk, TenantScoped, CreatedAt, Base):
    __tablename__ = "asset_verifications"
    asset_id: Mapped[uuid.UUID] = _fk("assets.id", nullable=False)
    method: Mapped[str] = mapped_column(Text, nullable=False)
    challenge_token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="PENDING")
    requested_by: Mapped[str] = mapped_column(Text, nullable=False)
    checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    failure_reason: Mapped[str | None] = mapped_column(Text)


class SecurityEvent(TenantScoped, Base):
    __tablename__ = "security_events"
    event_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    asset_id: Mapped[uuid.UUID | None] = _fk("assets.id")
    source: Mapped[str] = mapped_column(Text, nullable=False)
    event_type: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    confidence: Mapped[Decimal] = mapped_column(Numeric(4, 3), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    src_ip: Mapped[str | None] = mapped_column(INET)
    destination: Mapped[str | None] = mapped_column(Text)
    request_path: Mapped[str | None] = mapped_column(Text)
    http_method: Mapped[str | None] = mapped_column(Text)
    status_code: Mapped[int | None] = mapped_column(SmallInteger)
    user_id: Mapped[str | None] = mapped_column(Text)
    country: Mapped[str | None] = mapped_column(String(2))
    user_agent: Mapped[str | None] = mapped_column(Text)
    signature: Mapped[str | None] = mapped_column(Text)
    rule_id: Mapped[str | None] = mapped_column(Text)
    action_taken: Mapped[str | None] = mapped_column(Text)
    risk: Mapped[str | None] = mapped_column(Text)
    metadata_redacted: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=_JSON_OBJ)
    raw_event_reference: Mapped[str | None] = mapped_column(Text)
    dedupe_key: Mapped[str] = mapped_column(String(64), nullable=False)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False,
                                                  server_default=func.now())


class Incident(UUIDPk, TenantScoped, Timestamps, Base):
    __tablename__ = "incidents"
    title: Mapped[str] = mapped_column(Text, nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    category: Mapped[str] = mapped_column(Text, nullable=False)
    asset_id: Mapped[uuid.UUID | None] = _fk("assets.id")
    risk_level: Mapped[str] = mapped_column(Text, nullable=False)
    risk_score: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    claim_status: Mapped[str] = mapped_column(Text, nullable=False,
                                              server_default="SUSPECTED INCIDENT")
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="NEW")
    correlation_key: Mapped[str] = mapped_column(String(64), nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    signals: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=_JSON_ARR)
    recommendations: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=_JSON_ARR)
    analysis: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=_JSON_OBJ)
    assignee_id: Mapped[uuid.UUID | None] = _fk("users.id")
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    contained_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    confirmed_by: Mapped[uuid.UUID | None] = _fk("users.id")
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    confirmation_evidence: Mapped[dict | None] = mapped_column(JSONB)


class IncidentEvent(UUIDPk, TenantScoped, CreatedAt, Base):
    __tablename__ = "incident_events"
    incident_id: Mapped[uuid.UUID] = _fk("incidents.id", nullable=False, ondelete="CASCADE")
    security_event_id: Mapped[uuid.UUID | None] = _fk("security_events.event_id")
    entry_type: Mapped[str] = mapped_column(Text, nullable=False)
    actor_type: Mapped[str] = mapped_column(Text, nullable=False)
    actor_id: Mapped[str] = mapped_column(Text, nullable=False)
    body: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=_JSON_OBJ)


class ApprovalRequest(UUIDPk, TenantScoped, Base):
    __tablename__ = "approval_requests"
    action_type: Mapped[str] = mapped_column(Text, nullable=False)
    action_payload: Mapped[dict] = mapped_column(JSONB, nullable=False)
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    target_type: Mapped[str | None] = mapped_column(Text)
    target_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    requested_by: Mapped[str] = mapped_column(Text, nullable=False)
    requested_by_type: Mapped[str] = mapped_column(Text, nullable=False)
    requested_via: Mapped[str] = mapped_column(Text, nullable=False)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False,
                                                   server_default=func.now())
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    risk_level: Mapped[str] = mapped_column(Text, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="PENDING")
    approved_by: Mapped[str | None] = mapped_column(Text)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    decision_comment: Mapped[str | None] = mapped_column(Text)
    approval_signature: Mapped[str | None] = mapped_column(Text)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    consumed_by: Mapped[str | None] = mapped_column(Text)


class ScanJob(UUIDPk, TenantScoped, Timestamps, Base):
    __tablename__ = "scan_jobs"
    asset_id: Mapped[uuid.UUID] = _fk("assets.id", nullable=False)
    target_url: Mapped[str] = mapped_column(Text, nullable=False)
    requested_by: Mapped[str] = mapped_column(Text, nullable=False)
    approval_id: Mapped[uuid.UUID | None] = _fk("approval_requests.id")
    authorization_ticket: Mapped[str] = mapped_column(Text, nullable=False)
    customer_authorization_ref: Mapped[str] = mapped_column(Text, nullable=False)
    profile: Mapped[str] = mapped_column(Text, nullable=False)
    scanners: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="PENDING_APPROVAL")
    workflow_id: Mapped[str | None] = mapped_column(Text)
    idempotency_key: Mapped[str] = mapped_column(Text, nullable=False)
    scheduled_for: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False, server_default="3600")
    attempt: Mapped[int] = mapped_column(Integer, nullable=False, server_default="1")
    retry_of_id: Mapped[uuid.UUID | None] = _fk("scan_jobs.id")
    findings_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    error: Mapped[str | None] = mapped_column(Text)
    scanner_log: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=_JSON_ARR)


class Finding(UUIDPk, TenantScoped, Timestamps, Base):
    __tablename__ = "findings"
    scan_job_id: Mapped[uuid.UUID | None] = _fk("scan_jobs.id")
    asset_id: Mapped[uuid.UUID] = _fk("assets.id", nullable=False)
    scanner: Mapped[str] = mapped_column(Text, nullable=False)
    rule_id: Mapped[str] = mapped_column(Text, nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    category: Mapped[str] = mapped_column(Text, nullable=False, server_default="vulnerability")
    severity: Mapped[str] = mapped_column(Text, nullable=False)
    cvss_score: Mapped[Decimal | None] = mapped_column(Numeric(3, 1))
    cwe: Mapped[str | None] = mapped_column(Text)
    url: Mapped[str | None] = mapped_column(Text)
    evidence_redacted: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=_JSON_OBJ)
    remediation: Mapped[str | None] = mapped_column(Text)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    false_positive_status: Mapped[str] = mapped_column(Text, nullable=False,
                                                       server_default="UNREVIEWED")
    remediation_status: Mapped[str] = mapped_column(Text, nullable=False, server_default="OPEN")
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False,
                                                 server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False,
                                                server_default=func.now())
    remediated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reviewed_by: Mapped[str | None] = mapped_column(Text)


class MalwareResult(UUIDPk, TenantScoped, Timestamps, Base):
    __tablename__ = "malware_results"
    asset_id: Mapped[uuid.UUID | None] = _fk("assets.id")
    filename_sanitized: Mapped[str] = mapped_column(Text, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    sha1: Mapped[str] = mapped_column(String(40), nullable=False)
    md5: Mapped[str] = mapped_column(String(32), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    mime_declared: Mapped[str | None] = mapped_column(Text)
    mime_detected: Mapped[str | None] = mapped_column(Text)
    clamav_result: Mapped[str | None] = mapped_column(Text)
    clamav_signature: Mapped[str | None] = mapped_column(Text)
    yara_matches: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=_JSON_ARR)
    archive_info: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=_JSON_OBJ)
    verdict: Mapped[str] = mapped_column(Text, nullable=False, server_default="pending")
    quarantine_status: Mapped[str] = mapped_column(Text, nullable=False,
                                                   server_default="QUARANTINED")
    storage_ref: Mapped[str] = mapped_column(Text, nullable=False)
    submitted_by: Mapped[str] = mapped_column(Text, nullable=False)
    analyzed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error: Mapped[str | None] = mapped_column(Text)


class WafAction(UUIDPk, TenantScoped, Timestamps, Base):
    __tablename__ = "waf_actions"
    incident_id: Mapped[uuid.UUID | None] = _fk("incidents.id")
    approval_id: Mapped[uuid.UUID | None] = _fk("approval_requests.id")
    provider: Mapped[str] = mapped_column(Text, nullable=False)
    action_type: Mapped[str] = mapped_column(Text, nullable=False)
    target: Mapped[str] = mapped_column(Text, nullable=False)
    params: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=_JSON_OBJ)
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    risk_level: Mapped[str] = mapped_column(Text, nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    mode: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="RECOMMENDED")
    ttl_seconds: Mapped[int | None] = mapped_column(Integer)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    executed_by: Mapped[str | None] = mapped_column(Text)
    provider_ref: Mapped[str | None] = mapped_column(Text)
    error: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[str] = mapped_column(Text, nullable=False)


# ------------------------------------------------------------------------ agents & auditing
class AgentRun(UUIDPk, TenantScoped, Base):
    __tablename__ = "agent_runs"
    agent_name: Mapped[str] = mapped_column(Text, nullable=False)
    actor_type: Mapped[str] = mapped_column(Text, nullable=False)
    actor_id: Mapped[str] = mapped_column(Text, nullable=False)
    conversation_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    incident_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    runtime: Mapped[str] = mapped_column(Text, nullable=False)
    model: Mapped[str | None] = mapped_column(Text)
    trace_id: Mapped[str | None] = mapped_column(Text)
    request_id: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="RUNNING")
    input_tokens: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    output_tokens: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    latency_ms: Mapped[int | None] = mapped_column(Integer)
    guardrail_flags: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=_JSON_ARR)
    error: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False,
                                                 server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ToolCall(UUIDPk, TenantScoped, CreatedAt, Base):
    __tablename__ = "tool_calls"
    agent_run_id: Mapped[uuid.UUID] = _fk("agent_runs.id", nullable=False, ondelete="CASCADE")
    agent_name: Mapped[str] = mapped_column(Text, nullable=False)
    tool_name: Mapped[str] = mapped_column(Text, nullable=False)
    arguments_redacted: Mapped[dict] = mapped_column(JSONB, nullable=False,
                                                     server_default=_JSON_OBJ)
    arguments_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    decision: Mapped[str] = mapped_column(Text, nullable=False)
    decision_reason: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    latency_ms: Mapped[int | None] = mapped_column(Integer)
    error: Mapped[str | None] = mapped_column(Text)


class AuditLog(UUIDPk, TenantScoped, Base):
    __tablename__ = "audit_logs"
    seq: Mapped[int] = mapped_column(BigInteger, nullable=False)
    actor_type: Mapped[str] = mapped_column(Text, nullable=False)
    actor_id: Mapped[str] = mapped_column(Text, nullable=False)
    agent_name: Mapped[str | None] = mapped_column(Text)
    agent_run_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    service: Mapped[str] = mapped_column(Text, nullable=False)
    tool_name: Mapped[str | None] = mapped_column(Text)
    action: Mapped[str] = mapped_column(Text, nullable=False)
    target_type: Mapped[str | None] = mapped_column(Text)
    target_id: Mapped[str | None] = mapped_column(Text)
    request_id: Mapped[str] = mapped_column(Text, nullable=False)
    source_ip: Mapped[str | None] = mapped_column(INET)
    result: Mapped[str] = mapped_column(Text, nullable=False)
    risk_level: Mapped[str | None] = mapped_column(Text)
    approval_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    metadata_redacted: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=_JSON_OBJ)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
