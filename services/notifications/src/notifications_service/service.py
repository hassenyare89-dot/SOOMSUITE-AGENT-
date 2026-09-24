from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import UTC, datetime, timedelta

from pydantic import Field
from sqlalchemy import select, text, update

from notifications_service.senders import EmailSender, WhatsAppRelay, post_slack
from notifications_service.templates import (
    TEMPLATES,
    build_variables,
    render_email_html,
    render_text,
    template_for,
)
from platform_core.db.engine import Database
from platform_core.db.models import Notification, RoleRow, User, UserRole
from platform_core.errors import PlatformError, ValidationFailed
from platform_core.observability import instruments
from platform_core.schemas.common import StrictModel
from platform_core.security.crypto import FieldEncryptor
from platform_core.security.principal import Principal

log = logging.getLogger(__name__)


class NotificationIn(StrictModel):
    template: str = Field(max_length=100)
    channel: str = Field(pattern="^(email|whatsapp|slack)$")
    contact_id: uuid.UUID | None = None
    recipient_user_id: uuid.UUID | None = None
    security_team: bool = False
    variables: dict[str, str | int | float | None] = Field(default_factory=dict, max_length=30)
    scheduled_for: datetime | None = None
    idempotency_key: str = Field(min_length=8, max_length=200)
    related_type: str | None = Field(default=None, max_length=40)
    related_id: uuid.UUID | None = None


class CancelIn(StrictModel):
    related_type: str = Field(max_length=40)
    related_id: uuid.UUID


class NotificationService:
    def __init__(self, db: Database, email: EmailSender, whatsapp: WhatsAppRelay | None,
                 crm_client, enc: FieldEncryptor, *, slack_url: str | None,  # noqa: ANN001
                 max_attempts: int = 5) -> None:
        self.db = db
        self.email = email
        self.whatsapp = whatsapp
        self.crm = crm_client
        self.enc = enc
        self.slack_url = slack_url
        self.max_attempts = max_attempts

    async def enqueue(self, tenant_id: uuid.UUID, body: NotificationIn, caller: str
                      ) -> uuid.UUID:
        tpl = template_for(body.template, caller)
        if tpl.category == "customer" and body.contact_id is None:
            raise ValidationFailed("customer notifications require a contact")
        if tpl.category == "security" and not (body.recipient_user_id or body.security_team):
            raise ValidationFailed("security notifications require internal recipients")
        missing = [k for k in tpl.required if k not in body.variables]
        if missing:
            raise ValidationFailed("missing template variables", details={"missing": missing})
        async with self.db.tenant_session(tenant_id, actor=caller) as s:
            existing = await s.scalar(select(Notification.id).where(
                Notification.idempotency_key == body.idempotency_key))
            if existing:
                return existing
            n = Notification(
                tenant_id=tenant_id, channel=body.channel, template=body.template,
                contact_id=body.contact_id, recipient_user_id=body.recipient_user_id,
                variables={**body.variables, "_security_team": body.security_team},
                scheduled_for=body.scheduled_for or datetime.now(UTC),
                idempotency_key=body.idempotency_key, related_type=body.related_type,
                related_id=body.related_id, requested_by=caller)
            if n.scheduled_for < datetime.now(UTC) - timedelta(minutes=5):
                n.status = "CANCELLED"
                n.last_error = "scheduled time already passed"
            s.add(n)
            await s.flush()
            return n.id

    async def cancel_related(self, tenant_id: uuid.UUID, body: CancelIn) -> int:
        async with self.db.tenant_session(tenant_id) as s:
            result = await s.execute(update(Notification).where(
                Notification.related_type == body.related_type,
                Notification.related_id == body.related_id,
                Notification.status == "SCHEDULED",
                Notification.scheduled_for > datetime.now(UTC)).values(status="CANCELLED"))
            return result.rowcount or 0

    # ---------------------------------------------------------------- delivery
    async def run_worker(self, poll: float, batch: int, stop: asyncio.Event) -> None:
        while not stop.is_set():
            try:
                claimed = await self.claim(batch)
                for tenant_id, nid in claimed:
                    await self.deliver(tenant_id, nid)
            except Exception:
                log.exception("notification worker iteration failed")
            try:
                await asyncio.wait_for(stop.wait(), timeout=poll)
            except TimeoutError:
                pass

    async def claim(self, batch: int) -> list[tuple[uuid.UUID, uuid.UUID]]:
        async with self.db.system_session() as s:
            rows = (await s.execute(text("SELECT * FROM app_claim_due_notifications(:n)"),
                                    {"n": batch})).all()
        return [(r[0], r[1]) for r in rows]

    async def deliver(self, tenant_id: uuid.UUID, nid: uuid.UUID) -> None:
        async with self.db.tenant_session(tenant_id, actor="notifications") as s:
            n = await s.get(Notification, nid)
            if n is None or n.status != "SENDING":
                return
            try:
                n.provider_message_id = await self._send(s, tenant_id, n)
                n.status = "SENT"
                n.sent_at = datetime.now(UTC)
                n.last_error = None
                instruments().notifications.add(1, {"channel": n.channel, "result": "sent"})
            except _Skip as skip:
                n.status = "CANCELLED"
                n.last_error = str(skip)
            except (PlatformError, OSError) as exc:
                n.last_error = type(exc).__name__
                if n.attempts >= self.max_attempts:
                    n.status = "FAILED"
                    instruments().notifications.add(1, {"channel": n.channel, "result": "failed"})
                else:
                    n.status = "SCHEDULED"
                    n.scheduled_for = datetime.now(UTC) + timedelta(seconds=30 * 2 ** n.attempts)

    async def _send(self, s, tenant_id: uuid.UUID, n: Notification) -> str:  # noqa: ANN001
        tpl = TEMPLATES[n.template]
        system = Principal.system(tenant_id, "notifications")
        rid = f"notif-{n.id.hex}"
        variables = {k: v for k, v in n.variables.items() if not k.startswith("_")}
        if tpl.category == "security":
            values = build_variables(tpl, variables, name=None, recipient_tz=None)
            subject = render_text(tpl.email_subject, values)
            body = render_text(tpl.email_body, values)
            if n.channel == "slack":
                if not self.slack_url:
                    raise _Skip("slack not configured")
                await post_slack(self.slack_url, f"*{subject}*\n{body}")
                return "slack"
            recipients = await self._security_recipients(s, tenant_id, n)
            if not recipients:
                raise _Skip("no security recipients")
            ids = [await self.email.send(r, subject, body, render_email_html(body))
                   for r in recipients]
            return ",".join(ids)[:500]
        contact = await self.crm.get(f"/internal/contacts/{n.contact_id}/delivery",
                                     principal=system, request_id=rid)
        values = build_variables(tpl, variables, name=contact.get("full_name"),
                                 recipient_tz=contact.get("timezone"))
        consent = contact.get("consent") or {}
        if n.channel == "email":
            if not contact.get("email"):
                raise _Skip("contact has no email")
            if consent.get("email") is False:
                raise _Skip("no email consent")
            body = render_text(tpl.email_body, values)
            return await self.email.send(contact["email"], render_text(tpl.email_subject, values),
                                         body, render_email_html(body))
        if n.channel == "whatsapp":
            if not consent.get("whatsapp"):
                raise _Skip("no whatsapp consent")
            if not contact.get("phone") or self.whatsapp is None:
                raise _Skip("contact has no whatsapp number")
            return await self.whatsapp.send(
                system, rid, phone=contact["phone"],
                text=render_text(tpl.whatsapp_text, values) if tpl.whatsapp_text else None,
                template=tpl.whatsapp_template,
                params=[values.get(p, "") for p in tpl.whatsapp_params],
                idempotency_key=f"notif:{n.id}")
        raise _Skip("unsupported channel")

    async def _security_recipients(self, s, tenant_id: uuid.UUID, n: Notification  # noqa: ANN001
                                   ) -> list[str]:
        stmt = select(User).where(User.status == "active", User.deleted_at.is_(None))
        if n.recipient_user_id:
            stmt = stmt.where(User.id == n.recipient_user_id)
        else:
            stmt = stmt.join(UserRole, UserRole.user_id == User.id).join(
                RoleRow, RoleRow.id == UserRole.role_id).where(
                RoleRow.name.in_(["security_engineer", "security_analyst"]))
        users = (await s.scalars(stmt)).unique().all()
        return [e for u in users if (e := self.enc.decrypt(u.email_ciphertext, tenant_id))]


class _Skip(Exception):
    pass
