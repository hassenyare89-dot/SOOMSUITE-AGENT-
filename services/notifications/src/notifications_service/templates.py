"""Approved message templates. Customer templates are legal-approved copy; variables are
escaped and length-bounded, and callers may only use templates in their category."""

from __future__ import annotations

import html
from dataclasses import dataclass, field
from datetime import datetime
from string import Template
from typing import Literal
from zoneinfo import ZoneInfo

from platform_core.errors import Forbidden, ValidationFailed

Category = Literal["customer", "security"]


@dataclass(frozen=True)
class MessageTemplate:
    name: str
    category: Category
    email_subject: str
    email_body: str
    whatsapp_text: str | None = None
    # Name of the Meta-approved template used outside the 24h customer-service window.
    whatsapp_template: str | None = None
    whatsapp_params: tuple[str, ...] = ()
    required: tuple[str, ...] = field(default_factory=tuple)


TEMPLATES: dict[str, MessageTemplate] = {t.name: t for t in [
    MessageTemplate(
        "customer.appointment_confirmation", "customer",
        "Your $appointment_type is confirmed",
        "Hello $name,\n\nYour $appointment_type is confirmed for $when.\n\n"
        "If you need to reschedule or cancel, reply to this message or chat with us on our "
        "website.\n\nThank you.",
        whatsapp_text="Your $appointment_type is confirmed for $when. Reply here if you need to "
                      "reschedule or cancel.",
        whatsapp_template="appointment_confirmation", whatsapp_params=("appointment_type", "when"),
        required=("appointment_type", "starts_at", "timezone")),
    MessageTemplate(
        "customer.appointment_reminder", "customer",
        "Reminder: your $appointment_type",
        "Hello $name,\n\nThis is a reminder of your $appointment_type on $when.\n\nThank you.",
        whatsapp_text="Reminder: your $appointment_type is on $when.",
        whatsapp_template="appointment_reminder", whatsapp_params=("appointment_type", "when"),
        required=("appointment_type", "starts_at", "timezone")),
    MessageTemplate(
        "customer.appointment_rescheduled", "customer",
        "Your $appointment_type has been rescheduled",
        "Hello $name,\n\nYour $appointment_type has been moved to $when.\n\nThank you.",
        whatsapp_text="Your $appointment_type has been moved to $when.",
        whatsapp_template="appointment_rescheduled", whatsapp_params=("appointment_type", "when"),
        required=("appointment_type", "starts_at", "timezone")),
    MessageTemplate(
        "customer.appointment_cancelled", "customer",
        "Your $appointment_type has been cancelled",
        "Hello $name,\n\nYour $appointment_type on $when has been cancelled. "
        "You are welcome to book a new time any time.\n\nThank you.",
        whatsapp_text="Your $appointment_type on $when has been cancelled.",
        whatsapp_template="appointment_cancelled", whatsapp_params=("appointment_type", "when"),
        required=("appointment_type", "starts_at", "timezone")),
    MessageTemplate(
        "customer.followup", "customer",
        "Following up on your enquiry",
        "Hello $name,\n\nThank you for contacting us. A member of our team will follow up "
        "about $topic shortly.\n\nThank you.",
        whatsapp_text="Thanks for contacting us. A team member will follow up about $topic shortly.",
        whatsapp_template="enquiry_followup", whatsapp_params=("topic",), required=("topic",)),
    MessageTemplate(
        "security.incident_alert", "security",
        "[$risk_level] $title",
        "FATMA SOC alert\n\nIncident: $title\nRisk: $risk_level ($risk_score/100)\n"
        "Status: $claim_status\nAsset: $asset\n\nOpen the SOC console to triage: $link\n\n"
        "This notification contains no raw evidence by design.",
        required=("title", "risk_level", "risk_score", "claim_status")),
    MessageTemplate(
        "security.approval_required", "security",
        "Approval required: $action_type",
        "A $risk_level action requires human approval.\n\nAction: $action_type\nReason: $reason\n"
        "Expires: $expires_at\n\nReview in the console: $link",
        required=("action_type", "risk_level", "reason")),
]}

CALLER_CATEGORIES: dict[str, frozenset[str]] = {
    "samiir-agent": frozenset({"customer"}),
    "scheduling": frozenset({"customer"}),
    "fatma-soc": frozenset({"security"}),
    "api-gateway-admin": frozenset({"customer", "security"}),
}


def template_for(name: str, caller: str) -> MessageTemplate:
    tpl = TEMPLATES.get(name)
    if tpl is None:
        raise ValidationFailed("unknown template")
    if tpl.category not in CALLER_CATEGORIES.get(caller, frozenset()):
        raise Forbidden("caller may not use this template category")
    return tpl


def _clean(value: object, limit: int = 300) -> str:
    text = str(value).replace("\r", " ").replace("\n", " ")
    return "".join(ch for ch in text if ch.isprintable())[:limit]


def build_variables(tpl: MessageTemplate, variables: dict, *, name: str | None,
                    recipient_tz: str | None) -> dict[str, str]:
    missing = [k for k in tpl.required if k not in variables]
    if missing:
        raise ValidationFailed("missing template variables", details={"missing": missing})
    out = {k: _clean(v) for k, v in variables.items()}
    out["name"] = _clean(name or "there", 80)
    if "starts_at" in variables:
        tz_name = recipient_tz or variables.get("timezone") or "UTC"
        try:
            tz = ZoneInfo(tz_name)
        except Exception:
            tz, tz_name = ZoneInfo("UTC"), "UTC"
        start = datetime.fromisoformat(str(variables["starts_at"])).astimezone(tz)
        out["when"] = f"{start:%A %d %B %Y at %H:%M} ({tz_name})"
    return out


def render_text(template: str, values: dict[str, str]) -> str:
    return Template(template).safe_substitute(values)


def render_email_html(body_text: str) -> str:
    escaped = html.escape(body_text).replace("\n", "<br>")
    return f"<!doctype html><html><body style=\"font-family:sans-serif\">{escaped}</body></html>"
