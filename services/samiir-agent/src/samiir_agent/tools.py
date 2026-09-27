"""SAMIIR's typed tools and the gateway every tool call must pass through.

Security properties enforced here (outside the model):
* Only tools in ``TOOL_REGISTRY[SAMIIR]`` exist; the executing identity is bound to SAMIIR.
* The policy engine authorizes each call against the *customer's* principal and the caller
  ceiling — the model's wishes are irrelevant.
* Arguments are validated against strict Pydantic schemas before execution.
* Every call is persisted (``tool_calls``), measured and, when state-changing, audited.
* Tool outputs derived from retrieved content are fenced as untrusted data.
* Slot tokens never reach the model: it can only reference slot *numbers* it was shown.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field, ValidationError

from platform_core.app import ServiceRuntime
from platform_core.db.models import ToolCall
from platform_core.errors import Conflict, NotFound, PlatformError, ValidationFailed
from platform_core.observability import instruments, tracer
from platform_core.schemas.chat import Card
from platform_core.schemas.enums import KnowledgeCategory
from platform_core.security.crypto import canonical_json, sha256_hex
from platform_core.security.principal import AgentName, Principal
from platform_core.security.redaction import redact
from platform_core.security.service_acl import SAMIIR_AGENT
from platform_core.security.service_auth import RequestContext
from platform_core.security.untrusted import fence

log = logging.getLogger(__name__)
AGENT = AgentName.SAMIIR


# ------------------------------------------------------------------------ run state
@dataclass
class RunState:
    """Per-run context shared by tools. Never serialized to the model."""

    ctx: RequestContext
    conversation_id: uuid.UUID
    agent_run_id: uuid.UUID
    channel: str
    context: dict[str, Any]           # persisted conversation context (contact, slots, ...)
    customer_timezone: str
    grounding: list[str] = field(default_factory=list)   # text the answer may rely on
    cards: list[Card] = field(default_factory=list)
    escalated: bool = False
    escalation_reason: str | None = None
    tools_used: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)

    @property
    def contact_id(self) -> uuid.UUID | None:
        v = self.context.get("contact_id")
        return uuid.UUID(v) if v else None

    @property
    def opportunity_id(self) -> uuid.UUID | None:
        v = self.context.get("opportunity_id")
        return uuid.UUID(v) if v else None

    def system_principal(self) -> Principal:
        return Principal.system(self.ctx.tenant_id, SAMIIR_AGENT)


# ------------------------------------------------------------------ argument schemas
class _Args(BaseModel):
    # Strict-mode friendly: every field is required (nullable where optional).
    model_config = ConfigDict(extra="forbid")


class KnowledgeSearchArgs(_Args):
    query: str = Field(min_length=2, max_length=300, description="What to look up")
    category: KnowledgeCategory | None = Field(description="Optional category filter")


class PricingArgs(_Args):
    service: str | None = Field(max_length=120, description="Service name, or null for all")


class CaptureContactArgs(_Args):
    full_name: str | None = Field(max_length=120)
    email: EmailStr | None
    phone: str | None = Field(pattern=r"^\+?[1-9]\d{6,14}$")
    company_name: str | None = Field(max_length=200)
    customer_agreed_to_share: bool = Field(
        description="True only if the customer explicitly agreed to share these details")
    whatsapp_updates_opt_in: bool = Field(
        description="True only if the customer asked for WhatsApp updates")


class QualifyLeadArgs(_Args):
    service_interest: str = Field(max_length=200)
    company_size: str | None = Field(max_length=40)
    budget_range: str | None = Field(max_length=60)
    timeline: str | None = Field(max_length=60)
    needs_summary: str = Field(max_length=800)


class AvailabilityArgs(_Args):
    appointment_type: str | None = Field(pattern="^[a-z0-9_-]{2,64}$",
                                         description="Appointment type code, or null for default")
    earliest_date: str | None = Field(pattern=r"^\d{4}-\d{2}-\d{2}$",
                                      description="YYYY-MM-DD, or null for as soon as possible")


class BookArgs(_Args):
    slot_number: int = Field(ge=1, le=5, description="Number of an offered slot")


class RescheduleArgs(_Args):
    slot_number: int = Field(ge=1, le=5, description="Number of a newly offered slot")


class CancelArgs(_Args):
    reason: str = Field(max_length=200)


class EscalateArgs(_Args):
    reason: str = Field(max_length=300)


@dataclass(frozen=True)
class ToolSpec:
    name: str                  # registry name, e.g. "calendar.book_appointment"
    description: str
    args: type[_Args]
    handler: Callable[[ServiceRuntime, RunState, Any], Awaitable[str]]
    audited: bool = False

    @property
    def model_name(self) -> str:  # OpenAI tool names cannot contain dots
        return self.name.replace(".", "_")


class ToolDenied(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# -------------------------------------------------------------------------- gateway
class ToolGateway:
    def __init__(self, rt: ServiceRuntime, specs: dict[str, ToolSpec]) -> None:
        self.rt = rt
        self.specs = specs
        self.by_model_name = {s.model_name: s for s in specs.values()}

    async def invoke(self, state: RunState, name: str, raw_args: dict[str, Any] | str) -> str:
        spec = self.specs.get(name) or self.by_model_name.get(name)
        tool_name = spec.name if spec else name
        args_dict: dict[str, Any]
        try:
            args_dict = json.loads(raw_args) if isinstance(raw_args, str) else dict(raw_args)
        except (ValueError, TypeError):
            args_dict = {}
        args_hash = sha256_hex(canonical_json(args_dict))
        decision = self.rt.policy.authorize_tool(state.ctx, SAMIIR_AGENT, AGENT, tool_name)
        if spec is None or not decision.allowed:
            reason = decision.reason if spec is not None else "tool_not_registered_for_agent"
            instruments().tool_denials.add(1, {"agent": AGENT.value, "tool": tool_name[:64]})
            await self._persist(state, tool_name, args_dict, args_hash, "DENIED", reason, "denied",
                                None, None)
            await self.rt.audit.record(state.ctx, action="agent.tool.denied", result="denied",
                                       agent_name=AGENT.value, tool_name=tool_name[:64],
                                       risk_level="HIGH", metadata={"reason": reason})
            state.flags.append(f"tool_denied:{tool_name[:64]}")
            return "ERROR: this action is not available."
        try:
            args = spec.args.model_validate(args_dict)
        except ValidationError as exc:
            await self._persist(state, tool_name, args_dict, args_hash, "ALLOWED", "allowlisted",
                                "invalid_arguments", None, "validation")
            fields = ", ".join(".".join(map(str, e["loc"])) for e in exc.errors()[:5])
            return f"ERROR: invalid arguments ({fields}). Ask the customer for valid details."
        start = time.perf_counter()
        status, error, result = "ok", None, ""
        with tracer().start_as_current_span(f"tool {tool_name}") as span:
            span.set_attribute("agent.name", AGENT.value)
            span.set_attribute("tool.name", tool_name)
            try:
                result = await spec.handler(self.rt, state, args)
            except (NotFound, Conflict, ValidationFailed) as exc:
                status, error = "rejected", exc.code
                result = f"ERROR: {exc.message}"
            except PlatformError as exc:
                status, error = "failed", exc.code
                result = "ERROR: the system is temporarily unavailable. Offer to escalate."
                instruments().tool_failures.add(1, {"agent": AGENT.value, "tool": tool_name})
        latency = int((time.perf_counter() - start) * 1000)
        instruments().tool_calls.add(1, {"agent": AGENT.value, "tool": tool_name, "status": status})
        instruments().tool_latency.record(latency, {"agent": AGENT.value, "tool": tool_name})
        state.tools_used.append(tool_name)
        await self._persist(state, tool_name, args_dict, args_hash, "ALLOWED", "allowlisted",
                            status, latency, error)
        if spec.audited:
            await self.rt.audit.record(
                state.ctx, action=f"agent.tool.{tool_name}", agent_name=AGENT.value,
                tool_name=tool_name, result="success" if status == "ok" else "failure",
                target_type="conversation", target_id=state.conversation_id,
                risk_level=decision.risk.value, metadata={"status": status, "error": error})
        return result

    async def _persist(self, state: RunState, tool: str, args: dict, args_hash: str,
                       decision: str, reason: str, status: str, latency: int | None,
                       error: str | None) -> None:
        try:
            async with self.rt.require_db().tenant_session(state.ctx.tenant_id,
                                                           actor="agent:SAMIIR") as s:
                s.add(ToolCall(tenant_id=state.ctx.tenant_id, agent_run_id=state.agent_run_id,
                               agent_name=AGENT.value, tool_name=tool[:128],
                               arguments_redacted=redact(args, mask_pii=True),
                               arguments_hash=args_hash, decision=decision,
                               decision_reason=reason, status=status, latency_ms=latency,
                               error=error))
        except Exception:
            log.exception("failed to persist tool call")


# -------------------------------------------------------------------------- handlers
def _client_kwargs(state: RunState, principal: Principal | None = None) -> dict[str, Any]:
    return {"principal": principal or state.ctx.principal, "request_id": state.ctx.request_id,
            "agent_run_id": state.agent_run_id}


async def knowledge_search(rt: ServiceRuntime, state: RunState, a: KnowledgeSearchArgs) -> str:
    resp = await rt.client("knowledge").post("/internal/search", json={
        "query": a.query, "categories": [a.category.value] if a.category else None, "limit": 4},
        **_client_kwargs(state))
    if not resp["sufficient"]:
        return ("NO_APPROVED_INFORMATION: nothing in the approved knowledge base answers this. "
                "Tell the customer you need to check with the team and offer to escalate.")
    parts = []
    for r in resp["results"]:
        state.grounding.append(r["content"])
        parts.append(fence(f"[{r['title']} v{r['version']}]\n{r['content']}", label="document"))
    state.cards.append(Card(type="sources", data={"sources": [
        {"title": r["title"], "version": r["version"]} for r in resp["results"]]}))
    return "\n\n".join(parts)


async def pricing_lookup(rt: ServiceRuntime, state: RunState, a: PricingArgs) -> str:
    params = {"service": a.service} if a.service else None
    answers = await rt.client("knowledge").get("/internal/pricing", params=params,
                                               **_client_kwargs(state))
    if not answers:
        return ("NO_APPROVED_PRICING: there is no approved price for this. Do not estimate; "
                "offer to have the sales team follow up.")
    lines, items_out = [], []
    for ans in answers:
        for it in ans["items"]:
            if it.get("price") is not None:
                price = f"{ans['currency']} {it['price']}"
            elif it.get("price_from") is not None:
                upper = f"–{it['price_to']}" if it.get("price_to") is not None else "+"
                price = f"from {ans['currency']} {it['price_from']}{upper}"
            else:
                price = "price on request"
            line = f"- {it['service']}: {price} ({it['unit']}). {it.get('notes', '')}".strip()
            lines.append(line)
            items_out.append({"service": it["service"], "price": price, "unit": it["unit"]})
            state.grounding.append(line)
    state.cards.append(Card(type="pricing", data={"items": items_out}))
    return "APPROVED_PRICING (quote exactly, do not round or discount):\n" + "\n".join(lines)


async def capture_contact(rt: ServiceRuntime, state: RunState, a: CaptureContactArgs) -> str:
    if not a.customer_agreed_to_share:
        return "NOT_SAVED: ask the customer whether they agree to share their contact details."
    body = {
        "full_name": a.full_name, "email": a.email, "phone": a.phone,
        "company_name": a.company_name, "preferred_channel": state.channel
        if state.channel in ("web", "whatsapp") else None,
        "timezone": state.customer_timezone,
        "consent": {"contact_processing": True, "email": True,
                    "whatsapp": a.whatsapp_updates_opt_in or state.channel == "whatsapp",
                    "marketing": False},
        "source": state.channel if state.channel in ("web", "whatsapp") else "web",
        "conversation_id": str(state.conversation_id),
        "whatsapp_ref_hash": state.context.get("whatsapp_ref_hash"),
    }
    if state.channel == "whatsapp" and not a.phone and state.context.get("_wa_phone"):
        body["phone"] = state.context["_wa_phone"]
    ref = await rt.client("crm").post("/internal/samiir/contacts", json=body,
                                      **_client_kwargs(state))
    state.context["contact_id"] = ref["contact_id"]
    state.context["opportunity_id"] = ref["opportunity_id"]
    return "SAVED: the customer's contact details were recorded."


async def qualify_lead(rt: ServiceRuntime, state: RunState, a: QualifyLeadArgs) -> str:
    if state.contact_id is None:
        state.cards.append(Card(type="contact_form", data={"reason": "qualification"}))
        return "NEED_CONTACT: ask the customer for their name and email first."
    resp = await rt.client("crm").post("/internal/samiir/qualify", json={
        "contact_id": str(state.contact_id), **a.model_dump(),
        "conversation_id": str(state.conversation_id)}, **_client_kwargs(state))
    state.context["opportunity_id"] = resp["opportunity_id"]
    if resp["missing"]:
        return f"PARTIAL: still missing {', '.join(resp['missing'])}."
    return "QUALIFIED: lead details recorded."


async def check_availability(rt: ServiceRuntime, state: RunState, a: AvailabilityArgs) -> str:
    atype = a.appointment_type or state.context.get("default_appointment_type", "consultation")
    body: dict[str, Any] = {"appointment_type": atype, "timezone": state.customer_timezone,
                            "max_slots": 5, "days": 14,
                            "conversation_id": str(state.conversation_id)}
    if a.earliest_date:
        body["earliest"] = f"{a.earliest_date}T00:00:00+00:00"
    resp = await rt.client("scheduling").post("/internal/availability", json=body,
                                              **_client_kwargs(state))
    if not resp["slots"]:
        return "NO_AVAILABILITY: no free times in the next two weeks. Offer to escalate."
    offered = [{"n": i + 1, "token": s["slot_token"], "display": s["display"],
                "starts_at": s["starts_at"]} for i, s in enumerate(resp["slots"])]
    state.context["offered_slots"] = offered
    state.context["appointment_type"] = resp["appointment_type"]
    state.cards.append(Card(type="slots", data={
        "appointment_type": resp["appointment_name"], "timezone": resp["timezone"],
        "slots": [{"n": o["n"], "display": o["display"], "slot_token": o["token"]}
                  for o in offered]}))
    lines = [f"{o['n']}. {o['display']}" for o in offered]
    state.grounding.extend(lines)
    return (f"AVAILABLE_SLOTS for {resp['appointment_name']} (offer these exactly, by number):\n"
            + "\n".join(lines))


def _slot(state: RunState, n: int) -> dict[str, Any]:
    for o in state.context.get("offered_slots", []):
        if o["n"] == n:
            return o
    raise ValidationFailed("that slot number was not offered; check availability first")


async def book_by_token(rt: ServiceRuntime, state: RunState, token: str, display: str) -> str:
    if state.contact_id is None:
        state.context["pending_slot_token"] = token
        state.cards.append(Card(type="contact_form", data={"reason": "booking"}))
        return "NEED_CONTACT: ask for the customer's name and email to confirm the booking."
    idem = hashlib.sha256(f"{state.conversation_id}:{token}".encode()).hexdigest()[:48]
    appt = await rt.client("scheduling").post("/internal/appointments", json={
        "slot_token": token, "contact_id": str(state.contact_id),
        "opportunity_id": str(state.opportunity_id) if state.opportunity_id else None,
        "conversation_id": str(state.conversation_id), "idempotency_key": idem},
        **_client_kwargs(state))
    state.context.setdefault("appointment_ids", []).append(appt["id"])
    state.context.pop("offered_slots", None)
    state.context.pop("pending_slot_token", None)
    state.cards.append(Card(type="appointment", data={"status": "BOOKED", "display": display,
                                                      "appointment_id": appt["id"]}))
    state.grounding.append(display)
    return f"BOOKED: appointment confirmed for {display}. A confirmation will be sent."


async def book_appointment(rt: ServiceRuntime, state: RunState, a: BookArgs) -> str:
    slot = _slot(state, a.slot_number)
    return await book_by_token(rt, state, slot["token"], slot["display"])


def _latest_appointment(state: RunState) -> str:
    ids = state.context.get("appointment_ids") or []
    if not ids:
        raise NotFound("there is no appointment booked in this conversation")
    return ids[-1]


async def reschedule_appointment(rt: ServiceRuntime, state: RunState, a: RescheduleArgs) -> str:
    appt_id = _latest_appointment(state)
    slot = _slot(state, a.slot_number)
    idem = hashlib.sha256(f"resched:{appt_id}:{slot['token']}".encode()).hexdigest()[:48]
    new = await rt.client("scheduling").post(
        f"/internal/appointments/{appt_id}/reschedule",
        json={"slot_token": slot["token"], "idempotency_key": idem,
              "conversation_id": str(state.conversation_id)}, **_client_kwargs(state))
    state.context["appointment_ids"] = [*state.context["appointment_ids"], new["id"]]
    state.context.pop("offered_slots", None)
    state.cards.append(Card(type="appointment", data={"status": "RESCHEDULED",
                                                      "display": slot["display"]}))
    state.grounding.append(slot["display"])
    return f"RESCHEDULED: the appointment is now {slot['display']}."


async def cancel_appointment(rt: ServiceRuntime, state: RunState, a: CancelArgs) -> str:
    appt_id = _latest_appointment(state)
    await rt.client("scheduling").post(
        f"/internal/appointments/{appt_id}/cancel",
        json={"reason": a.reason, "conversation_id": str(state.conversation_id)},
        **_client_kwargs(state))
    state.cards.append(Card(type="appointment", data={"status": "CANCELLED"}))
    return "CANCELLED: the appointment was cancelled."


async def escalate_to_human(rt: ServiceRuntime, state: RunState, a: EscalateArgs) -> str:
    state.escalated = True
    state.escalation_reason = a.reason
    state.cards.append(Card(type="escalation", data={"status": "requested"}))
    return "ESCALATED: a human team member has been notified and will join the conversation."


SAMIIR_TOOLS: dict[str, ToolSpec] = {s.name: s for s in [
    ToolSpec("knowledge.search", "Search the company's approved knowledge base "
             "(services, FAQs, policies, onboarding, scope).", KnowledgeSearchArgs,
             knowledge_search),
    ToolSpec("pricing.lookup", "Get approved, structured prices. The only source of prices.",
             PricingArgs, pricing_lookup),
    ToolSpec("crm.capture_contact", "Save contact details the customer agreed to share.",
             CaptureContactArgs, capture_contact, audited=True),
    ToolSpec("crm.qualify_lead", "Record the customer's needs for the sales team.",
             QualifyLeadArgs, qualify_lead, audited=True),
    ToolSpec("calendar.check_availability", "Get real, numbered appointment slots.",
             AvailabilityArgs, check_availability),
    ToolSpec("calendar.book_appointment", "Book one of the numbered slots offered.",
             BookArgs, book_appointment, audited=True),
    ToolSpec("calendar.reschedule_appointment", "Move this conversation's appointment to a "
             "newly offered slot number.", RescheduleArgs, reschedule_appointment, audited=True),
    ToolSpec("calendar.cancel_appointment", "Cancel this conversation's appointment.",
             CancelArgs, cancel_appointment, audited=True),
    ToolSpec("conversation.escalate_to_human", "Hand the conversation to a human agent.",
             EscalateArgs, escalate_to_human, audited=True),
]}

# Import-time proof that SAMIIR's tool set equals its registry entry (and nothing more).
from platform_core.security.policy import TOOL_REGISTRY  # noqa: E402

if set(SAMIIR_TOOLS) != set(TOOL_REGISTRY[AGENT]):
    raise RuntimeError("SAMIIR tool implementations diverge from the policy registry")
