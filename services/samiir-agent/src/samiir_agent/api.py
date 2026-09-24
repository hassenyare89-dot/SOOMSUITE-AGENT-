from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime
from importlib import resources
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import func, select, text, update

from platform_core.app import RuntimeDep, ServiceRuntime, internal_caller
from platform_core.db.models import AgentRun, Conversation, Message, ToolCall
from platform_core.errors import Forbidden, NotFound, ValidationFailed
from platform_core.schemas.chat import ChatReply, InboundMessage
from platform_core.schemas.common import Page, StrictModel
from platform_core.schemas.enums import Channel, ConversationStatus, SenderType
from platform_core.security.policy import TOOL_REGISTRY
from platform_core.security.principal import AgentName
from platform_core.security.rbac import P
from platform_core.security.service_acl import GATEWAY_ADMIN, GATEWAY_PUBLIC, WHATSAPP
from platform_core.security.service_auth import RequestContext
from platform_core.security.untrusted import normalize_text
from samiir_agent.service import ChatService

router = APIRouter(prefix="/internal")
CustomerCtx = Annotated[RequestContext, Depends(internal_caller(GATEWAY_PUBLIC, WHATSAPP,
                                                                GATEWAY_ADMIN))]
PublicCtx = Annotated[RequestContext, Depends(internal_caller(GATEWAY_PUBLIC))]
WhatsAppCtx = Annotated[RequestContext, Depends(internal_caller(WHATSAPP))]
AdminCtx = Annotated[RequestContext, Depends(internal_caller(GATEWAY_ADMIN))]


def _chat(rt: ServiceRuntime) -> ChatService:
    return rt.extras["chat"]


def _bind_ref(ctx: RequestContext, ref: str) -> None:
    """A customer can only address the conversation bound to its own authenticated session."""
    if ctx.principal.is_customer and ctx.principal.session_id != ref:
        raise NotFound()


# ------------------------------------------------------------------------ customer
@router.post("/chat", response_model=ChatReply)
async def chat(body: InboundMessage, ctx: CustomerCtx, rt: RuntimeDep) -> ChatReply:
    rt.policy.require(ctx, P.SAMIIR_CHAT)
    _bind_ref(ctx, body.conversation_ref)
    if ctx.caller == WHATSAPP and body.channel is not Channel.WHATSAPP:
        raise ValidationFailed("channel mismatch")
    if ctx.caller == GATEWAY_PUBLIC and body.channel is not Channel.WEB:
        raise ValidationFailed("channel mismatch")
    return await _chat(rt).handle(ctx, body)


@router.get("/chat/history")
async def chat_history(ctx: CustomerCtx, rt: RuntimeDep, channel: Channel = Channel.WEB) -> dict:
    rt.policy.require(ctx, P.SAMIIR_CHAT)
    if not ctx.principal.session_id:
        raise NotFound()
    return await _chat(rt).history(ctx, channel, ctx.principal.session_id)


class ContactForm(StrictModel):
    full_name: str = Field(min_length=1, max_length=120)
    email: EmailStr
    phone: str | None = Field(default=None, pattern=r"^\+?[1-9]\d{6,14}$")
    company_name: str | None = Field(default=None, max_length=200)
    consent_contact: bool
    consent_whatsapp: bool = False


@router.post("/chat/contact", response_model=ChatReply)
async def chat_contact(body: ContactForm, ctx: PublicCtx, rt: RuntimeDep) -> ChatReply:
    rt.policy.require(ctx, P.CONTACT_SUBMIT)
    if not body.consent_contact:
        raise ValidationFailed("consent is required to save contact details")
    return await _chat(rt).submit_contact(ctx, ctx.principal.session_id or "", Channel.WEB, {
        "full_name": body.full_name, "email": body.email, "phone": body.phone,
        "company_name": body.company_name, "customer_agreed_to_share": True,
        "whatsapp_updates_opt_in": body.consent_whatsapp})


class EscalateBody(StrictModel):
    reason: str = Field("customer_requested", max_length=200)


@router.post("/chat/escalate")
async def chat_escalate(body: EscalateBody, ctx: PublicCtx, rt: RuntimeDep) -> dict:
    rt.policy.require(ctx, P.SAMIIR_CHAT)
    chat_svc = _chat(rt)
    ref_hash = chat_svc.ref_hash(ctx.tenant_id, Channel.WEB.value, ctx.principal.session_id or "")
    async with rt.require_db().tenant_session(ctx.tenant_id) as s:
        conv_id = await s.scalar(select(Conversation.id).where(
            Conversation.channel == "web", Conversation.external_ref_hash == ref_hash))
    if conv_id is None:
        raise NotFound()
    await chat_svc.escalate(ctx, conv_id, normalize_text(body.reason, max_len=200))
    return {"escalated": True}


@router.get("/widget/resolve")
async def widget_resolve(ctx: PublicCtx, rt: RuntimeDep,
                         key: Annotated[str, Query(pattern="^pk_[A-Za-z0-9_-]{16,64}$")]) -> dict:
    async with rt.require_db().system_session() as s:
        row = (await s.execute(text("SELECT * FROM app_resolve_widget(:k)"), {"k": key})).first()
    if row is None:
        raise NotFound()
    return {"tenant_id": row.tenant_id, "site_id": row.site_id, "tenant_name": row.tenant_name,
            "allowed_origins": list(row.allowed_origins), "greeting": row.greeting,
            "theme": row.theme}


class StatusUpdate(StrictModel):
    external_message_id: str = Field(max_length=200)
    status: str = Field(pattern="^(sent|delivered|read|failed)$")


@router.post("/messages/status")
async def message_status(body: StatusUpdate, ctx: WhatsAppCtx, rt: RuntimeDep) -> dict:
    rt.policy.require(ctx, P.INTERNAL_EXECUTE)
    async with rt.require_db().tenant_session(ctx.tenant_id) as s:
        res = await s.execute(update(Message).where(
            Message.external_message_id == body.external_message_id).values(
            delivery_status=body.status))
    return {"updated": res.rowcount or 0}


# --------------------------------------------------------------------------- admin
class ConversationOut(BaseModel):
    id: uuid.UUID
    channel: str
    status: str
    contact_id: uuid.UUID | None
    assigned_user_id: uuid.UUID | None
    summary: str | None
    escalation_reason: str | None
    last_message_at: datetime | None
    created_at: datetime


@router.get("/conversations", response_model=Page[ConversationOut])
async def list_conversations(ctx: AdminCtx, rt: RuntimeDep,
                             status: ConversationStatus | None = None,
                             channel: Channel | None = None,
                             limit: Annotated[int, Query(ge=1, le=200)] = 50,
                             offset: Annotated[int, Query(ge=0)] = 0) -> Page[ConversationOut]:
    rt.policy.require(ctx, P.CONVERSATION_READ)
    async with rt.require_db().tenant_session(ctx.tenant_id) as s:
        stmt = select(Conversation)
        if status:
            stmt = stmt.where(Conversation.status == status.value)
        if channel:
            stmt = stmt.where(Conversation.channel == channel.value)
        total = await s.scalar(select(func.count()).select_from(stmt.subquery()))
        rows = (await s.scalars(stmt.order_by(Conversation.last_message_at.desc().nulls_last())
                                .limit(limit).offset(offset))).all()
        return Page(items=[ConversationOut.model_validate(c, from_attributes=True) for c in rows],
                    total=int(total or 0), limit=limit, offset=offset)


@router.get("/conversations/{conversation_id}")
async def get_conversation(conversation_id: uuid.UUID, ctx: AdminCtx, rt: RuntimeDep) -> dict:
    rt.policy.require(ctx, P.CONVERSATION_READ)
    async with rt.require_db().tenant_session(ctx.tenant_id) as s:
        conv = await s.get(Conversation, conversation_id)
        if conv is None:
            raise NotFound()
        msgs = (await s.scalars(select(Message).where(Message.conversation_id == conv.id)
                                .order_by(Message.created_at))).all()
        return {
            "conversation": ConversationOut.model_validate(conv, from_attributes=True)
            .model_dump(mode="json"),
            "messages": [{"id": str(m.id), "direction": m.direction, "sender": m.sender_type,
                          "text": m.content, "cards": m.cards, "delivery_status": m.delivery_status,
                          "injection_score": float(m.injection_score)
                          if m.injection_score is not None else None,
                          "created_at": m.created_at.isoformat()} for m in msgs],
        }


class HumanReply(StrictModel):
    text: str = Field(min_length=1, max_length=4000)


@router.post("/conversations/{conversation_id}/reply")
async def human_reply(conversation_id: uuid.UUID, body: HumanReply, ctx: AdminCtx,
                      rt: RuntimeDep) -> dict:
    rt.policy.require(ctx, P.CONVERSATION_MANAGE)
    async with rt.require_db().tenant_session(ctx.tenant_id, actor=ctx.principal.subject) as s:
        conv = await s.get(Conversation, conversation_id)
        if conv is None:
            raise NotFound()
        if conv.status == ConversationStatus.CLOSED:
            raise ValidationFailed("conversation is closed")
        m = Message(tenant_id=ctx.tenant_id, conversation_id=conv.id, direction="outbound",
                    sender_type=SenderType.HUMAN_AGENT.value, sender_id=ctx.principal.subject,
                    content=normalize_text(body.text, max_len=4000))
        conv.status = ConversationStatus.HUMAN_HANDLING.value
        conv.assigned_user_id = conv.assigned_user_id or uuid.UUID(ctx.principal.subject)
        conv.last_message_at = datetime.now(UTC)
        s.add(m)
        await s.flush()
        channel, wa_enc, last_inbound = conv.channel, conv.context.get("_wa_phone_enc"), \
            conv.last_inbound_at
        message_id = m.id
    if channel == Channel.WHATSAPP.value and wa_enc:
        from platform_core.security.principal import Principal

        phone = _chat(rt).enc.decrypt(wa_enc, ctx.tenant_id)
        within_window = last_inbound and (datetime.now(UTC) - last_inbound).total_seconds() < 86400
        if not within_window:
            raise ValidationFailed("outside the 24h WhatsApp service window; use a template")
        resp = await rt.client("whatsapp").post(
            "/internal/send", principal=Principal.system(ctx.tenant_id, "samiir-agent"),
            request_id=ctx.request_id, json={"to": phone, "text": body.text, "template": None,
                                             "template_params": [],
                                             "idempotency_key": f"human:{message_id}"})
        async with rt.require_db().tenant_session(ctx.tenant_id) as s:
            msg = await s.get(Message, message_id)
            if msg:
                msg.external_message_id = resp["message_id"]
    await rt.audit.record(ctx, action="conversation.human_reply", result="success",
                          target_type="conversation", target_id=conversation_id)
    await rt.realtime.publish(ctx.tenant_id, "samiir", "message.outbound",
                              {"conversation_id": conversation_id})
    return {"message_id": message_id}


class StatusChange(StrictModel):
    status: ConversationStatus


@router.post("/conversations/{conversation_id}/status")
async def change_status(conversation_id: uuid.UUID, body: StatusChange, ctx: AdminCtx,
                        rt: RuntimeDep) -> dict:
    rt.policy.require(ctx, P.CONVERSATION_MANAGE)
    async with rt.require_db().tenant_session(ctx.tenant_id, actor=ctx.principal.subject) as s:
        conv = await s.get(Conversation, conversation_id)
        if conv is None:
            raise NotFound()
        conv.status = body.status.value
        if body.status is ConversationStatus.HUMAN_HANDLING:
            conv.assigned_user_id = uuid.UUID(ctx.principal.subject)
        if body.status is ConversationStatus.OPEN:
            conv.assigned_user_id = None
    await rt.audit.record(ctx, action="conversation.status", result="success",
                          target_type="conversation", target_id=conversation_id,
                          metadata={"status": body.status.value})
    return {"status": body.status.value}


@router.post("/conversations/{conversation_id}/summarize")
async def summarize(conversation_id: uuid.UUID, ctx: AdminCtx, rt: RuntimeDep) -> dict:
    """Extractive summary (no model call): who, what was asked, outcomes."""
    rt.policy.require(ctx, P.CONVERSATION_READ)
    async with rt.require_db().tenant_session(ctx.tenant_id, actor=ctx.principal.subject) as s:
        conv = await s.get(Conversation, conversation_id)
        if conv is None:
            raise NotFound()
        msgs = (await s.scalars(select(Message).where(Message.conversation_id == conv.id)
                                .order_by(Message.created_at))).all()
        customer = [m.content for m in msgs if m.sender_type == SenderType.CUSTOMER]
        outcomes = [c["type"] for m in msgs for c in (m.cards or [])
                    if c.get("type") in ("appointment", "escalation")]
        summary = (f"{len(customer)} customer messages via {conv.channel}. "
                   f"First request: {customer[0][:200] if customer else 'n/a'}. "
                   f"Latest: {customer[-1][:200] if customer else 'n/a'}. "
                   f"Outcomes: {', '.join(outcomes) or 'none'}. Status: {conv.status}.")
        conv.summary = summary
    return {"summary": summary}


@router.get("/agent-runs")
async def agent_runs(ctx: AdminCtx, rt: RuntimeDep,
                     limit: Annotated[int, Query(ge=1, le=200)] = 50) -> list[dict]:
    rt.policy.require_any(ctx, {P.AGENT_CONFIG_MANAGE, P.CONVERSATION_READ})
    async with rt.require_db().tenant_session(ctx.tenant_id) as s:
        runs = (await s.scalars(select(AgentRun).order_by(AgentRun.started_at.desc())
                                .limit(limit))).all()
        denied = await s.scalar(select(func.count()).select_from(ToolCall).where(
            ToolCall.decision == "DENIED"))
        return [{"id": r.id, "status": r.status, "runtime": r.runtime, "model": r.model,
                 "latency_ms": r.latency_ms, "input_tokens": r.input_tokens,
                 "output_tokens": r.output_tokens, "guardrail_flags": r.guardrail_flags,
                 "conversation_id": r.conversation_id, "started_at": r.started_at,
                 "denied_tool_calls_total": denied} for r in runs]


@router.get("/agent/config")
async def agent_config(ctx: AdminCtx, rt: RuntimeDep) -> dict:
    rt.policy.require_any(ctx, {P.AGENT_CONFIG_MANAGE, P.CONVERSATION_READ})
    prompt = resources.files("samiir_agent").joinpath("prompts/samiir_system.md").read_text()
    chat_svc = _chat(rt)
    return {"agent": "SAMIIR", "runtime": chat_svc.runtime.name,
            "model": getattr(chat_svc.runtime, "model", None),
            "tools": [{"name": r.name, "risk": r.risk.value, "permissions": sorted(r.any_of),
                       "requires_approval": r.requires_approval}
                      for r in TOOL_REGISTRY[AgentName.SAMIIR].values()],
            "system_prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
            "system_prompt": prompt, "service_identity": rt.identity.name}


def _require_not_customer(ctx: RequestContext) -> None:
    if ctx.principal.is_customer:
        raise Forbidden()
