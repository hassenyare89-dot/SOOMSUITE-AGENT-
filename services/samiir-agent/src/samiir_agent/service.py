"""Conversation orchestration for SAMIIR."""

from __future__ import annotations

import logging
import time
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select

from platform_core.app import ServiceRuntime
from platform_core.db.models import AgentRun, Conversation, Message, Tenant
from platform_core.errors import Conflict, RateLimited
from platform_core.observability import current_trace_id, instruments, tracer
from platform_core.schemas.chat import Card, ChatReply, InboundMessage
from platform_core.schemas.enums import Channel, ConversationStatus, SenderType
from platform_core.security.crypto import FieldEncryptor
from platform_core.security.ratelimit import InMemoryRateLimiter, Limit, RateLimiter
from platform_core.security.redaction import redact_text
from platform_core.security.service_auth import RequestContext
from platform_core.security.untrusted import normalize_text
from samiir_agent.guardrails import SAFE_FALLBACK, SECURITY_REDIRECT, assess_input, check_grounding
from samiir_agent.runtime import AgentResult, AgentRuntime
from samiir_agent.tools import RunState, ToolGateway

log = logging.getLogger(__name__)

HUMAN_HANDLING_REPLY = ("Thanks — a member of our team is handling this conversation and will "
                        "reply here shortly.")


class ChatService:
    def __init__(self, rt: ServiceRuntime, runtime: AgentRuntime, gateway: ToolGateway,
                 enc: FieldEncryptor, *, history_messages: int = 12,
                 default_appointment_type: str = "consultation",
                 limiter: RateLimiter | None = None, per_minute: int = 12) -> None:
        self.rt = rt
        self.runtime = runtime
        self.gateway = gateway
        self.enc = enc
        self.history_messages = history_messages
        self.default_appointment_type = default_appointment_type
        self.limiter = limiter or InMemoryRateLimiter()
        self.per_minute = per_minute

    def ref_hash(self, tenant_id: uuid.UUID, channel: str, ref: str) -> str:
        return self.enc.blind_index(f"{channel}:{ref}", tenant_id, "conversation") or ""

    async def _conversation(self, s, tenant_id: uuid.UUID, msg: InboundMessage  # noqa: ANN001
                            ) -> Conversation:
        ref_hash = self.ref_hash(tenant_id, msg.channel.value, msg.conversation_ref)
        conv = await s.scalar(select(Conversation).where(
            Conversation.channel == msg.channel.value,
            Conversation.external_ref_hash == ref_hash).with_for_update())
        if conv is None:
            context: dict[str, Any] = {"default_appointment_type": self.default_appointment_type}
            if msg.channel is Channel.WHATSAPP:
                context["whatsapp_ref_hash"] = self.enc.blind_index(
                    msg.conversation_ref, tenant_id, "whatsapp")
                context["_wa_phone_enc"] = self.enc.encrypt("+" + msg.conversation_ref.lstrip("+"),
                                                            tenant_id)
            conv = Conversation(tenant_id=tenant_id, channel=msg.channel.value,
                                external_ref_hash=ref_hash, status=ConversationStatus.OPEN.value,
                                context=context)
            s.add(conv)
            await s.flush()
        return conv

    async def handle(self, ctx: RequestContext, msg: InboundMessage) -> ChatReply:
        tenant_id = ctx.tenant_id
        allowed, retry = await self.limiter.hit(
            f"samiir:conv:{tenant_id}:{self.ref_hash(tenant_id, msg.channel.value, msg.conversation_ref)}",
            Limit(self.per_minute, 60))
        if not allowed:
            raise RateLimited(retry)
        text = normalize_text(msg.text, max_len=4000)
        assessment = assess_input(text)
        db = self.rt.require_db()

        # 1) Persist inbound message (idempotent on the channel's message id).
        async with db.tenant_session(tenant_id, actor="agent:SAMIIR") as s:
            conv = await self._conversation(s, tenant_id, msg)
            if msg.external_message_id:
                dup = await s.scalar(select(Message).where(
                    Message.external_message_id == msg.external_message_id))
                if dup is not None:
                    raise Conflict("duplicate message")
            now = datetime.now(UTC)
            s.add(Message(tenant_id=tenant_id, conversation_id=conv.id, direction="inbound",
                          sender_type=SenderType.CUSTOMER.value, sender_id=None,
                          content=text, external_message_id=msg.external_message_id,
                          injection_score=assessment.injection_score,
                          metadata_={"signals": list(assessment.signals)}))
            conv.last_message_at = conv.last_inbound_at = now
            conversation_id, status = conv.id, conv.status
            context = dict(conv.context or {})
            history_rows = (await s.scalars(
                select(Message).where(Message.conversation_id == conv.id)
                .order_by(Message.created_at.desc()).limit(self.history_messages + 1))).all()
            tenant = await s.get(Tenant, tenant_id)
            company = tenant.name if tenant else "our company"
        await self.rt.realtime.publish(tenant_id, "samiir", "message.inbound",
                                       {"conversation_id": conversation_id})

        if status in (ConversationStatus.HUMAN_HANDLING, ConversationStatus.ESCALATED):
            return await self._store_reply(ctx, conversation_id, context, HUMAN_HANDLING_REPLY,
                                           [], escalated=True, handled_by="human")

        if context.get("_wa_phone_enc"):
            context["_wa_phone"] = self.enc.decrypt(context["_wa_phone_enc"], tenant_id)
        history = [{"role": "user" if m.sender_type == SenderType.CUSTOMER else "assistant",
                    "content": m.content} for m in reversed(history_rows[1:])]

        run_id = uuid.uuid4()
        run_ctx = RequestContext(caller=ctx.caller, receiver=ctx.receiver,
                                 principal=ctx.principal, request_id=ctx.request_id,
                                 source_ip=ctx.source_ip, agent_run_id=run_id)
        state = RunState(ctx=run_ctx, conversation_id=conversation_id, agent_run_id=run_id,
                         channel=msg.channel.value, context=context,
                         customer_timezone=msg.customer_timezone or context.get("timezone")
                         or "UTC")
        if msg.customer_timezone:
            context["timezone"] = msg.customer_timezone
        async with db.tenant_session(tenant_id, actor="agent:SAMIIR") as s:
            s.add(AgentRun(id=run_id, tenant_id=tenant_id, agent_name="SAMIIR",
                           actor_type=ctx.principal.actor_type.value,
                           actor_id=ctx.principal.subject[:200], conversation_id=conversation_id,
                           runtime=self.runtime.name, request_id=ctx.request_id,
                           trace_id=current_trace_id()))

        started = time.perf_counter()
        result: AgentResult
        with tracer().start_as_current_span("samiir.run") as span:
            span.set_attribute("agent.name", "SAMIIR")
            span.set_attribute("agent.runtime", self.runtime.name)
            try:
                if msg.selected_slot_token:
                    result = AgentResult(text=await self._select_slot(state,
                                                                      msg.selected_slot_token))
                elif assessment.security_request:
                    result = AgentResult(text=SECURITY_REDIRECT,
                                         guardrail_flags=["security_request_redirected"])
                else:
                    result = await self.runtime.run(self.gateway, state, history, text, company)
                    grounding = check_grounding(result.text, state.grounding)
                    if not grounding.ok:  # defence in depth for any runtime
                        result.guardrail_flags.extend(f"grounding:{v}"
                                                      for v in grounding.violations[:5])
                        result.text = SAFE_FALLBACK
                        state.escalated = True
                        state.escalation_reason = "ungrounded answer blocked"
                status_run = "COMPLETED"
                error = None
            except Exception as exc:
                log.exception("samiir run failed")
                result = AgentResult(text=SAFE_FALLBACK)
                state.escalated = True
                state.escalation_reason = "agent error"
                status_run, error = "FAILED", type(exc).__name__
        latency = int((time.perf_counter() - started) * 1000)
        flags = [*state.flags, *result.guardrail_flags, *(f"input:{s}" for s in assessment.signals)]
        instruments().agent_runs.add(1, {"agent": "SAMIIR", "status": status_run,
                                         "runtime": self.runtime.name})
        async with db.tenant_session(tenant_id, actor="agent:SAMIIR") as s:
            run = await s.get(AgentRun, run_id)
            if run is not None:
                blocked = any(f.startswith("grounding") for f in result.guardrail_flags)
                run.status = "BLOCKED" if blocked else status_run
                run.completed_at = datetime.now(UTC)
                run.latency_ms = latency
                run.input_tokens = result.input_tokens
                run.output_tokens = result.output_tokens
                run.model = result.model
                run.guardrail_flags = flags
                run.error = error
        if state.escalated:
            await self.escalate(ctx, conversation_id, state.escalation_reason or "requested")
        reply_text = redact_text(result.text)
        return await self._store_reply(ctx, conversation_id, state.context, reply_text,
                                       state.cards, escalated=state.escalated)

    async def _select_slot(self, state: RunState, token: str) -> str:
        """Deterministic path for widget/WhatsApp slot buttons: only tokens that were offered
        in this conversation are accepted, and the booking still goes through the gateway."""
        offered = {o["token"]: o for o in state.context.get("offered_slots", [])}
        if token not in offered:
            return "That time is no longer on offer. Would you like me to check availability again?"
        slot = offered[token]
        result = await self.gateway.invoke(state, "calendar.book_appointment",
                                           {"slot_number": slot["n"]})
        if result.startswith("BOOKED"):
            return f"You're all set! Your appointment is confirmed for {slot['display']}."
        if result.startswith("NEED_CONTACT"):
            return ("Great choice! To confirm the booking, please share your name and email "
                    "address (and optionally your phone number).")
        return "Sorry, that time could not be booked. Would you like me to check other times?"

    async def submit_contact(self, ctx: RequestContext, conversation_ref: str, channel: Channel,
                             details: dict[str, Any]) -> ChatReply:
        """Widget contact form: structured input that bypasses the model entirely."""
        db = self.rt.require_db()
        async with db.tenant_session(ctx.tenant_id, actor="agent:SAMIIR") as s:
            conv = await self._conversation(s, ctx.tenant_id, InboundMessage(
                channel=channel, conversation_ref=conversation_ref, text="[contact form]"))
            conversation_id, context = conv.id, dict(conv.context or {})
        run_id = uuid.uuid4()
        run_ctx = RequestContext(caller=ctx.caller, receiver=ctx.receiver, principal=ctx.principal,
                                 request_id=ctx.request_id, source_ip=ctx.source_ip,
                                 agent_run_id=run_id)
        state = RunState(ctx=run_ctx, conversation_id=conversation_id, agent_run_id=run_id,
                         channel=channel.value, context=context,
                         customer_timezone=context.get("timezone", "UTC"))
        async with db.tenant_session(ctx.tenant_id, actor="agent:SAMIIR") as s:
            s.add(AgentRun(id=run_id, tenant_id=ctx.tenant_id, agent_name="SAMIIR",
                           actor_type=ctx.principal.actor_type.value,
                           actor_id=ctx.principal.subject[:200], conversation_id=conversation_id,
                           runtime="form", request_id=ctx.request_id, status="COMPLETED"))
        result = await self.gateway.invoke(state, "crm.capture_contact", details)
        text = "Thank you, your details are saved." if result.startswith("SAVED") else \
            "Sorry, those details could not be saved. Please check them and try again."
        if result.startswith("SAVED") and (token := context.get("pending_slot_token")):
            text = await self._select_slot(state, token)
        return await self._store_reply(ctx, conversation_id, state.context, text, state.cards,
                                       escalated=False)

    async def _store_reply(self, ctx: RequestContext, conversation_id: uuid.UUID,
                           context: dict[str, Any], text: str, cards: list[Card], *,
                           escalated: bool, handled_by: str = "samiir") -> ChatReply:
        persisted_context = {k: v for k, v in context.items() if k != "_wa_phone"}
        async with self.rt.require_db().tenant_session(ctx.tenant_id, actor="agent:SAMIIR") as s:
            conv = await s.get(Conversation, conversation_id)
            if conv is not None:
                conv.context = persisted_context
                conv.last_message_at = datetime.now(UTC)
                if persisted_context.get("contact_id") and not conv.contact_id:
                    conv.contact_id = uuid.UUID(persisted_context["contact_id"])
            m = Message(tenant_id=ctx.tenant_id, conversation_id=conversation_id,
                        direction="outbound", sender_type=SenderType.SAMIIR.value,
                        sender_id="SAMIIR", content=text[:8000],
                        cards=[c.model_dump(mode="json") for c in cards])
            s.add(m)
            await s.flush()
            message_id = m.id
        await self.rt.realtime.publish(ctx.tenant_id, "samiir", "message.outbound",
                                       {"conversation_id": conversation_id,
                                        "escalated": escalated})
        return ChatReply(conversation_id=conversation_id, message_id=message_id, text=text,
                         cards=cards, escalated=escalated, handled_by=handled_by)  # type: ignore[arg-type]

    async def escalate(self, ctx: RequestContext, conversation_id: uuid.UUID, reason: str) -> None:
        async with self.rt.require_db().tenant_session(ctx.tenant_id, actor="agent:SAMIIR") as s:
            conv = await s.get(Conversation, conversation_id)
            if conv is None or conv.status in (ConversationStatus.ESCALATED,
                                               ConversationStatus.HUMAN_HANDLING):
                return
            conv.status = ConversationStatus.ESCALATED.value
            conv.escalation_reason = reason[:300]
        await self.rt.audit.record(ctx, action="conversation.escalate", result="success",
                                   agent_name="SAMIIR", target_type="conversation",
                                   target_id=conversation_id, metadata={"reason": reason})
        await self.rt.realtime.publish(ctx.tenant_id, "samiir", "conversation.escalated",
                                       {"conversation_id": conversation_id, "reason": reason})

    async def history(self, ctx: RequestContext, channel: Channel, conversation_ref: str,
                      limit: int = 50) -> dict[str, Any]:
        ref_hash = self.ref_hash(ctx.tenant_id, channel.value, conversation_ref)
        async with self.rt.require_db().tenant_session(ctx.tenant_id) as s:
            conv = await s.scalar(select(Conversation).where(
                Conversation.channel == channel.value, Conversation.external_ref_hash == ref_hash))
            if conv is None:
                return {"conversation_id": None, "messages": []}
            rows = (await s.scalars(select(Message).where(Message.conversation_id == conv.id)
                                    .order_by(Message.created_at.desc()).limit(limit))).all()
            return {"conversation_id": conv.id, "status": conv.status, "messages": [
                {"id": m.id, "sender": m.sender_type, "text": m.content, "cards": m.cards,
                 "created_at": m.created_at} for m in reversed(rows)]}


__all__ = ["ChatService"]
