"""Inbound webhook processing and outbound delivery."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import secrets
import uuid
from typing import Any

from sqlalchemy import select, text

from platform_core.app import ServiceRuntime
from platform_core.db.models import Integration
from platform_core.errors import Conflict, NotFound, PlatformError, RateLimited, Unauthenticated
from platform_core.observability import instruments
from platform_core.security.principal import ActorType, Principal, Role
from platform_core.security.ratelimit import InMemoryRateLimiter, Limit, RateLimiter
from whatsapp_service.meta import (
    GraphClient,
    InboundWa,
    buttons_payload,
    list_payload,
    parse_webhook,
    template_payload,
    text_payload,
    verify_signature,
)

log = logging.getLogger(__name__)
KIND = "whatsapp.cloud"
UNSUPPORTED_REPLY = ("Thanks! I can only read text messages here. Please type your question, "
                     "and please don't send files or sensitive documents.")


class _Memory:
    """Tiny Redis stand-in for tests/dev without Redis."""

    def __init__(self) -> None:
        self.kv: dict[str, str] = {}

    async def set(self, k: str, v: str, nx: bool = False, ex: int | None = None) -> bool:
        if nx and k in self.kv:
            return False
        self.kv[k] = v
        return True

    async def get(self, k: str) -> str | None:
        return self.kv.get(k)


class WhatsAppService:
    def __init__(self, rt: ServiceRuntime, graph: GraphClient, *, app_secret: str,
                 verify_token: str, language: str, dedupe_ttl: int, per_minute: int,
                 max_concurrency: int, limiter: RateLimiter | None = None) -> None:
        self.rt = rt
        self.graph = graph
        self.app_secret = app_secret
        self.verify_token = verify_token
        self.language = language
        self.dedupe_ttl = dedupe_ttl
        self.per_minute = per_minute
        self.kv: Any = rt.redis or _Memory()
        self.limiter = limiter or InMemoryRateLimiter()
        self.sem = asyncio.Semaphore(max_concurrency)
        self.tasks: set[asyncio.Task] = set()

    # ------------------------------------------------------------------ webhook
    def check_verification(self, mode: str | None, token: str | None) -> bool:
        return mode == "subscribe" and bool(token) and secrets.compare_digest(
            token or "", self.verify_token)

    async def receive(self, raw: bytes, signature: str | None, request_id: str) -> dict[str, int]:
        if not verify_signature(raw, signature, self.app_secret):
            instruments().webhooks.add(1, {"source": "whatsapp", "result": "bad_signature"})
            raise Unauthenticated("invalid webhook signature")
        try:
            payload = json.loads(raw)
        except ValueError as exc:
            raise Unauthenticated("malformed webhook") from exc
        messages, statuses = parse_webhook(payload)
        accepted = 0
        for m in messages:
            # Deduplicate: Meta retries deliveries; process each message id once.
            if not await self.kv.set(f"wa:seen:{m.message_id}", "1", nx=True, ex=self.dedupe_ttl):
                continue
            accepted += 1
            task = asyncio.create_task(self._process_guarded(m, request_id))
            self.tasks.add(task)
            task.add_done_callback(self.tasks.discard)
        for st in statuses:
            task = asyncio.create_task(self._status(st.phone_number_id, st.message_id, st.status,
                                                    request_id))
            self.tasks.add(task)
            task.add_done_callback(self.tasks.discard)
        instruments().webhooks.add(1, {"source": "whatsapp", "result": "accepted"})
        return {"messages": accepted, "statuses": len(statuses)}

    async def _resolve(self, phone_number_id: str) -> tuple[uuid.UUID, str]:
        async with self.rt.require_db().system_session() as s:
            row = (await s.execute(text("SELECT * FROM app_resolve_integration(:k, :e)"),
                                   {"k": KIND, "e": phone_number_id})).first()
        if row is None or not row.secret_ref:
            raise NotFound("no tenant for this phone number")
        return row.tenant_id, await self.rt.secrets.get(row.secret_ref)

    async def _process_guarded(self, m: InboundWa, request_id: str) -> None:
        async with self.sem:
            try:
                await self.process(m, request_id)
            except Exception:
                log.exception("whatsapp message processing failed")

    async def process(self, m: InboundWa, request_id: str) -> None:
        tenant_id, token = await self._resolve(m.phone_number_id)
        rid = f"{request_id[:40]}-{hashlib.sha256(m.message_id.encode()).hexdigest()[:12]}"
        allowed, _ = await self.limiter.hit(f"wa:in:{tenant_id}:{m.wa_id}", Limit(self.per_minute, 60))
        if not allowed:
            raise RateLimited()
        await self.graph.mark_read(m.phone_number_id, token, m.message_id)
        if m.kind == "unsupported" or not (m.text or m.reply_id):
            await self.graph.send(m.phone_number_id, token, text_payload(m.wa_id, UNSUPPORTED_REPLY))
            return
        selected = None
        if m.reply_id and m.reply_id.startswith("slot_"):
            selected = await self.kv.get(f"wa:slotref:{m.reply_id}")
            if isinstance(selected, bytes):
                selected = selected.decode()
        principal = Principal(subject=f"wa:{hashlib.sha256(m.wa_id.encode()).hexdigest()[:24]}",
                              tenant_id=tenant_id, actor_type=ActorType.CUSTOMER,
                              roles=frozenset({Role.ANONYMOUS_CUSTOMER}), session_id=m.wa_id)
        try:
            reply = await self.rt.client("samiir-agent").post("/internal/chat", principal=principal,
                                                              request_id=rid, json={
                "channel": "whatsapp", "conversation_ref": m.wa_id,
                "text": m.text or "(selection)", "external_message_id": m.message_id,
                "selected_slot_token": selected})
        except Conflict:
            return  # duplicate already handled
        await self._send_reply(m.phone_number_id, token, m.wa_id, reply)

    async def _send_reply(self, pnid: str, token: str, to: str, reply: dict[str, Any]) -> None:
        cards = {c["type"]: c["data"] for c in reply.get("cards", [])}
        body = reply["text"]
        if slots := cards.get("slots"):
            rows = []
            for slot in slots["slots"]:
                ref = f"slot_{secrets.token_urlsafe(9)}"
                await self.kv.set(f"wa:slotref:{ref}", slot["slot_token"], ex=1800)
                rows.append((ref, slot["display"]))
            payload = list_payload(to, body, "Choose a time", rows)
        elif quick := cards.get("quick_replies"):
            payload = buttons_payload(to, body, quick["options"])
        else:
            payload = text_payload(to, body)
        await self.graph.send(pnid, token, payload)

    async def _status(self, pnid: str, message_id: str, status: str, request_id: str) -> None:
        try:
            tenant_id, _ = await self._resolve(pnid)
        except PlatformError:
            return
        system = Principal.system(tenant_id, "whatsapp")
        for audience, path, body in (
            ("samiir-agent", "/internal/messages/status",
             {"external_message_id": message_id, "status": status}),
            ("notifications", "/internal/notifications/status",
             {"provider_message_id": message_id, "status": status}),
        ):
            try:
                await self.rt.client(audience).post(path, principal=system,
                                                    request_id=request_id[:60], json=body)
            except PlatformError:
                log.warning("status forwarding failed", extra={"ctx": {"to": audience}})

    # ----------------------------------------------------------------- outbound
    async def tenant_sender(self, tenant_id: uuid.UUID) -> tuple[str, str, dict]:
        async with self.rt.require_db().tenant_session(tenant_id) as s:
            integ = await s.scalar(select(Integration).where(Integration.kind == KIND,
                                                             Integration.status == "active"))
        if integ is None or not integ.external_key or not integ.secret_ref:
            raise NotFound("whatsapp is not configured for this tenant")
        return integ.external_key, await self.rt.secrets.get(integ.secret_ref), integ.config

    async def send(self, tenant_id: uuid.UUID, *, to: str, text_body: str | None,
                   template: str | None, params: list[str], idempotency_key: str) -> str:
        key = f"wa:out:{tenant_id}:{hashlib.sha256(idempotency_key.encode()).hexdigest()}"
        if existing := await self.kv.get(key):
            return existing.decode() if isinstance(existing, bytes) else existing
        pnid, token, config = await self.tenant_sender(tenant_id)
        to = to.lstrip("+")
        approved = set(config.get("approved_templates", []))
        if template and template in approved:
            payload = template_payload(to, template, config.get("language", self.language), params)
        elif text_body:
            payload = text_payload(to, text_body)
        else:
            raise NotFound("no approved template and no text body")
        message_id = await self.graph.send(pnid, token, payload)
        await self.kv.set(key, message_id, ex=86400)
        return message_id
