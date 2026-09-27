"""Meta WhatsApp Cloud API: signature validation, payload parsing, message sending."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
from dataclasses import dataclass
from typing import Any

import httpx

from platform_core.errors import UpstreamUnavailable, ValidationFailed


def verify_signature(raw_body: bytes, header: str | None, app_secret: str) -> bool:
    """X-Hub-Signature-256 = 'sha256=' + HMAC-SHA256(app_secret, raw request body)."""
    if not header or not header.startswith("sha256=") or not app_secret:
        return False
    expected = hmac.new(app_secret.encode(), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(header.removeprefix("sha256="), expected)


@dataclass(frozen=True)
class InboundWa:
    phone_number_id: str
    wa_id: str
    message_id: str
    timestamp: int
    kind: str                 # text | interactive | unsupported
    text: str | None
    reply_id: str | None      # interactive button/list reply id
    profile_name: str | None


@dataclass(frozen=True)
class StatusWa:
    phone_number_id: str
    message_id: str
    status: str
    recipient: str | None


def parse_webhook(payload: dict[str, Any]) -> tuple[list[InboundWa], list[StatusWa]]:
    if payload.get("object") != "whatsapp_business_account":
        raise ValidationFailed("unexpected webhook object")
    messages: list[InboundWa] = []
    statuses: list[StatusWa] = []
    for entry in payload.get("entry", [])[:50]:
        for change in entry.get("changes", [])[:50]:
            if change.get("field") != "messages":
                continue
            value = change.get("value", {})
            pnid = str(value.get("metadata", {}).get("phone_number_id", ""))
            profiles = {c.get("wa_id"): c.get("profile", {}).get("name")
                        for c in value.get("contacts", [])}
            for m in value.get("messages", [])[:100]:
                mtype = m.get("type")
                text = reply_id = None
                if mtype == "text":
                    text = str(m.get("text", {}).get("body", ""))[:4000]
                    kind = "text"
                elif mtype == "interactive":
                    inter = m.get("interactive", {})
                    reply = inter.get("button_reply") or inter.get("list_reply") or {}
                    reply_id = str(reply.get("id", ""))[:200]
                    text = str(reply.get("title", ""))[:200]
                    kind = "interactive"
                elif mtype == "button":  # quick-reply button on a template
                    text = str(m.get("button", {}).get("text", ""))[:200]
                    reply_id = str(m.get("button", {}).get("payload", ""))[:200]
                    kind = "interactive"
                else:
                    kind = "unsupported"
                wa_id = str(m.get("from", ""))
                if not (pnid and wa_id.isdigit() and m.get("id")):
                    continue
                messages.append(InboundWa(pnid, wa_id, str(m["id"])[:200],
                                          int(m.get("timestamp", 0) or 0), kind, text, reply_id,
                                          profiles.get(wa_id)))
            for st in value.get("statuses", [])[:100]:
                if st.get("id") and st.get("status") in ("sent", "delivered", "read", "failed"):
                    statuses.append(StatusWa(pnid, str(st["id"])[:200], st["status"],
                                             st.get("recipient_id")))
    return messages, statuses


class GraphClient:
    def __init__(self, base: str, version: str, client: httpx.AsyncClient | None = None) -> None:
        self._base = f"{base.rstrip('/')}/{version}"
        self._http = client or httpx.AsyncClient(timeout=15)

    async def send(self, phone_number_id: str, token: str, payload: dict[str, Any]) -> str:
        body = {"messaging_product": "whatsapp", "recipient_type": "individual", **payload}
        for attempt in range(4):
            try:
                resp = await self._http.post(f"{self._base}/{phone_number_id}/messages", json=body,
                                             headers={"Authorization": f"Bearer {token}"})
            except httpx.TransportError:
                await asyncio.sleep(0.5 * 2**attempt)
                continue
            if resp.status_code == 200:
                return str(resp.json()["messages"][0]["id"])
            if resp.status_code in (429, 500, 502, 503, 504):
                await asyncio.sleep(float(resp.headers.get("Retry-After", 0.5 * 2**attempt)))
                continue
            raise UpstreamUnavailable(f"meta rejected message ({resp.status_code})")
        raise UpstreamUnavailable("meta unavailable")

    async def mark_read(self, phone_number_id: str, token: str, message_id: str) -> None:
        try:
            await self._http.post(f"{self._base}/{phone_number_id}/messages",
                                  headers={"Authorization": f"Bearer {token}"},
                                  json={"messaging_product": "whatsapp", "status": "read",
                                        "message_id": message_id})
        except httpx.HTTPError:
            pass


def text_payload(to: str, body: str) -> dict[str, Any]:
    return {"to": to, "type": "text", "text": {"body": body[:4096], "preview_url": False}}


def template_payload(to: str, name: str, language: str, params: list[str]) -> dict[str, Any]:
    components = [{"type": "body", "parameters": [{"type": "text", "text": p[:1000]}
                                                  for p in params]}] if params else []
    return {"to": to, "type": "template",
            "template": {"name": name, "language": {"code": language}, "components": components}}


def list_payload(to: str, body: str, button: str, rows: list[tuple[str, str]]) -> dict[str, Any]:
    return {"to": to, "type": "interactive", "interactive": {
        "type": "list", "body": {"text": body[:1024]},
        "action": {"button": button[:20], "sections": [{"title": "Available times", "rows": [
            {"id": rid[:200], "title": title[:24], "description": title[24:96]}
            for rid, title in rows[:10]]}]}}}


def buttons_payload(to: str, body: str, options: list[str]) -> dict[str, Any]:
    return {"to": to, "type": "interactive", "interactive": {
        "type": "button", "body": {"text": body[:1024]},
        "action": {"buttons": [{"type": "reply", "reply": {"id": f"qr_{i}", "title": o[:20]}}
                               for i, o in enumerate(options[:3])]}}}
