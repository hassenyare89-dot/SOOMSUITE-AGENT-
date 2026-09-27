"""Delivery channels."""

from __future__ import annotations

from email.message import EmailMessage
from typing import Any, Protocol

import httpx

from platform_core.errors import UpstreamUnavailable
from platform_core.security.principal import Principal


class EmailSender(Protocol):
    async def send(self, to: str, subject: str, text: str, html: str) -> str: ...


class SmtpEmailSender:
    def __init__(self, host: str, port: int, sender: str, *, username: str | None = None,
                 password: str | None = None, starttls: bool = False, use_tls: bool = False
                 ) -> None:
        self.host, self.port, self.sender = host, port, sender
        self.username, self.password = username, password
        self.starttls, self.use_tls = starttls, use_tls

    async def send(self, to: str, subject: str, text: str, html: str) -> str:
        import aiosmtplib

        msg = EmailMessage()
        msg["From"] = self.sender
        msg["To"] = to
        msg["Subject"] = subject.replace("\n", " ")[:200]
        msg.set_content(text)
        msg.add_alternative(html, subtype="html")
        try:
            await aiosmtplib.send(msg, hostname=self.host, port=self.port, username=self.username,
                                  password=self.password, start_tls=self.starttls,
                                  use_tls=self.use_tls, timeout=15)
        except (aiosmtplib.SMTPException, OSError) as exc:
            raise UpstreamUnavailable("smtp delivery failed") from exc
        return msg.get("Message-ID") or ""


class MemoryEmailSender:
    def __init__(self) -> None:
        self.sent: list[dict[str, str]] = []

    async def send(self, to: str, subject: str, text: str, html: str) -> str:
        self.sent.append({"to": to, "subject": subject, "text": text})
        return f"mem-{len(self.sent)}"


class WhatsAppRelay:
    """Delegates to the WhatsApp service, which alone holds Meta credentials."""

    def __init__(self, client: Any) -> None:
        self._client = client

    async def send(self, principal: Principal, request_id: str, *, phone: str,
                   text: str | None, template: str | None, params: list[str],
                   idempotency_key: str) -> str:
        resp = await self._client.post("/internal/send", principal=principal,
                                       request_id=request_id, json={
            "to": phone, "text": text, "template": template, "template_params": params,
            "idempotency_key": idempotency_key})
        return resp["message_id"]


async def post_slack(url: str, text: str) -> None:
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(url, json={"text": text[:3000]})
    if resp.status_code >= 300:
        raise UpstreamUnavailable("slack delivery failed")
