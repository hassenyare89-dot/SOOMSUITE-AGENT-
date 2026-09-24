from __future__ import annotations

import asyncio

from fastapi import FastAPI

from notifications_service.api import router
from notifications_service.config import Settings
from notifications_service.senders import SmtpEmailSender, WhatsAppRelay
from notifications_service.service import NotificationService
from platform_core.app import ServiceRuntime, build_runtime, create_app
from platform_core.security.crypto import load_field_encryptor


def create(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()

    async def startup(rt: ServiceRuntime) -> None:
        if "notifications" not in rt.extras:
            enc = await load_field_encryptor(rt.secrets, settings.field_keyring_ref,
                                             settings.blind_index_key_ref,
                                             allow_ephemeral=not settings.is_production_like)
            user = await rt.secrets.get(settings.smtp_username_ref) if settings.smtp_username_ref else None
            pw = await rt.secrets.get(settings.smtp_password_ref) if settings.smtp_password_ref else None
            slack = (await rt.secrets.get(settings.security_slack_webhook_ref)
                     if settings.security_slack_webhook_ref else None)
            email = SmtpEmailSender(settings.smtp_host, settings.smtp_port, settings.email_from,
                                    username=user, password=pw, starttls=settings.smtp_starttls,
                                    use_tls=settings.smtp_use_tls)
            wa = WhatsAppRelay(rt.client("whatsapp")) if "whatsapp" in rt.clients else None
            rt.extras["notifications"] = NotificationService(
                rt.require_db(), email, wa, rt.client("crm"), enc, slack_url=slack,
                max_attempts=settings.max_attempts)
        if settings.run_worker:
            stop = asyncio.Event()
            rt.extras["stop"] = stop
            rt.extras["worker"] = asyncio.create_task(rt.extras["notifications"].run_worker(
                settings.worker_poll_seconds, settings.worker_batch, stop))

    async def shutdown(rt: ServiceRuntime) -> None:
        if stop := rt.extras.get("stop"):
            stop.set()
            await rt.extras["worker"]

    return create_app(settings=settings,
                      runtime_factory=lambda: build_runtime(settings, {
                          "crm": settings.crm_url, "whatsapp": settings.whatsapp_url}),
                      routers=[router], on_startup=startup, on_shutdown=shutdown,
                      title="Notifications Service")
