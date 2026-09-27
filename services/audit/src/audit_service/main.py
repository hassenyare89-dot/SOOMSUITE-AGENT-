from __future__ import annotations

import asyncio

from fastapi import FastAPI

from audit_service.api import router
from audit_service.config import Settings
from audit_service.service import AuditStore, SiemForwarder
from platform_core.app import ServiceRuntime, build_runtime, create_app


def create(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()

    async def startup(rt: ServiceRuntime) -> None:
        if "store" not in rt.extras:
            key = (await rt.secrets.get(settings.siem_hmac_key_ref)).encode() \
                if settings.siem_hmac_key_ref else None
            forwarder = SiemForwarder(settings.siem_webhook_url, key, settings.siem_queue_size)
            rt.extras["store"] = AuditStore(rt.require_db(), forwarder)
            stop = asyncio.Event()
            rt.extras["stop"] = stop
            rt.extras["task"] = asyncio.create_task(forwarder.run(stop))

    async def shutdown(rt: ServiceRuntime) -> None:
        if stop := rt.extras.get("stop"):
            stop.set()
            await rt.extras["task"]

    # The audit service itself must never call out to an audit service (no recursion).
    settings.audit_url = None
    return create_app(settings=settings, runtime_factory=lambda: build_runtime(settings, {}),
                      routers=[router], on_startup=startup, on_shutdown=shutdown,
                      title="Audit Service")
