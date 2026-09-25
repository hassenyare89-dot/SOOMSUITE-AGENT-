from __future__ import annotations

import base64
import os

from fastapi import FastAPI

from platform_core.app import ServiceRuntime, build_runtime, create_app
from platform_core.security.secret_manager import SecretNotFound
from scheduling_service.api import router
from scheduling_service.config import Settings
from scheduling_service.service import SchedulingService


def create(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()

    async def startup(rt: ServiceRuntime) -> None:
        if "scheduling" in rt.extras:
            return
        try:
            key = base64.b64decode(await rt.secrets.get(settings.slot_token_key_ref or ""))
        except SecretNotFound:
            if settings.is_production_like:
                raise
            key = os.urandom(32)
        rt.extras["scheduling"] = SchedulingService(key, rt.secrets,
                                                    settings.slot_offer_ttl_seconds)

    return create_app(settings=settings,
                      runtime_factory=lambda: build_runtime(settings, {
                          "crm": settings.crm_url, "notifications": settings.notifications_url}),
                      routers=[router], on_startup=startup, title="SAMIIR Scheduling Service")
