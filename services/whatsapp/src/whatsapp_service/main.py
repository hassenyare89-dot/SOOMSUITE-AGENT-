from __future__ import annotations

import asyncio

from fastapi import FastAPI

from platform_core.app import ServiceRuntime, build_runtime, create_app
from platform_core.security.ratelimit import RedisRateLimiter
from platform_core.security.secret_manager import SecretNotFound
from whatsapp_service.api import router
from whatsapp_service.config import Settings
from whatsapp_service.meta import GraphClient
from whatsapp_service.service import WhatsAppService


def create(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()

    async def startup(rt: ServiceRuntime) -> None:
        if "whatsapp" in rt.extras:
            return

        async def secret(ref: str) -> str:
            try:
                return await rt.secrets.get(ref)
            except SecretNotFound:
                if settings.is_production_like:
                    raise
                return ""  # empty secret => every signature/verification check fails closed

        rt.extras["whatsapp"] = WhatsAppService(
            rt, GraphClient(settings.meta_graph_base, settings.meta_graph_version),
            app_secret=await secret(settings.meta_app_secret_ref),
            verify_token=await secret(settings.meta_verify_token_ref),
            language=settings.template_language, dedupe_ttl=settings.dedupe_ttl_seconds,
            per_minute=settings.inbound_per_minute,
            max_concurrency=settings.max_concurrent_processing,
            limiter=RedisRateLimiter(rt.redis, "wa") if rt.redis is not None else None)

    async def shutdown(rt: ServiceRuntime) -> None:
        tasks = rt.extras["whatsapp"].tasks
        if tasks:
            await asyncio.wait(tasks, timeout=10)

    return create_app(settings=settings,
                      runtime_factory=lambda: build_runtime(settings, {
                          "samiir-agent": settings.samiir_url,
                          "notifications": settings.notifications_url}),
                      routers=[router], on_startup=startup, on_shutdown=shutdown,
                      title="WhatsApp Integration Service")
