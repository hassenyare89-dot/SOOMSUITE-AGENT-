from __future__ import annotations

import logging

from fastapi import FastAPI

from platform_core.app import ServiceRuntime, build_runtime, create_app
from platform_core.security.crypto import load_field_encryptor
from platform_core.security.ratelimit import RedisRateLimiter
from platform_core.security.secret_manager import SecretNotFound
from samiir_agent.api import router
from samiir_agent.config import Settings
from samiir_agent.runtime.deterministic import DeterministicRuntime
from samiir_agent.service import ChatService
from samiir_agent.tools import SAMIIR_TOOLS, ToolGateway

log = logging.getLogger(__name__)


async def _runtime(rt: ServiceRuntime, settings: Settings):  # noqa: ANN202
    if settings.openai_api_key_ref:
        try:
            key = await rt.secrets.get(settings.openai_api_key_ref)
        except SecretNotFound:
            key = None
        if key:
            from samiir_agent.runtime.openai_agents import OpenAIAgentsRuntime

            return OpenAIAgentsRuntime(key, settings.openai_model, max_turns=settings.max_turns,
                                       tracing_enabled=settings.openai_tracing_enabled)
    log.warning("SAMIIR running with the deterministic runtime (no model API key configured)")
    return DeterministicRuntime()


def create(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()

    async def startup(rt: ServiceRuntime) -> None:
        if "chat" in rt.extras:
            return
        enc = await load_field_encryptor(rt.secrets, settings.field_keyring_ref,
                                         settings.blind_index_key_ref,
                                         allow_ephemeral=not settings.is_production_like)
        limiter = RedisRateLimiter(rt.redis, "samiir") if rt.redis is not None else None
        rt.extras["chat"] = ChatService(
            rt, await _runtime(rt, settings), ToolGateway(rt, SAMIIR_TOOLS), enc,
            history_messages=settings.history_messages,
            default_appointment_type=settings.default_appointment_type, limiter=limiter,
            per_minute=settings.per_conversation_messages_per_minute)

    return create_app(settings=settings,
                      runtime_factory=lambda: build_runtime(settings, {
                          "knowledge": settings.knowledge_url, "crm": settings.crm_url,
                          "scheduling": settings.scheduling_url,
                          "notifications": settings.notifications_url,
                          "whatsapp": settings.whatsapp_url}),
                      routers=[router], on_startup=startup, title="SAMIIR Agent Service")
