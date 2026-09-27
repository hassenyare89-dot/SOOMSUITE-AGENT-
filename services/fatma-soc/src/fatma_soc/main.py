from __future__ import annotations

import asyncio
import contextlib
import logging
import secrets
import uuid

from fastapi import FastAPI
from sqlalchemy import select, text

from fatma_soc.agent import DeterministicAnalyst, FatmaAgent, FatmaTools, OpenAIAnalyst
from fatma_soc.api import process_events, router
from fatma_soc.config import Settings
from fatma_soc.defense import DefenseService
from fatma_soc.incidents import IncidentEngine
from platform_core.app import ServiceRuntime, build_runtime, create_app
from platform_core.db.models import SecurityEvent, WafAction
from platform_core.security.secret_manager import SecretNotFound

log = logging.getLogger(__name__)


async def sweep(rt: ServiceRuntime) -> None:
    """Safety net: process events FATMA was not notified about; expire time-boxed actions."""
    db = rt.require_db()
    async with db.system_session() as s:
        tenants = [r[0] for r in (await s.execute(text("SELECT * FROM app_active_tenants()"))).all()]
        due = (await s.execute(text("SELECT * FROM app_due_waf_expirations(100)"))).all()
    for tenant_id in tenants:
        async with db.tenant_session(tenant_id) as s:
            ids = list((await s.scalars(select(SecurityEvent.event_id).where(
                SecurityEvent.risk.is_(None)).limit(1000))).all())
        if ids:
            await process_events(rt, tenant_id, ids, f"sweep-{secrets.token_hex(6)}")
    for tenant_id, action_id in due:
        async with db.tenant_session(tenant_id, actor="agent:FATMA") as s:
            action = await s.get(WafAction, action_id)
            if action is not None:
                try:
                    await rt.extras["defense"].revert(s, action, expired=True)
                except Exception:
                    log.exception("failed to expire action %s", action_id)


def create(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()

    async def loop(rt: ServiceRuntime, stop: asyncio.Event) -> None:
        while not stop.is_set():
            try:
                await sweep(rt)
            except Exception:
                log.exception("FATMA sweep failed")
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=settings.sweep_seconds)

    async def startup(rt: ServiceRuntime) -> None:
        if "engine" not in rt.extras:
            rt.extras["engine"] = IncidentEngine()
            rt.extras["defense"] = DefenseService(
                rt.secrets, allow_documentation_ranges=not settings.is_production_like
                and settings.environment.value in ("development", "test"))
            analyst = DeterministicAnalyst()
            if settings.openai_api_key_ref:
                try:
                    key = await rt.secrets.get(settings.openai_api_key_ref)
                    analyst = OpenAIAnalyst(key, settings.openai_model,
                                            settings.openai_tracing_enabled)
                except SecretNotFound:
                    log.warning("FATMA running with the deterministic analyst")
            rt.extras["agent"] = FatmaAgent(rt, FatmaTools(rt, rt.extras["defense"]), analyst)
        if settings.run_background:
            stop = asyncio.Event()
            rt.extras["stop"] = stop
            rt.extras["loop"] = asyncio.create_task(loop(rt, stop))

    async def shutdown(rt: ServiceRuntime) -> None:
        if stop := rt.extras.get("stop"):
            stop.set()
            await rt.extras["loop"]
        tasks = rt.extras.get("tasks") or set()
        if tasks:
            await asyncio.wait(tasks, timeout=15)

    return create_app(settings=settings,
                      runtime_factory=lambda: build_runtime(settings, {
                          "approvals": settings.approvals_url,
                          "notifications": settings.notifications_url}),
                      routers=[router], on_startup=startup, on_shutdown=shutdown,
                      title="FATMA SOC Service")


__all__ = ["create", "sweep", "uuid"]
