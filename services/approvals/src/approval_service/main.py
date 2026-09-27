from __future__ import annotations

import asyncio
import contextlib
import logging

from fastapi import FastAPI

from approval_service.api import router
from approval_service.config import Settings
from approval_service.service import ApprovalService
from platform_core.app import ServiceRuntime, build_runtime, create_app

log = logging.getLogger(__name__)


def create(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()

    async def sweeper(rt: ServiceRuntime, stop: asyncio.Event) -> None:
        while not stop.is_set():
            try:
                await rt.extras["approvals"].expire_all(rt.require_db())
            except Exception:
                log.exception("approval expiry sweep failed")
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=settings.expiry_sweep_seconds)

    async def startup(rt: ServiceRuntime) -> None:
        rt.extras.setdefault("approvals", ApprovalService(rt.identity))
        stop = asyncio.Event()
        rt.extras["stop"] = stop
        rt.extras["task"] = asyncio.create_task(sweeper(rt, stop))

    async def shutdown(rt: ServiceRuntime) -> None:
        rt.extras["stop"].set()
        await rt.extras["task"]

    return create_app(settings=settings, runtime_factory=lambda: build_runtime(settings, {}),
                      routers=[router], on_startup=startup, on_shutdown=shutdown,
                      title="Approval Service")
