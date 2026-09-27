from __future__ import annotations

from fastapi import FastAPI

from platform_core.app import ServiceRuntime, build_runtime, create_app
from scanner_controller.api import router
from scanner_controller.config import Settings
from scanner_controller.service import ScanService


def create(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()

    async def startup(rt: ServiceRuntime) -> None:
        rt.extras.setdefault("scans", ScanService(max_per_day=settings.max_scans_per_day,
                                                  max_concurrent=settings.max_concurrent_scans))
        if settings.temporal_address and "start_workflow" not in rt.extras:
            from scanner_controller.workflows import setup_temporal

            await setup_temporal(rt, settings.temporal_address, settings.temporal_namespace,
                                 settings.controller_task_queue)

    async def shutdown(rt: ServiceRuntime) -> None:
        if worker := rt.extras.get("temporal_worker"):
            await worker.shutdown()

    return create_app(settings=settings,
                      runtime_factory=lambda: build_runtime(settings, {
                          "approvals": settings.approvals_url, "fatma-soc": settings.fatma_url}),
                      routers=[router], on_startup=startup, on_shutdown=shutdown,
                      title="Scanner Controller")
