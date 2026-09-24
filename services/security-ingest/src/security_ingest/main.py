from __future__ import annotations

import base64
import logging
import os
from pathlib import Path

from fastapi import FastAPI

from platform_core.app import ServiceRuntime, build_runtime, create_app
from platform_core.config import Environment
from platform_core.security.secret_manager import SecretNotFound
from platform_core.security.service_auth import InMemoryReplayCache, RedisReplayCache
from platform_core.storage import FilesystemObjectStore, Quarantine
from security_ingest.api import router
from security_ingest.config import Settings
from security_ingest.service import IngestService

log = logging.getLogger(__name__)


def create(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()

    async def startup(rt: ServiceRuntime) -> None:
        async def key(ref: str | None) -> bytes:
            try:
                return base64.b64decode(await rt.secrets.get(ref or ""))
            except SecretNotFound:
                if settings.is_production_like:
                    raise
                return os.urandom(32)

        if "ingest" in rt.extras:
            return
        store = FilesystemObjectStore(settings.raw_store_path)
        quarantine = Quarantine(FilesystemObjectStore(settings.quarantine_path),
                                await key(settings.quarantine_key_ref))
        replay = RedisReplayCache(rt.redis, "ingest") if rt.redis else InMemoryReplayCache()
        svc = IngestService(rt, store, quarantine, replay, await key(settings.pseudonym_key_ref),
                            tolerance=settings.signature_tolerance_seconds,
                            max_decompressed=settings.max_decompressed_bytes,
                            max_events=settings.max_events_per_batch)
        if settings.temporal_address:
            from temporalio.client import Client

            svc.temporal = await Client.connect(settings.temporal_address,
                                                namespace=settings.temporal_namespace)
            rt.extras["temporal_worker"] = await _start_worker(svc, settings)
        elif settings.environment in (Environment.DEVELOPMENT, Environment.TEST):
            import scanner_worker
            from scanner_worker.malware import YaraEngine, analyze

            rules = YaraEngine(Path(scanner_worker.__file__).parent / "rules")
            clamd = (settings.clamd_host, settings.clamd_port) if settings.clamd_host else None

            async def inline(data: bytes, declared: str | None) -> dict:
                return await analyze(data, declared_mime=declared, yara=rules, clamd=clamd)

            svc.inline_analyzer = inline
            log.warning("malware analysis running INLINE (development only; no sandbox)")
        rt.extras["ingest"] = svc

    async def shutdown(rt: ServiceRuntime) -> None:
        if worker := rt.extras.get("temporal_worker"):
            await worker.shutdown()

    return create_app(settings=settings,
                      runtime_factory=lambda: build_runtime(settings, {
                          "fatma-soc": settings.fatma_url}),
                      routers=[router], on_startup=startup, on_shutdown=shutdown,
                      body_limit_overrides={"/internal/ingest/": settings.max_webhook_bytes,
                                            "/internal/malware/submit": settings.max_upload_bytes},
                      title="Security Ingestion Service")


async def _start_worker(svc: IngestService, settings: Settings):  # noqa: ANN202
    import asyncio
    import uuid

    from temporalio import activity
    from temporalio.worker import Worker

    from platform_core.workflows.types import MalwareVerdict

    @activity.defn(name="ingest.persist_malware_verdict")
    async def persist(v: MalwareVerdict) -> None:
        await svc.persist_verdict(uuid.UUID(v.tenant_id), uuid.UUID(v.sample_id), {
            "verdict": v.verdict, "mime_detected": v.mime_detected,
            "clamav_result": v.clamav_result, "clamav_signature": v.clamav_signature,
            "yara_matches": v.yara_matches, "archive_info": v.archive_info, "error": v.error},
            f"malware-{v.sample_id}")

    worker = Worker(svc.temporal, task_queue=settings.ingest_task_queue, activities=[persist])
    asyncio.create_task(worker.run())
    return worker
