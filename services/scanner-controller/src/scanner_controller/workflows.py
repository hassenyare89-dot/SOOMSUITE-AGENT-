"""Temporal integration: workflow starter and persistence activities (DB access lives here,
never in the scanner worker)."""

from __future__ import annotations

import asyncio
import dataclasses
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from platform_core.app import ServiceRuntime
from platform_core.security.principal import Principal

log = logging.getLogger(__name__)


async def setup_temporal(rt: ServiceRuntime, address: str, namespace: str, queue: str) -> Any:
    from temporalio import activity
    from temporalio.client import Client
    from temporalio.worker import Worker

    from platform_core.workflows.scan import ScanWorkflow
    from platform_core.workflows.types import ScanInput, ScannerRun, ScanStatusUpdate

    client = await Client.connect(address, namespace=namespace)

    async def start(job: Any, host: str, tenant_id: uuid.UUID) -> None:
        delay = None
        if job.scheduled_for and job.scheduled_for > datetime.now(UTC):
            delay = job.scheduled_for - datetime.now(UTC)
        await client.start_workflow(
            ScanWorkflow.run,
            ScanInput(str(job.id), str(tenant_id),
                      job.target_url, host, job.profile, list(job.scanners), job.timeout_seconds),
            id=job.workflow_id, task_queue=queue, start_delay=delay)

    async def cancel(workflow_id: str) -> None:
        try:
            await client.get_workflow_handle(workflow_id).cancel()
        except Exception:
            log.warning("workflow cancel failed", exc_info=True)

    @activity.defn(name="controller.update_scan_status")
    async def update_status(u: ScanStatusUpdate) -> None:
        async with rt.require_db().tenant_session(uuid.UUID(u.tenant_id),
                                                  actor="service:scanner-controller") as s:
            await rt.extras["scans"].set_status(s, uuid.UUID(u.scan_job_id), u.status, u.error)
        await rt.realtime.publish(uuid.UUID(u.tenant_id), "fatma", "scan.updated",
                                  {"scan_id": u.scan_job_id, "status": u.status})

    @activity.defn(name="controller.persist_findings")
    async def persist(inp: ScanInput, runs: list[ScannerRun]) -> int:
        tenant = uuid.UUID(inp.tenant_id)
        async with rt.require_db().tenant_session(tenant, actor="service:scanner-controller") as s:
            count = await rt.extras["scans"].persist_findings(
                s, tenant, uuid.UUID(inp.scan_job_id), [dataclasses.asdict(r) for r in runs])
        await notify_fatma(rt, tenant, uuid.UUID(inp.scan_job_id))
        return count

    worker = Worker(client, task_queue=queue, activities=[update_status, persist],
                    workflows=[ScanWorkflow])
    task = asyncio.create_task(worker.run())
    rt.extras.update(start_workflow=start, cancel_workflow=cancel, temporal_worker=worker,
                     temporal_task=task)
    return worker


async def notify_fatma(rt: ServiceRuntime, tenant_id: uuid.UUID, job_id: uuid.UUID) -> None:
    if "fatma-soc" not in rt.clients:
        return
    try:
        await rt.client("fatma-soc").post("/internal/findings/ingested",
                                          principal=Principal.system(tenant_id,
                                                                     "scanner-controller"),
                                          request_id=f"scan-{job_id}",
                                          json={"scan_job_id": str(job_id)})
    except Exception:
        log.warning("FATMA notification failed", exc_info=True)
