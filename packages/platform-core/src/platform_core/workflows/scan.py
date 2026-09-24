from __future__ import annotations

import asyncio
from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import ActivityError

with workflow.unsafe.imports_passed_through():
    from platform_core.workflows.types import (
        CONTROLLER_QUEUE,
        SCANNER_QUEUE,
        ScanInput,
        ScannerRun,
        ScanStatusUpdate,
    )


@workflow.defn(name="ScanWorkflow")
class ScanWorkflow:
    """Runs approved scanners sequentially in isolated workers and persists normalized
    findings. Cancellation propagates to running scanner processes via heartbeats."""

    @workflow.run
    async def run(self, inp: ScanInput) -> str:
        async def status(value: str, error: str | None = None) -> None:
            await workflow.execute_activity(
                "controller.update_scan_status", ScanStatusUpdate(inp.scan_job_id, inp.tenant_id,
                                                                  value, error),
                task_queue=CONTROLLER_QUEUE, start_to_close_timeout=timedelta(seconds=30),
                retry_policy=RetryPolicy(maximum_attempts=5))

        await status("RUNNING")
        runs: list[ScannerRun] = []
        try:
            per_scanner = max(60, inp.timeout_seconds // max(1, len(inp.scanners)))
            for scanner in inp.scanners:
                result = await workflow.execute_activity(
                    f"scanner.run_{scanner}", inp, result_type=ScannerRun,
                    task_queue=SCANNER_QUEUE,
                    start_to_close_timeout=timedelta(seconds=per_scanner),
                    heartbeat_timeout=timedelta(seconds=90),
                    retry_policy=RetryPolicy(maximum_attempts=2,
                                             non_retryable_error_types=["TargetNotAllowed"]))
                runs.append(result)
            await workflow.execute_activity(
                "controller.persist_findings", args=[inp, runs], task_queue=CONTROLLER_QUEUE,
                start_to_close_timeout=timedelta(minutes=5),
                retry_policy=RetryPolicy(maximum_attempts=5))
        except asyncio.CancelledError:
            await asyncio.shield(asyncio.ensure_future(status("CANCELLED")))
            raise
        except ActivityError as exc:
            timed_out = "timeout" in str(exc.cause or exc).lower()
            await status("TIMED_OUT" if timed_out else "FAILED", str(exc.cause or exc)[:500])
            return "failed"
        return "succeeded"
