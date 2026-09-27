"""Worker entrypoint: ``WORKER_ROLE=scanner`` or ``WORKER_ROLE=malware``."""

from __future__ import annotations

import asyncio
import base64
import logging
import os
from pathlib import Path

from temporalio.client import Client
from temporalio.worker import Worker

from platform_core.logs import configure_logging
from platform_core.workflows.types import MALWARE_QUEUE, SCANNER_QUEUE
from scanner_worker.activities import make_malware_activity, run_nuclei, run_zap

log = logging.getLogger(__name__)


async def main() -> None:
    role = os.environ.get("WORKER_ROLE", "scanner")
    configure_logging(f"{role}-worker", os.environ.get("LOG_LEVEL", "INFO"))
    client = await Client.connect(os.environ["TEMPORAL_ADDRESS"],
                                  namespace=os.environ.get("TEMPORAL_NAMESPACE", "default"))
    if role == "scanner":
        max_concurrent = int(os.environ.get("SCANNER_MAX_CONCURRENT", "2"))
        worker = Worker(client, task_queue=SCANNER_QUEUE, activities=[run_nuclei, run_zap],
                        max_concurrent_activities=max_concurrent)
    elif role == "malware":
        from platform_core.storage import FilesystemObjectStore, Quarantine
        from scanner_worker.malware import YaraEngine

        key = base64.b64decode(Path(os.environ["QUARANTINE_KEY_FILE"]).read_text().strip())
        quarantine = Quarantine(FilesystemObjectStore(Path(os.environ.get(
            "QUARANTINE_PATH", "/var/lib/quarantine"))), key)
        yara = YaraEngine(Path(os.environ.get("YARA_RULES_DIR",
                                              str(Path(__file__).parent / "rules"))))
        yara.load()
        clamd_host = os.environ.get("CLAMD_HOST")
        clamd = (clamd_host, int(os.environ.get("CLAMD_PORT", "3310"))) if clamd_host else None
        worker = Worker(client, task_queue=MALWARE_QUEUE,
                        activities=[make_malware_activity(quarantine, yara, clamd)],
                        max_concurrent_activities=int(os.environ.get("MALWARE_MAX_CONCURRENT", "4")))
    else:
        raise SystemExit(f"unknown WORKER_ROLE {role}")
    log.info("worker started", extra={"ctx": {"role": role}})
    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())
