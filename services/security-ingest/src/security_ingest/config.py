from pathlib import Path

from platform_core.config import BaseServiceSettings


class Settings(BaseServiceSettings):
    service_name: str = "security-ingest"
    fatma_url: str | None = "http://fatma-soc:8000"
    raw_store_path: Path = Path("/var/lib/security-ingest/raw")
    quarantine_path: Path = Path("/var/lib/quarantine")
    quarantine_key_ref: str | None = "env://QUARANTINE_KEY"
    pseudonym_key_ref: str | None = "env://PSEUDONYM_KEY"
    max_webhook_bytes: int = 5 * 1024 * 1024
    max_decompressed_bytes: int = 50 * 1024 * 1024
    max_events_per_batch: int = 5000
    signature_tolerance_seconds: int = 300
    max_upload_bytes: int = 25 * 1024 * 1024
    temporal_address: str | None = None
    temporal_namespace: str = "default"
    malware_task_queue: str = "malware-analysis"
    ingest_task_queue: str = "security-ingest"
    clamd_host: str | None = None
    clamd_port: int = 3310
