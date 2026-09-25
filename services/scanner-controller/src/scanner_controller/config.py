from platform_core.config import BaseServiceSettings


class Settings(BaseServiceSettings):
    service_name: str = "scanner-controller"
    approvals_url: str | None = "http://approvals:8000"
    fatma_url: str | None = "http://fatma-soc:8000"
    temporal_address: str | None = None
    temporal_namespace: str = "default"
    controller_task_queue: str = "scanner-controller"
    max_scans_per_day: int = 10
    max_concurrent_scans: int = 2
    verification_validity_days: int = 90
    default_scanners: list[str] = ["nuclei", "zap"]
