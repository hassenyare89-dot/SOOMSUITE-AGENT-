from platform_core.config import BaseServiceSettings


class Settings(BaseServiceSettings):
    service_name: str = "approvals"
    expiry_sweep_seconds: float = 30.0
