from platform_core.config import BaseServiceSettings


class Settings(BaseServiceSettings):
    service_name: str = "audit"
    siem_webhook_url: str | None = None
    siem_hmac_key_ref: str | None = None
    siem_queue_size: int = 10_000
