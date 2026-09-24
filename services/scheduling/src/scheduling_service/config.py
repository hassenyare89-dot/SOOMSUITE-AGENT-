from platform_core.config import BaseServiceSettings


class Settings(BaseServiceSettings):
    service_name: str = "scheduling"
    crm_url: str | None = "http://crm:8000"
    notifications_url: str | None = "http://notifications:8000"
    slot_token_key_ref: str | None = "env://SLOT_TOKEN_KEY"
    slot_offer_ttl_seconds: int = 1800
