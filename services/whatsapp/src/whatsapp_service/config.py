from platform_core.config import BaseServiceSettings


class Settings(BaseServiceSettings):
    service_name: str = "whatsapp"
    samiir_url: str | None = "http://samiir-agent:8000"
    notifications_url: str | None = "http://notifications:8000"
    meta_graph_base: str = "https://graph.facebook.com"
    meta_graph_version: str = "v23.0"
    meta_app_secret_ref: str = "env://META_APP_SECRET"
    meta_verify_token_ref: str = "env://META_VERIFY_TOKEN"
    template_language: str = "en"
    dedupe_ttl_seconds: int = 7 * 86400
    inbound_per_minute: int = 20
    max_concurrent_processing: int = 32
