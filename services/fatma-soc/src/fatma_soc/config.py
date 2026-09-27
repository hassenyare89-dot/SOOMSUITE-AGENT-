from pydantic import Field

from platform_core.config import BaseServiceSettings


class Settings(BaseServiceSettings):
    service_name: str = "fatma-soc"
    approvals_url: str | None = "http://approvals:8000"
    notifications_url: str | None = "http://notifications:8000"
    scanner_controller_url: str | None = "http://scanner-controller:8000"
    console_base_url: str = "http://localhost:3000"
    openai_api_key_ref: str | None = "env://FATMA_OPENAI_API_KEY"
    openai_model: str = "gpt-5.5"
    openai_tracing_enabled: bool = False
    llm_min_risk_score: int = Field(50, ge=0, le=100)
    sweep_seconds: float = 30.0
    run_background: bool = True
