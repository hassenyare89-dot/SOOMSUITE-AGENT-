
from platform_core.config import BaseServiceSettings, EncryptionSettingsMixin


class Settings(EncryptionSettingsMixin, BaseServiceSettings):
    service_name: str = "samiir-agent"
    knowledge_url: str | None = "http://knowledge:8000"
    crm_url: str | None = "http://crm:8000"
    scheduling_url: str | None = "http://scheduling:8000"
    notifications_url: str | None = "http://notifications:8000"
    whatsapp_url: str | None = "http://whatsapp:8000"
    # Model configuration. Without an API key SAMIIR runs its deterministic runtime.
    openai_api_key_ref: str | None = "env://SAMIIR_OPENAI_API_KEY"
    openai_model: str = "gpt-5.4-mini"
    openai_tracing_enabled: bool = False
    max_turns: int = 8
    history_messages: int = 12
    default_appointment_type: str = "consultation"
    per_conversation_messages_per_minute: int = 12
