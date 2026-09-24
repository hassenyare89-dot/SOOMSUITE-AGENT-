from platform_core.config import BaseServiceSettings, EncryptionSettingsMixin


class Settings(EncryptionSettingsMixin, BaseServiceSettings):
    service_name: str = "notifications"
    crm_url: str | None = "http://crm:8000"
    whatsapp_url: str | None = "http://whatsapp:8000"
    smtp_host: str = "mailpit"
    smtp_port: int = 1025
    smtp_username_ref: str | None = None
    smtp_password_ref: str | None = None
    smtp_starttls: bool = False
    smtp_use_tls: bool = False
    email_from: str = "SAMIIR <no-reply@example.com>"
    security_slack_webhook_ref: str | None = None
    worker_poll_seconds: float = 2.0
    worker_batch: int = 50
    max_attempts: int = 5
    run_worker: bool = True
