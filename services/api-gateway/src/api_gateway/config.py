from typing import Literal

from pydantic import model_validator

from platform_core.config import BaseServiceSettings, EncryptionSettingsMixin


class Settings(EncryptionSettingsMixin, BaseServiceSettings):
    service_name: str = "api-gateway-public"
    gateway_mode: Literal["public", "admin"] = "public"
    # Browser-facing origins (CORS allowlist) — the console / widget host.
    allowed_origins: list[str] = ["http://localhost:3000"]
    trusted_proxy_cidrs: list[str] = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                                      "127.0.0.1/32"]
    cookie_secure: bool = True
    csrf_key_ref: str | None = "env://CSRF_KEY"

    # downstream services
    samiir_url: str | None = "http://samiir-agent:8000"
    whatsapp_url: str | None = "http://whatsapp:8000"
    security_ingest_url: str | None = "http://security-ingest:8000"
    crm_url: str | None = "http://crm:8000"
    scheduling_url: str | None = "http://scheduling:8000"
    knowledge_url: str | None = "http://knowledge:8000"
    notifications_url: str | None = "http://notifications:8000"
    fatma_url: str | None = "http://fatma-soc:8000"
    scanner_controller_url: str | None = "http://scanner-controller:8000"
    approvals_url: str | None = "http://approvals:8000"
    audit_read_url: str | None = "http://audit:8000"

    # widget
    widget_session_ttl_seconds: int = 86_400
    widget_messages_per_minute: int = 10
    widget_ip_requests_per_minute: int = 60
    widget_tenant_messages_per_minute: int = 600

    # admin SSO (OIDC authorization code + PKCE)
    oidc_issuer: str | None = None
    oidc_client_id: str | None = None
    oidc_client_secret_ref: str | None = None
    oidc_authorize_url: str | None = None
    oidc_token_url: str | None = None
    oidc_jwks_url: str | None = None
    oidc_redirect_uri: str = "http://localhost:3000/api/admin/auth/callback"
    oidc_scopes: str = "openid profile email"
    require_mfa: bool = True
    admin_session_idle_seconds: int = 1800
    admin_session_absolute_seconds: int = 8 * 3600
    admin_requests_per_minute: int = 300
    dev_login_enabled: bool = False
    post_login_redirect: str = "http://localhost:3000/"

    @model_validator(mode="after")
    def _mode_guards(self) -> "Settings":
        if self.is_production_like and self.dev_login_enabled:
            raise ValueError("dev login can never be enabled outside development")
        if self.is_production_like and not self.cookie_secure:
            raise ValueError("secure cookies are mandatory outside development")
        if self.gateway_mode == "admin" and self.is_production_like and not self.oidc_issuer:
            raise ValueError("OIDC configuration is mandatory for the admin gateway")
        return self
