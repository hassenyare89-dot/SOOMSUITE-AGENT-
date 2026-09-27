"""Typed service configuration. Secrets are never given defaults."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(StrEnum):
    DEVELOPMENT = "development"
    TEST = "test"
    STAGING = "staging"
    PRODUCTION = "production"


class BaseServiceSettings(BaseSettings):
    """Settings common to every service. Each service subclasses and adds its own."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore", env_nested_delimiter="__")

    service_name: str
    environment: Environment = Environment.DEVELOPMENT
    log_level: str = "INFO"

    # Database: each service connects with its own least-privilege PostgreSQL role.
    database_url: SecretStr | None = None
    database_pool_size: int = Field(10, ge=1, le=100)
    database_statement_timeout_ms: int = Field(15_000, ge=100)

    redis_url: SecretStr | None = None

    # Service identity (Ed25519). The private key is mounted only into this service's pod.
    service_private_key_path: Path | None = None
    service_trust_bundle_path: Path | None = None
    service_token_ttl_seconds: int = Field(60, ge=10, le=300)

    # Optional client certificates for mTLS when a mesh is not used.
    mtls_cert_path: Path | None = None
    mtls_key_path: Path | None = None
    mtls_ca_path: Path | None = None

    # Downstream service URLs (only those a service actually needs are set in its env).
    audit_url: str | None = None

    otel_exporter_otlp_endpoint: str | None = None
    otel_service_namespace: str = "samiir-fatma"

    max_request_bytes: int = Field(1_048_576, ge=1024)

    @field_validator("log_level")
    @classmethod
    def _upper(cls, v: str) -> str:
        return v.upper()

    @property
    def is_production_like(self) -> bool:
        return self.environment in {Environment.STAGING, Environment.PRODUCTION}

    @model_validator(mode="after")
    def _production_guards(self) -> BaseServiceSettings:
        if self.is_production_like:
            if self.service_private_key_path is None or self.service_trust_bundle_path is None:
                raise ValueError("service identity keys are mandatory outside development")
        return self


class EncryptionSettingsMixin(BaseSettings):
    """For services that read or write encrypted PII fields."""

    field_keyring_ref: str | None = "env://FIELD_ENCRYPTION_KEYRING"
    blind_index_key_ref: str | None = "env://BLIND_INDEX_KEY"
