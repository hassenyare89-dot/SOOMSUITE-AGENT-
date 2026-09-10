from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator


class Role(StrEnum):
    ANONYMOUS_CUSTOMER = "anonymous_customer"
    AUTHENTICATED_CUSTOMER = "authenticated_customer"
    SALES_AGENT = "sales_agent"
    SUPPORT_AGENT = "support_agent"
    SECURITY_ANALYST = "security_analyst"
    SECURITY_ENGINEER = "security_engineer"
    TENANT_ADMIN = "tenant_admin"
    PLATFORM_ADMIN = "platform_admin"
    SYSTEM_SERVICE = "system_service"


class AgentName(StrEnum):
    SAMIIR = "SAMIIR"
    FATMA = "FATMA"


class Risk(StrEnum):
    NORMAL = "NORMAL"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH RISK"
    CRITICAL = "CRITICAL"


class IncidentClaim(StrEnum):
    SUSPECTED = "SUSPECTED INCIDENT"
    CONFIRMED = "CONFIRMED INCIDENT"


class Principal(BaseModel):
    subject: str
    tenant_id: UUID
    roles: frozenset[Role]
    permissions: frozenset[str] = frozenset()


class ChatRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    message: str = Field(min_length=1, max_length=4000)
    conversation_id: UUID | None = None


class ChatResponse(BaseModel):
    conversation_id: UUID
    answer: str
    escalated: bool = False
    sources: list[str] = []


class SecurityEventIn(BaseModel):
    event_id: UUID
    tenant_id: UUID
    asset_id: UUID
    source: str = Field(max_length=64)
    event_type: str = Field(max_length=128)
    severity: int = Field(ge=0, le=10)
    confidence: float = Field(ge=0, le=1)
    timestamp: datetime
    src_ip: str | None = None
    destination: str | None = None
    request_path: str | None = None
    user_id: str | None = None
    country: str | None = None
    user_agent: str | None = None
    signature: str | None = None
    rule_id: str | None = None
    metadata_redacted: dict[str, Any] = {}
    raw_event_reference: str | None = None


class ScanRequest(BaseModel):
    asset_id: UUID
    target: HttpUrl
    authorization_ticket: str = Field(min_length=4, max_length=128)
    approval_id: UUID
    profile: str = Field(pattern="^(safe-passive|safe-standard)$")
    idempotency_key: str = Field(min_length=16, max_length=128)

    @field_validator("target")
    @classmethod
    def no_local_target(cls, v: HttpUrl) -> HttpUrl:
        host = (v.host or "").lower()
        if host in {"localhost", "127.0.0.1", "::1"} or host.endswith(".local"):
            raise ValueError("private/local scan targets are forbidden")
        return v
