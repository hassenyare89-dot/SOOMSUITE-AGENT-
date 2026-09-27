"""Normalized security-event schema shared by ingestion, FATMA and the dashboard.

Raw events never travel beyond security-ingest: only this normalized, redacted form does.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field, field_validator


class EventCategory(StrEnum):
    WEB_ATTACK = "web_attack"
    XSS = "xss"
    SQL_INJECTION = "sql_injection"
    PATH_TRAVERSAL = "path_traversal"
    CREDENTIAL_ATTACK = "credential_attack"
    AUTH_ANOMALY = "auth_anomaly"
    BOT = "bot"
    DDOS = "ddos"
    RATE_ANOMALY = "rate_anomaly"
    MALWARE = "malware"
    VULNERABILITY = "vulnerability"
    MISCONFIGURATION = "misconfiguration"
    EXPOSURE = "exposure"
    WAF_BLOCK = "waf_block"
    DATA_EXFILTRATION = "data_exfiltration"
    INFO = "info"


class NormalizedEvent(BaseModel):
    event_id: UUID
    tenant_id: UUID
    asset_id: UUID | None = None
    source: str = Field(max_length=64)
    event_type: str = Field(max_length=128)
    category: EventCategory = EventCategory.INFO
    severity: int = Field(ge=0, le=10)
    confidence: float = Field(ge=0, le=1)
    timestamp: datetime
    src_ip: str | None = None
    destination: str | None = Field(default=None, max_length=255)
    request_path: str | None = Field(default=None, max_length=2048)
    http_method: str | None = Field(default=None, max_length=16)
    status_code: int | None = Field(default=None, ge=100, le=599)
    user_id: str | None = Field(default=None, max_length=128)
    country: str | None = Field(default=None, pattern="^[A-Z]{2}$")
    user_agent: str | None = Field(default=None, max_length=512)
    signature: str | None = Field(default=None, max_length=256)
    rule_id: str | None = Field(default=None, max_length=128)
    action_taken: str | None = Field(default=None, max_length=32)
    metadata_redacted: dict[str, Any] = Field(default_factory=dict)
    raw_event_reference: str | None = Field(default=None, max_length=512)
    dedupe_key: str = Field(pattern="^[0-9a-f]{64}$")

    @field_validator("src_ip")
    @classmethod
    def _ip(cls, v: str | None) -> str | None:
        if v is None:
            return None
        return str(ipaddress.ip_address(v.strip()))


class EventForAnalysis(BaseModel):
    """What FATMA's model may see about an event: no raw payloads, no user identifiers."""

    event_id: UUID
    source: str
    category: str
    event_type: str
    severity: int
    confidence: float
    timestamp: datetime
    src_ip: str | None
    request_path: str | None
    http_method: str | None
    status_code: int | None
    country: str | None
    rule_id: str | None
    action_taken: str | None
