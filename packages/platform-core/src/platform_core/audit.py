"""Audit event emission. Privileged actions must be audited or they must not happen:
``AuditClient.record`` raises if the audit service cannot durably accept the event."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any, Literal, Protocol
from uuid import UUID

from pydantic import BaseModel, Field

from platform_core.security.redaction import redact
from platform_core.security.service_auth import RequestContext

log = logging.getLogger(__name__)

AuditResult = Literal["success", "denied", "failure", "pending"]


class AuditEvent(BaseModel):
    tenant_id: UUID
    actor_type: str
    actor_id: str
    agent_name: str | None = None
    agent_run_id: UUID | None = None
    service: str
    tool_name: str | None = None
    action: str = Field(max_length=128)
    target_type: str | None = None
    target_id: str | None = None
    request_id: str
    source_ip: str | None = None
    result: AuditResult
    risk_level: str | None = None
    approval_id: UUID | None = None
    metadata_redacted: dict[str, Any] = Field(default_factory=dict)
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class AuditSink(Protocol):
    async def write(self, event: AuditEvent) -> None: ...


class AuditClient:
    def __init__(self, service: str, sink: AuditSink) -> None:
        self.service = service
        self._sink = sink

    async def record(
        self,
        ctx: RequestContext,
        *,
        action: str,
        result: AuditResult,
        target_type: str | None = None,
        target_id: str | UUID | None = None,
        tool_name: str | None = None,
        agent_name: str | None = None,
        risk_level: str | None = None,
        approval_id: UUID | None = None,
        metadata: dict[str, Any] | None = None,
        tenant_id: UUID | None = None,
    ) -> None:
        event = AuditEvent(
            tenant_id=tenant_id or ctx.tenant_id,
            actor_type=ctx.principal.actor_type.value,
            actor_id=ctx.principal.subject,
            agent_name=agent_name,
            agent_run_id=ctx.agent_run_id,
            service=self.service,
            tool_name=tool_name,
            action=action,
            target_type=target_type,
            target_id=str(target_id) if target_id else None,
            request_id=ctx.request_id,
            source_ip=ctx.source_ip,
            result=result,
            risk_level=risk_level,
            approval_id=approval_id,
            metadata_redacted=redact(metadata or {}, mask_pii=True),
        )
        await self._sink.write(event)


class HttpAuditSink:
    """Writes to the audit service (which owns the hash chain and SIEM forwarding)."""

    def __init__(self, client: Any, service_name: str) -> None:  # ServiceClient("audit")
        self._client = client
        self._service = service_name

    async def write(self, event: AuditEvent) -> None:
        from platform_core.security.principal import Principal

        principal = Principal.system(event.tenant_id, self._service)
        await self._client.post("/internal/audit/events", principal=principal,
                                request_id=event.request_id,
                                json=event.model_dump(mode="json"), retries=2)


class MemoryAuditSink:
    """Test/dev sink."""

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    async def write(self, event: AuditEvent) -> None:
        self.events.append(event)
