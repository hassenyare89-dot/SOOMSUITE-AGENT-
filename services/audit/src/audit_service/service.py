from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

import httpx
from sqlalchemy import select, text

from audit_service.chain import GENESIS, entry_hash
from platform_core.audit import AuditEvent
from platform_core.db.engine import Database
from platform_core.db.models import AuditLog
from platform_core.observability import instruments
from platform_core.security.redaction import redact

log = logging.getLogger(__name__)


class SiemForwarder:
    """Best-effort async forwarding (the database remains the system of record)."""

    def __init__(self, url: str | None, key: bytes | None, queue_size: int) -> None:
        self.url, self.key = url, key
        self.queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=queue_size)
        self.dropped = 0

    def submit(self, record: dict[str, Any]) -> None:
        if not self.url:
            return
        try:
            self.queue.put_nowait(record)
        except asyncio.QueueFull:
            self.dropped += 1

    async def run(self, stop: asyncio.Event) -> None:
        if not self.url:
            return
        async with httpx.AsyncClient(timeout=10) as client:
            while not stop.is_set():
                try:
                    record = await asyncio.wait_for(self.queue.get(), timeout=1)
                except TimeoutError:
                    continue
                body = json.dumps(record, default=str).encode()
                headers = {"Content-Type": "application/json"}
                if self.key:
                    headers["X-Signature-SHA256"] = hmac.new(self.key, body,
                                                             hashlib.sha256).hexdigest()
                for attempt in range(3):
                    try:
                        resp = await client.post(self.url, content=body, headers=headers)
                        if resp.status_code < 500:
                            break
                    except httpx.HTTPError:
                        pass
                    await asyncio.sleep(2**attempt)


class AuditStore:
    def __init__(self, db: Database, forwarder: SiemForwarder) -> None:
        self.db = db
        self.forwarder = forwarder

    async def append(self, event: AuditEvent, *, writer: str) -> AuditLog:
        async with self.db.tenant_session(event.tenant_id, actor=f"service:{writer}") as s:
            await s.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:k, 0))"),
                            {"k": f"audit:{event.tenant_id}"})
            last = (await s.execute(select(AuditLog.seq, AuditLog.entry_hash)
                                    .order_by(AuditLog.seq.desc()).limit(1))).first()
            seq, prev = (last[0] + 1, last[1]) if last else (1, GENESIS)
            entry = {
                "tenant_id": event.tenant_id, "seq": seq, "actor_type": event.actor_type,
                "actor_id": event.actor_id[:256], "agent_name": event.agent_name,
                "agent_run_id": event.agent_run_id,
                # The writing service is taken from the authenticated caller, not the body.
                "service": writer, "tool_name": event.tool_name, "action": event.action,
                "target_type": event.target_type, "target_id": event.target_id,
                "request_id": event.request_id[:128], "source_ip": event.source_ip,
                "result": event.result, "risk_level": event.risk_level,
                "approval_id": event.approval_id,
                "metadata_redacted": redact(event.metadata_redacted, mask_pii=True),
                "created_at": datetime.now(UTC).replace(microsecond=0),
            }
            row = AuditLog(id=uuid.uuid4(), prev_hash=prev, entry_hash=entry_hash(prev, entry),
                           **entry)
            s.add(row)
        instruments().audit_writes.add(1, {"service": writer, "result": event.result})
        self.forwarder.submit({k: v for k, v in entry.items()} | {"entry_hash": row.entry_hash})
        return row

    async def verify(self, tenant_id: uuid.UUID) -> dict[str, Any]:
        async with self.db.tenant_session(tenant_id) as s:
            rows = (await s.scalars(select(AuditLog).order_by(AuditLog.seq))).all()
        prev, expected_seq = GENESIS, 1
        for r in rows:
            entry = {k: getattr(r, k) for k in (
                "tenant_id", "seq", "actor_type", "actor_id", "agent_name", "agent_run_id",
                "service", "tool_name", "action", "target_type", "target_id", "request_id",
                "source_ip", "result", "risk_level", "approval_id", "metadata_redacted",
                "created_at")}
            entry["created_at"] = r.created_at.astimezone(UTC)
            if r.seq != expected_seq or r.prev_hash != prev or r.entry_hash != entry_hash(prev, entry):
                return {"valid": False, "broken_at_seq": r.seq, "entries": len(rows)}
            prev, expected_seq = r.entry_hash, expected_seq + 1
        return {"valid": True, "entries": len(rows), "head": prev}
