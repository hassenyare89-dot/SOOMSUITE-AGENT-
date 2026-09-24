from __future__ import annotations

import base64
import gzip
import json
import logging
import re
import uuid
import zlib
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.dialects.postgresql import insert

from platform_core.app import ServiceRuntime
from platform_core.db.models import MalwareResult, SecurityEvent
from platform_core.errors import NotFound, PayloadTooLarge, ValidationFailed
from platform_core.observability import instruments
from platform_core.schemas.security import NormalizedEvent
from platform_core.security.crypto import sha256_hex
from platform_core.security.files import detect_mime, hashes
from platform_core.security.principal import Principal
from platform_core.security.service_auth import ReplayCache
from platform_core.storage import ObjectStore, Quarantine, store_raw
from security_ingest import webhook_auth
from security_ingest.normalizers import NORMALIZERS, NormContext, normalize_all

log = logging.getLogger(__name__)
FILENAME_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def safe_decompress(body: bytes, encoding: str | None, limit: int) -> bytes:
    if encoding in ("gzip", "x-gzip") or body[:2] == b"\x1f\x8b":
        d = zlib.decompressobj(wbits=31)
        out = d.decompress(body, limit + 1)
        if len(out) > limit or d.unconsumed_tail:
            raise PayloadTooLarge("decompressed payload exceeds limit")
        return out
    return body


def parse_records(kind: str, body: bytes) -> tuple[list[dict[str, Any]], str | None]:
    """Returns records and, for Firehose, the requestId that must be echoed."""
    text_body = body.decode("utf-8", errors="strict")
    stripped = text_body.lstrip()
    if kind == "aws_waf":
        envelope = json.loads(text_body)
        records = []
        for r in envelope.get("records", [])[:10000]:
            decoded = base64.b64decode(r.get("data", ""), validate=True)
            for line in safe_decompress(decoded, None, 5 * 1024 * 1024).splitlines():
                if line.strip():
                    records.append(json.loads(line))
        return records, envelope.get("requestId")
    if stripped.startswith("["):
        return json.loads(stripped), None
    if stripped.startswith("{") and "\n" not in stripped.strip():
        obj = json.loads(stripped)
        return (obj.get("events") if isinstance(obj.get("events"), list) else [obj]), None
    return [json.loads(line) for line in text_body.splitlines() if line.strip()], None


class IngestService:
    def __init__(self, rt: ServiceRuntime, raw_store: ObjectStore, quarantine: Quarantine,
                 replay: ReplayCache, pseudonym_key: bytes, *, tolerance: int,
                 max_decompressed: int, max_events: int) -> None:
        self.rt = rt
        self.raw_store = raw_store
        self.quarantine = quarantine
        self.replay = replay
        self.pseudonym_key = pseudonym_key
        self.tolerance = tolerance
        self.max_decompressed = max_decompressed
        self.max_events = max_events
        self.temporal: Any = None
        self.inline_analyzer: Any = None

    async def _resolve(self, kind: str, key: str) -> tuple[uuid.UUID, str, dict[str, Any]]:
        async with self.rt.require_db().system_session() as s:
            row = (await s.execute(text("SELECT * FROM app_resolve_integration(:k, :e)"),
                                   {"k": f"ingest.{kind}", "e": key})).first()
        if row is None or not row.secret_ref:
            raise NotFound()
        return row.tenant_id, await self.rt.secrets.get(row.secret_ref), dict(row.config or {})

    async def ingest_webhook(self, kind: str, key: str, headers: dict[str, str], body: bytes,
                             request_id: str) -> dict[str, Any]:
        if kind not in NORMALIZERS:
            raise NotFound()
        tenant_id, secret, config = await self._resolve(kind, key)
        await webhook_auth.verify(kind, headers, body, secret, self.replay, self.tolerance)
        raw = safe_decompress(body, headers.get("content-encoding"), self.max_decompressed)
        try:
            records, firehose_id = parse_records(kind, raw)
        except (ValueError, UnicodeDecodeError) as exc:
            instruments().security_events_rejected.add(1, {"source": kind, "reason": "parse"})
            raise ValidationFailed("unparseable payload") from exc
        raw_ref = await store_raw(self.raw_store, tenant_id, kind, raw)
        asset_id = uuid.UUID(config["asset_id"]) if config.get("asset_id") else None
        ctx = NormContext(tenant_id=tenant_id, asset_id=asset_id, source=kind,
                          pseudonym_key=self.pseudonym_key, raw_reference=raw_ref)
        events, rejected = normalize_all(kind, records, ctx, self.max_events)
        inserted = await self.store_events(tenant_id, events)
        instruments().security_events.add(len(inserted), {"source": kind})
        if rejected:
            instruments().security_events_rejected.add(rejected, {"source": kind,
                                                                  "reason": "normalize"})
        await self.forward(tenant_id, inserted, request_id)
        result: dict[str, Any] = {"received": len(records), "stored": len(inserted),
                                  "duplicates": len(events) - len(inserted), "rejected": rejected}
        if firehose_id:  # Firehose requires the requestId and timestamp echoed back
            result = {"requestId": firehose_id, "timestamp": int(datetime.now(UTC).timestamp()
                                                                 * 1000)}
        return result

    async def store_events(self, tenant_id: uuid.UUID, events: list[NormalizedEvent]
                           ) -> list[uuid.UUID]:
        if not events:
            return []
        rows = []
        for e in events:
            row = e.model_dump()
            row["confidence"] = round(row["confidence"], 3)
            row["category"] = e.category.value
            rows.append(row)
        async with self.rt.require_db().tenant_session(tenant_id, actor="service:security-ingest"
                                                       ) as s:
            stmt = insert(SecurityEvent).values(rows).on_conflict_do_nothing(
                index_elements=["tenant_id", "dedupe_key"]).returning(SecurityEvent.event_id)
            return list((await s.scalars(stmt)).all())

    async def forward(self, tenant_id: uuid.UUID, event_ids: list[uuid.UUID],
                      request_id: str) -> None:
        if not event_ids or "fatma-soc" not in self.rt.clients:
            return
        system = Principal.system(tenant_id, "security-ingest")
        for i in range(0, len(event_ids), 1000):
            try:
                await self.rt.client("fatma-soc").post(
                    "/internal/events/ingested", principal=system, request_id=request_id,
                    json={"event_ids": [str(e) for e in event_ids[i:i + 1000]]})
            except Exception:
                # Events are durable in the DB; FATMA's periodic sweep will pick them up.
                log.warning("forwarding to FATMA failed", exc_info=True)

    # ------------------------------------------------------------------- malware
    async def submit_sample(self, tenant_id: uuid.UUID, *, data: bytes, filename: str,
                            declared_mime: str | None, asset_id: uuid.UUID | None,
                            submitted_by: str, request_id: str) -> MalwareResult:
        digests = hashes(data)
        detected = detect_mime(data)
        sample_id = uuid.uuid4()
        ref = await self.quarantine.put(tenant_id, sample_id, data)
        sample = MalwareResult(
            id=sample_id, tenant_id=tenant_id, asset_id=asset_id,
            filename_sanitized=sanitize_filename(filename), size_bytes=len(data),
            mime_declared=(declared_mime or "")[:100] or None, mime_detected=detected,
            verdict="pending", quarantine_status="QUARANTINED", storage_ref=ref,
            submitted_by=submitted_by, **digests)
        async with self.rt.require_db().tenant_session(tenant_id, actor=submitted_by) as s:
            s.add(sample)
        await self.start_analysis(tenant_id, sample, request_id)
        return sample

    async def start_analysis(self, tenant_id: uuid.UUID, sample: MalwareResult,
                             request_id: str) -> None:
        if self.temporal is not None:
            from platform_core.workflows.malware import MalwareAnalysisWorkflow
            from platform_core.workflows.types import MALWARE_QUEUE, MalwareInput

            await self.temporal.start_workflow(
                MalwareAnalysisWorkflow.run,
                MalwareInput(str(tenant_id), str(sample.id), sample.storage_ref,
                             sample.filename_sanitized, sample.mime_declared),
                id=f"malware-{sample.id}", task_queue=MALWARE_QUEUE)
        elif self.inline_analyzer is not None:
            # Development/test only: the analyzer never executes the sample.
            data = await self.quarantine.get(sample.storage_ref, sample.id)
            verdict = await self.inline_analyzer(data, sample.mime_declared)
            await self.persist_verdict(tenant_id, sample.id, verdict, request_id)

    async def persist_verdict(self, tenant_id: uuid.UUID, sample_id: uuid.UUID,
                              verdict: dict[str, Any], request_id: str) -> None:
        async with self.rt.require_db().tenant_session(tenant_id, actor="service:security-ingest"
                                                       ) as s:
            sample = await s.get(MalwareResult, sample_id)
            if sample is None:
                return
            sample.verdict = verdict["verdict"]
            sample.mime_detected = verdict.get("mime_detected")
            sample.clamav_result = verdict.get("clamav_result")
            sample.clamav_signature = verdict.get("clamav_signature")
            sample.yara_matches = verdict.get("yara_matches", [])
            sample.archive_info = verdict.get("archive_info", {})
            sample.error = verdict.get("error")
            sample.analyzed_at = datetime.now(UTC)
            sha, asset_id = sample.sha256, sample.asset_id
        ctx = NormContext(tenant_id=tenant_id, asset_id=asset_id, source="malware",
                          pseudonym_key=self.pseudonym_key)
        sig = verdict.get("clamav_signature") or next(
            (m["rule"] for m in verdict.get("yara_matches", [])), None)
        events, _ = normalize_all("malware", [{"sha256": sha, "verdict": verdict["verdict"],
                                               "signature": sig, "engine": "sandbox"}], ctx, 10)
        inserted = await self.store_events(tenant_id, events)
        await self.forward(tenant_id, inserted, request_id)


def sanitize_filename(name: str) -> str:
    base = name.replace("\\", "/").rsplit("/", 1)[-1]
    return (FILENAME_SAFE.sub("_", base).strip("._") or "sample")[:120]


def sample_key(sha256: str) -> str:
    return sha256_hex(sha256)[:16]


__all__ = ["IngestService", "gzip", "parse_records", "safe_decompress", "sanitize_filename"]
