from __future__ import annotations

from dataclasses import dataclass, field

SCANNER_QUEUE = "scanner"
MALWARE_QUEUE = "malware-analysis"
CONTROLLER_QUEUE = "scanner-controller"
INGEST_QUEUE = "security-ingest"


@dataclass
class ScanInput:
    scan_job_id: str
    tenant_id: str
    target_url: str
    target_host: str
    profile: str
    scanners: list[str]
    timeout_seconds: int


@dataclass
class ScannerRun:
    scanner: str
    status: str
    findings: list[dict] = field(default_factory=list)
    log: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass
class ScanStatusUpdate:
    scan_job_id: str
    tenant_id: str
    status: str
    error: str | None = None


@dataclass
class MalwareInput:
    tenant_id: str
    sample_id: str
    storage_ref: str
    filename: str
    declared_mime: str | None


@dataclass
class MalwareVerdict:
    tenant_id: str
    sample_id: str
    verdict: str
    mime_detected: str | None = None
    clamav_result: str | None = None
    clamav_signature: str | None = None
    yara_matches: list[dict] = field(default_factory=list)
    archive_info: dict = field(default_factory=dict)
    error: str | None = None
