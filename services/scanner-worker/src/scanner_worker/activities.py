"""Temporal activities executed inside the isolated worker."""

from __future__ import annotations

import json
import os
import tempfile
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from temporalio import activity
from temporalio.exceptions import ApplicationError

from platform_core.security.ssrf import resolve_public, validate_hostname
from platform_core.workflows.types import MalwareInput, MalwareVerdict, ScanInput, ScannerRun
from scanner_worker import runner
from scanner_worker.parsers import parse_nuclei, parse_zap
from scanner_worker.profiles import PROFILES, nuclei_args, zap_plan


async def _check_target(inp: ScanInput) -> str:
    """Defence in depth: the worker re-validates the approved target itself."""
    parts = urlsplit(inp.target_url)
    host = validate_hostname(parts.hostname or "")
    if parts.scheme != "https" or host != inp.target_host or parts.username:
        raise ApplicationError("target does not match the approved asset", type="TargetNotAllowed",
                               non_retryable=True)
    try:
        await resolve_public(host)
    except Exception as exc:
        raise ApplicationError("target does not resolve to a public address",
                               type="TargetNotAllowed", non_retryable=True) from exc
    if inp.profile not in PROFILES:
        raise ApplicationError("unknown scan profile", type="TargetNotAllowed", non_retryable=True)
    return host


@activity.defn(name="scanner.run_nuclei")
async def run_nuclei(inp: ScanInput) -> ScannerRun:
    host = await _check_target(inp)
    profile = PROFILES[inp.profile]
    with tempfile.TemporaryDirectory(prefix="nuclei-") as tmp:
        out = os.path.join(tmp, "results.jsonl")
        info = activity.info()
        timeout = max(30.0, (info.start_to_close_timeout.total_seconds()
                             if info.start_to_close_timeout else 1800) - 30)
        result = await runner.run(nuclei_args(profile, inp.target_url, out), cwd=tmp,
                                  timeout=timeout, heartbeat=activity.heartbeat)
        data = Path(out).read_text()[:20_000_000] if os.path.exists(out) else ""
    findings = parse_nuclei(data, host)
    status = "timed_out" if result.timed_out else "ok" if result.returncode == 0 else "error"
    return ScannerRun("nuclei", status, findings,
                      [f"nuclei exit={result.returncode} findings={len(findings)}"],
                      None if status == "ok" else result.stdout_tail[-500:])


@activity.defn(name="scanner.run_zap")
async def run_zap(inp: ScanInput) -> ScannerRun:
    import yaml

    host = await _check_target(inp)
    profile = PROFILES[inp.profile]
    with tempfile.TemporaryDirectory(prefix="zap-") as tmp:
        plan_path = os.path.join(tmp, "plan.yaml")
        Path(plan_path).write_text(yaml.safe_dump(zap_plan(profile, inp.target_url, tmp)))
        timeout = (profile.zap_spider_minutes + profile.zap_passive_minutes + 5) * 60
        result = await runner.run(["zap.sh", "-cmd", "-autorun", plan_path, "-config",
                                   "api.disablekey=false", "-config", "api.addrs.addr.name=127.0.0.1"],
                                  cwd=tmp, timeout=timeout, heartbeat=activity.heartbeat)
        report_path = Path(tmp) / "zap-report.json"
        report = json.loads(report_path.read_text()) if report_path.exists() else {}
    findings = parse_zap(report, host)
    status = "timed_out" if result.timed_out else "ok" if report else "error"
    return ScannerRun("zap", status, findings,
                      [f"zap exit={result.returncode} findings={len(findings)}"],
                      None if status == "ok" else result.stdout_tail[-500:])


def make_malware_activity(quarantine, yara, clamd):  # noqa: ANN001, ANN201
    @activity.defn(name="malware.analyze")
    async def analyze_sample(inp: MalwareInput) -> MalwareVerdict:
        from scanner_worker.malware import analyze

        try:
            data = await quarantine.get(inp.storage_ref, uuid.UUID(inp.sample_id))
            r = await analyze(data, declared_mime=inp.declared_mime, yara=yara, clamd=clamd)
        except Exception as exc:
            return MalwareVerdict(inp.tenant_id, inp.sample_id, "error", error=type(exc).__name__)
        return MalwareVerdict(inp.tenant_id, inp.sample_id, r["verdict"], r["mime_detected"],
                              r["clamav_result"], r["clamav_signature"], r["yara_matches"],
                              r["archive_info"])

    return analyze_sample
