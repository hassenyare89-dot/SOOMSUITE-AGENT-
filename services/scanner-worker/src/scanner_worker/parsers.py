"""Scanner output → normalized findings (evidence redacted and truncated)."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from platform_core.security.redaction import redact, redact_url

ZAP_RISK = {0: "info", 1: "low", 2: "medium", 3: "high"}
NUCLEI_SEV = {"info", "low", "medium", "high", "critical", "unknown"}
CATEGORY_HINTS = {"misconfig": "misconfiguration", "exposure": "exposure", "ssl": "misconfiguration",
                  "headers": "misconfiguration", "tech": "exposure", "cve": "vulnerability"}


def fingerprint(*parts: Any) -> str:
    return hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()


def parse_nuclei(jsonl: str, host: str, limit: int = 2000) -> list[dict[str, Any]]:
    findings = []
    for line in jsonl.splitlines()[:limit]:
        try:
            r = json.loads(line)
        except ValueError:
            continue
        info = r.get("info", {}) or {}
        sev = str(info.get("severity", "info")).lower()
        tags = info.get("tags") or []
        if isinstance(tags, str):
            tags = tags.split(",")
        category = next((CATEGORY_HINTS[t] for t in tags if t in CATEGORY_HINTS), "vulnerability")
        url = redact_url(str(r.get("matched-at") or r.get("host") or ""))[:1000]
        classification = info.get("classification") or {}
        cwe = classification.get("cwe-id")
        findings.append({
            "scanner": "nuclei", "rule_id": str(r.get("template-id", "unknown"))[:128],
            "title": str(info.get("name", "Nuclei finding"))[:300],
            "description": str(info.get("description", ""))[:2000],
            "severity": sev if sev in NUCLEI_SEV - {"unknown"} else "info",
            "category": category, "url": url,
            "cwe": (cwe[0] if isinstance(cwe, list) and cwe else cwe),
            "remediation": str(info.get("remediation", ""))[:2000] or None,
            "evidence": redact({"matcher": r.get("matcher-name"),
                                "extracted": (r.get("extracted-results") or [])[:5],
                                "type": r.get("type")}),
            "fingerprint": fingerprint("nuclei", host, r.get("template-id"), url,
                                       r.get("matcher-name")),
        })
    return findings


def parse_zap(report: dict[str, Any], host: str, limit: int = 2000) -> list[dict[str, Any]]:
    findings = []
    for site in report.get("site", [])[:20]:
        for alert in site.get("alerts", [])[:limit]:
            risk = int(alert.get("riskcode", 0) or 0)
            instances = alert.get("instances", []) or []
            url = redact_url(str(instances[0].get("uri", "")) if instances else "")[:1000]
            findings.append({
                "scanner": "zap", "rule_id": f"zap-{alert.get('pluginid', 'unknown')}",
                "title": str(alert.get("alert") or alert.get("name") or "ZAP alert")[:300],
                "description": _strip_html(str(alert.get("desc", "")))[:2000],
                "severity": ZAP_RISK.get(risk, "info"), "category": "misconfiguration"
                if risk <= 1 else "vulnerability", "url": url,
                "cwe": f"CWE-{alert['cweid']}" if str(alert.get("cweid", "")) not in ("", "-1", "0")
                else None,
                "remediation": _strip_html(str(alert.get("solution", "")))[:2000] or None,
                "evidence": redact({"instances": len(instances),
                                    "confidence": alert.get("confidence")}),
                "fingerprint": fingerprint("zap", host, alert.get("pluginid"), url),
            })
    return findings


def _strip_html(value: str) -> str:
    import re

    return re.sub(r"<[^>]{0,200}>", "", value).strip()
