"""Source adapters: vendor-specific records → ``NormalizedEvent``.

Every adapter:
* extracts only the fields in the normalized schema (minimization),
* strips query-string secrets, cookies and auth headers (redaction),
* pseudonymizes user identifiers with a keyed hash,
* computes a stable ``dedupe_key`` so retried deliveries are idempotent.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from platform_core.schemas.security import EventCategory, NormalizedEvent
from platform_core.security.redaction import redact, redact_url
from security_ingest.signatures import classify_request


@dataclass(frozen=True)
class NormContext:
    tenant_id: uuid.UUID
    asset_id: uuid.UUID | None
    source: str
    pseudonym_key: bytes
    raw_reference: str | None = None

    def pseudonymize(self, value: str | None) -> str | None:
        if not value:
            return None
        digest = hmac.new(self.pseudonym_key, f"{self.tenant_id}:{value}".encode(), hashlib.sha256)
        return "u_" + digest.hexdigest()[:20]


def _ts(value: Any) -> datetime:
    if isinstance(value, int | float):
        seconds = value / 1000 if value > 1e11 else value
        if value > 1e17:  # nanoseconds (Cloudflare "unixnano")
            seconds = value / 1e9
        return datetime.fromtimestamp(seconds, UTC)
    if isinstance(value, str) and value:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
    return datetime.now(UTC)


def _dedupe(source: str, *parts: Any) -> str:
    return hashlib.sha256("|".join([source, *map(str, parts)]).encode()).hexdigest()


def _country(v: Any) -> str | None:
    s = str(v or "").upper()
    return s if len(s) == 2 and s.isalpha() and s not in ("XX", "T1") else None


def _event(ctx: NormContext, *, native_id: Any, event_type: str, category: EventCategory,
           severity: int, confidence: float, timestamp: datetime, **fields: Any) -> NormalizedEvent:
    path = fields.pop("request_path", None)
    ua = fields.pop("user_agent", None)
    return NormalizedEvent(
        event_id=uuid.uuid4(), tenant_id=ctx.tenant_id, asset_id=fields.pop("asset_id", None)
        or ctx.asset_id, source=ctx.source, event_type=event_type[:128], category=category,
        severity=max(0, min(10, int(severity))), confidence=max(0.0, min(1.0, float(confidence))),
        timestamp=timestamp, request_path=redact_url(path)[:2048] if path else None,
        user_agent=str(ua)[:512] if ua else None, raw_event_reference=ctx.raw_reference,
        dedupe_key=_dedupe(ctx.source, native_id, event_type, timestamp.isoformat()), **fields)


def _with_signatures(ctx: NormContext, base: dict[str, Any], path: str | None, query: str | None,
                     ua: str | None) -> list[NormalizedEvent]:
    """Emit one event per matched signature (or one INFO event when nothing matched)."""
    hits = classify_request(path, query, ua)
    events = []
    for cat, name, sev, conf in hits or [(base.pop("_default_category", EventCategory.INFO),
                                         base.get("_default_type", "http.request"),
                                         base.get("_default_severity", 1), 0.5)]:
        fields = {k: v for k, v in base.items() if not k.startswith("_")}
        ev = _event(ctx, native_id=f"{base.get('_native_id')}:{name}", event_type=name,
                    category=cat, severity=sev, confidence=conf,
                    timestamp=base["_timestamp"], request_path=path, **fields)
        ev.user_agent = (ua or "")[:512] or None
        events.append(ev)
    return events


# ------------------------------------------------------------------------ Cloudflare
_CF_SOURCE_CATEGORY = {
    "l7ddos": EventCategory.DDOS, "ratelimit": EventCategory.RATE_ANOMALY,
    "bic": EventCategory.BOT, "botfight": EventCategory.BOT, "botmanagement": EventCategory.BOT,
    "securitylevel": EventCategory.BOT, "firewallmanaged": EventCategory.WAF_BLOCK,
    "firewallcustom": EventCategory.WAF_BLOCK, "waf": EventCategory.WAF_BLOCK,
    "firewallrules": EventCategory.WAF_BLOCK, "hot": EventCategory.WAF_BLOCK,
}


def cloudflare(record: dict[str, Any], ctx: NormContext) -> list[NormalizedEvent]:
    """Cloudflare Logpush ``firewall_events`` dataset."""
    src = str(record.get("Source", "")).lower()
    action = str(record.get("Action", "")).lower()
    ts = _ts(record.get("Datetime"))
    path = record.get("ClientRequestPath")
    query = str(record.get("ClientRequestQuery", "")).lstrip("?")
    ua = record.get("ClientRequestUserAgent")
    category = _CF_SOURCE_CATEGORY.get(src, EventCategory.WAF_BLOCK)
    blocked = action in ("block", "drop", "managed_challenge", "challenge", "jschallenge")
    base = {"src_ip": record.get("ClientIP"), "destination": record.get("ClientRequestHost"),
            "http_method": record.get("ClientRequestMethod"),
            "country": _country(record.get("ClientCountry")),
            "rule_id": str(record.get("RuleID", ""))[:128] or None,
            "signature": str(record.get("Description", ""))[:256] or None,
            "action_taken": action[:32] or None,
            "metadata_redacted": redact({"ray_id": record.get("RayID"), "source": src,
                                         "kind": record.get("Kind")}),
            "_timestamp": ts, "_native_id": record.get("RayID") or record.get("Ref")}
    signed = _with_signatures(ctx, {**base, "_default_category": category,
                                    "_default_type": f"cloudflare.{src or 'firewall'}",
                                    "_default_severity": 6 if category is EventCategory.DDOS
                                    else 4 if blocked else 2},
                              path, query, ua)
    for ev in signed:
        if ev.category is EventCategory.INFO:
            ev.category = category
        ev.confidence = max(ev.confidence, 0.8 if blocked else 0.6)
    return signed


# --------------------------------------------------------------------------- AWS WAF
def aws_waf(record: dict[str, Any], ctx: NormContext) -> list[NormalizedEvent]:
    """AWS WAF v2 log record (delivered via Kinesis Data Firehose HTTP endpoint)."""
    req = record.get("httpRequest", {}) or {}
    action = str(record.get("action", "")).lower()
    rule = str(record.get("terminatingRuleId", "Default_Action"))
    labels = [lbl.get("name", "") for lbl in record.get("labels", []) or []]
    label_text = " ".join(labels).lower()
    category = (EventCategory.SQL_INJECTION if "sqli" in label_text or "sqli" in rule.lower()
                else EventCategory.XSS if "xss" in label_text or "crosssitescripting" in rule.lower()
                else EventCategory.BOT if "bot" in label_text
                else EventCategory.RATE_ANOMALY if record.get("terminatingRuleType") == "RATE_BASED"
                else EventCategory.WAF_BLOCK if action == "block" else EventCategory.INFO)
    headers = {h.get("name", "").lower(): h.get("value", "") for h in req.get("headers", []) or []}
    ts = _ts(record.get("timestamp"))
    base = {"src_ip": req.get("clientIp"), "destination": headers.get("host"),
            "http_method": req.get("httpMethod"), "country": _country(req.get("country")),
            "rule_id": rule[:128], "action_taken": action[:32] or None,
            "metadata_redacted": redact({"labels": labels[:20],
                                         "web_acl": str(record.get("webaclId", ""))[-80:]}),
            "_timestamp": ts, "_native_id": req.get("requestId") or record.get("timestamp")}
    events = _with_signatures(ctx, {**base, "_default_category": category,
                                    "_default_type": f"aws_waf.{action or 'log'}",
                                    "_default_severity": 5 if action == "block" else 1},
                              req.get("uri"), req.get("args"), headers.get("user-agent"))
    for ev in events:
        if ev.category is EventCategory.INFO:
            ev.category = category
        if action == "block":
            ev.confidence = max(ev.confidence, 0.8)
    return events


# ------------------------------------------------------------------ generic SIEM feed
def siem(record: dict[str, Any], ctx: NormContext) -> list[NormalizedEvent]:
    category = record.get("category", "info")
    try:
        cat = EventCategory(category)
    except ValueError:
        cat = EventCategory.INFO
    ts = _ts(record.get("timestamp"))
    ev = _event(ctx, native_id=record.get("id") or record.get("event_id") or json.dumps(
        record, sort_keys=True, default=str)[:512], event_type=str(record.get("event_type",
                                                                              "siem.alert")),
        category=cat, severity=int(record.get("severity", 5)),
        confidence=float(record.get("confidence", 0.6)), timestamp=ts,
        src_ip=record.get("src_ip"), destination=record.get("destination"),
        request_path=record.get("request_path"), country=_country(record.get("country")),
        user_id=ctx.pseudonymize(record.get("user_id")), rule_id=record.get("rule_id"),
        signature=str(record.get("signature", ""))[:256] or None,
        metadata_redacted=redact({k: v for k, v in (record.get("metadata") or {}).items()},
                                 mask_pii=True))
    ev.user_agent = str(record.get("user_agent", ""))[:512] or None
    return [ev]


# ------------------------------------------------------------ application / proxy logs
def app_log(record: dict[str, Any], ctx: NormContext) -> list[NormalizedEvent]:
    path = record.get("path") or record.get("url")
    query = None
    if path and "?" in str(path):
        path, query = str(path).split("?", 1)
    status = record.get("status")
    base = {"src_ip": record.get("ip") or record.get("remote_addr"),
            "http_method": record.get("method"),
            "status_code": int(status) if str(status or "").isdigit() else None,
            "user_id": ctx.pseudonymize(record.get("user_id")),
            "metadata_redacted": redact({"level": record.get("level"),
                                         "event": record.get("event")}),
            "_timestamp": _ts(record.get("timestamp") or record.get("time")),
            "_native_id": record.get("request_id") or json.dumps(record, sort_keys=True,
                                                                 default=str)[:512]}
    return _with_signatures(ctx, base, path, query, record.get("user_agent"))


def proxy_log(record: dict[str, Any], ctx: NormContext) -> list[NormalizedEvent]:
    """nginx/envoy JSON access log."""
    uri = str(record.get("request_uri") or record.get("path") or "")
    path, _, query = uri.partition("?")
    status = str(record.get("status", ""))
    base = {"src_ip": record.get("remote_addr") or record.get("client_ip"),
            "destination": record.get("host"), "http_method": record.get("request_method"),
            "status_code": int(status) if status.isdigit() else None,
            "metadata_redacted": {"bytes_sent": record.get("body_bytes_sent"),
                                  "request_time": record.get("request_time")},
            "_timestamp": _ts(record.get("time_iso8601") or record.get("timestamp")),
            "_native_id": record.get("request_id") or json.dumps(record, sort_keys=True,
                                                                 default=str)[:512]}
    return _with_signatures(ctx, base, path, query, record.get("http_user_agent"))


# ----------------------------------------------------------------- auth provider logs
_AUTH_EVENTS = {
    "login_failure": (EventCategory.CREDENTIAL_ATTACK, 3, 0.4),
    "mfa_failure": (EventCategory.AUTH_ANOMALY, 4, 0.5),
    "account_locked": (EventCategory.CREDENTIAL_ATTACK, 5, 0.6),
    "impossible_travel": (EventCategory.AUTH_ANOMALY, 7, 0.7),
    "new_device": (EventCategory.AUTH_ANOMALY, 2, 0.3),
    "password_reset": (EventCategory.AUTH_ANOMALY, 2, 0.3),
    "token_reuse": (EventCategory.AUTH_ANOMALY, 8, 0.8),
    "login_success": (EventCategory.INFO, 0, 0.9),
}


def auth(record: dict[str, Any], ctx: NormContext) -> list[NormalizedEvent]:
    kind = str(record.get("event", "")).lower()
    cat, sev, conf = _AUTH_EVENTS.get(kind, (EventCategory.INFO, 1, 0.3))
    ts = _ts(record.get("timestamp"))
    ev = _event(ctx, native_id=record.get("id") or f"{kind}:{record.get('user')}:{ts.isoformat()}",
                event_type=f"auth.{kind or 'event'}", category=cat, severity=sev, confidence=conf,
                timestamp=ts, src_ip=record.get("ip"), country=_country(record.get("country")),
                user_id=ctx.pseudonymize(record.get("user")),
                metadata_redacted=redact({"app": record.get("app"),
                                          "method": record.get("method")}))
    ev.user_agent = str(record.get("user_agent", ""))[:512] or None
    return [ev]


# ---------------------------------------------------------- scanner / malware results
_SEV = {"info": (1, EventCategory.VULNERABILITY), "low": (3, EventCategory.VULNERABILITY),
        "medium": (5, EventCategory.VULNERABILITY), "high": (7, EventCategory.VULNERABILITY),
        "critical": (9, EventCategory.VULNERABILITY)}


def scanner_result(record: dict[str, Any], ctx: NormContext) -> list[NormalizedEvent]:
    sev_name = str(record.get("severity", "info")).lower()
    sev, cat = _SEV.get(sev_name, (1, EventCategory.VULNERABILITY))
    if record.get("category") in ("misconfiguration", "exposure"):
        cat = EventCategory(record["category"])
    return [_event(ctx, native_id=f"{record.get('scanner')}:{record.get('rule_id')}:"
                                  f"{record.get('url')}", event_type=f"scanner.{record.get('rule_id',
                                                                                     'finding')}",
                   category=cat, severity=sev, confidence=0.7,
                   timestamp=_ts(record.get("timestamp")), request_path=record.get("url"),
                   rule_id=str(record.get("rule_id", ""))[:128] or None,
                   signature=str(record.get("title", ""))[:256] or None,
                   metadata_redacted=redact({"scanner": record.get("scanner")}))]


def malware_result(record: dict[str, Any], ctx: NormContext) -> list[NormalizedEvent]:
    verdict = str(record.get("verdict", "")).lower()
    if verdict not in ("malicious", "suspicious"):
        return []
    return [_event(ctx, native_id=f"{record.get('sha256')}:{verdict}",
                   event_type=f"malware.{verdict}", category=EventCategory.MALWARE,
                   severity=9 if verdict == "malicious" else 6,
                   confidence=0.9 if verdict == "malicious" else 0.6,
                   timestamp=_ts(record.get("timestamp")),
                   signature=str(record.get("signature", ""))[:256] or None,
                   metadata_redacted={"sha256": str(record.get("sha256", ""))[:64],
                                      "engine": record.get("engine")})]


NORMALIZERS: dict[str, Callable[[dict[str, Any], NormContext], list[NormalizedEvent]]] = {
    "cloudflare": cloudflare, "aws_waf": aws_waf, "siem": siem, "app_log": app_log,
    "proxy": proxy_log, "auth": auth, "scanner": scanner_result, "malware": malware_result,
}


def normalize_all(kind: str, records: Iterable[dict[str, Any]], ctx: NormContext,
                  limit: int) -> tuple[list[NormalizedEvent], int]:
    fn = NORMALIZERS[kind]
    out: list[NormalizedEvent] = []
    rejected = 0
    for i, rec in enumerate(records):
        if i >= limit:
            rejected += 1
            continue
        if not isinstance(rec, dict):
            rejected += 1
            continue
        try:
            out.extend(fn(rec, ctx))
        except (ValueError, TypeError, KeyError):
            rejected += 1
    return out, rejected
