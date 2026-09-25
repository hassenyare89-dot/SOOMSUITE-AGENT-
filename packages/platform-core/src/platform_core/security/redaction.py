"""Redaction of secrets and unnecessary PII before logging, auditing or model exposure."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from typing import Any

REDACTED = "[REDACTED]"

SENSITIVE_KEY_PATTERN = re.compile(
    r"(pass(word|wd)?|secret|token|api[_-]?key|authorization|cookie|set-cookie|session|"
    r"credential|private[_-]?key|client[_-]?secret|signature|otp|mfa|ssn|card(number)?|cvv|"
    r"x-hub-signature|access[_-]?key)",
    re.IGNORECASE,
)

_VALUE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)\bbearer\s+[a-z0-9._~+/=-]{8,}"), "Bearer " + REDACTED),
    (re.compile(r"\beyJ[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,}\b"), "[JWT]"),
    (re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"), "[AWS_KEY]"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"), "[API_KEY]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "[GITHUB_TOKEN]"),
    (re.compile(r"\bxox[abpr]-[A-Za-z0-9-]{10,}\b"), "[SLACK_TOKEN]"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
     "[PRIVATE_KEY]"),
    (re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api_key|apikey|session)=([^&\s]+)"),
     r"\1=" + REDACTED),
]

CARD_CANDIDATE_RE = re.compile(r"\b\d(?:[ -]?\d){12,18}\b")


def _luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
        alt = not alt
    return total % 10 == 0


def _mask_card(match: re.Match[str]) -> str:
    digits = re.sub(r"\D", "", match.group(0))
    return "[CARD]" if 13 <= len(digits) <= 19 and _luhn_ok(digits) else match.group(0)

EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
PHONE_RE = re.compile(r"(?<!\w)\+?\d[\d\s().-]{7,}\d(?!\w)")


def redact_text(text: str, *, mask_pii: bool = False) -> str:
    for pattern, repl in _VALUE_PATTERNS:
        text = pattern.sub(repl, text)
    text = CARD_CANDIDATE_RE.sub(_mask_card, text)
    if mask_pii:
        text = EMAIL_RE.sub(r"\1***@\2", text)
        text = PHONE_RE.sub("[PHONE]", text)
    return text


def redact(value: Any, *, mask_pii: bool = False, _depth: int = 0) -> Any:
    if _depth > 12:
        return "[TRUNCATED]"
    if isinstance(value, Mapping):
        out = {}
        for k, v in value.items():
            key = str(k)
            if SENSITIVE_KEY_PATTERN.search(key):
                out[key] = REDACTED
            else:
                out[key] = redact(v, mask_pii=mask_pii, _depth=_depth + 1)
        return out
    if isinstance(value, list | tuple):
        return [redact(v, mask_pii=mask_pii, _depth=_depth + 1) for v in value]
    if isinstance(value, str):
        return redact_text(value, mask_pii=mask_pii)
    return value


def redact_url(url: str) -> str:
    """Strip query-string secrets and userinfo from URLs/paths."""
    url = re.sub(r"//[^/@\s]+@", "//[USERINFO]@", url)
    if "?" not in url:
        return url
    base, _, query = url.partition("?")
    parts = []
    for pair in query.split("&"):
        name, sep, val = pair.partition("=")
        parts.append(f"{name}={REDACTED}" if SENSITIVE_KEY_PATTERN.search(name) else pair)
    return redact_text(base + "?" + "&".join(parts))


def truncate_ip_for_analytics(ip: str) -> str:
    """Pseudonymize an IP to /24 (v4) or /48 (v6) where full precision is not needed."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"
    prefix = 24 if addr.version == 4 else 48
    return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
