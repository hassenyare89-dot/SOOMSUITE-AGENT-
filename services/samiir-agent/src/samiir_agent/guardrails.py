"""Deterministic guardrails around SAMIIR's model output and input.

``check_grounding`` is the enforcement point for "SAMIIR must never invent prices,
availability, discounts or guarantees": any monetary amount, percentage, clock time or
commitment phrase in a reply must be traceable to tool output from the same run.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from platform_core.security.untrusted import assess_injection

MONEY = re.compile(
    r"(?:(?:[$€£¥₹]|\b(?:USD|EUR|GBP|AED|SAR|KES|SOS|ETB|CAD|AUD)\b)\s?\d[\d,]*(?:\.\d+)?)"
    r"|(?:\d[\d,]*(?:\.\d+)?\s?(?:USD|EUR|GBP|AED|SAR|KES|SOS|ETB|CAD|AUD|dollars|euros|pounds)\b)",
    re.IGNORECASE)
PERCENT = re.compile(r"\b\d{1,3}(?:\.\d+)?\s?%")
CLOCK = re.compile(r"\b(?:[01]?\d|2[0-3])[:.][0-5]\d\b|\b(?:1[0-2]|0?[1-9])\s?(?:am|pm)\b",
                   re.IGNORECASE)
COMMITMENTS = re.compile(
    r"\b(guarantee[ds]?|warrant(?:y|ies|ed)|money[- ]back|refund(?:ed|able)?|discount(?:ed|s)?|"
    r"free of charge|100% (?:secure|safe|uptime)|unhackable|sla of|we promise)\b", re.IGNORECASE)

SAFE_FALLBACK = ("I want to make sure I give you accurate information, and I don't have an "
                 "approved answer for that. I've asked a member of our team to follow up with you.")

SECURITY_REDIRECT = ("I'm the customer-service assistant, so I can't run security scans, "
                     "investigate attacks or change any security settings. Our security team "
                     "can help through a consultation. Would you like me to find a time for one?")


def _digits(s: str) -> str:
    return re.sub(r"[^\d.]", "", s).rstrip(".").removesuffix(".00")


@dataclass(frozen=True)
class GroundingResult:
    ok: bool
    violations: tuple[str, ...]


def check_grounding(answer: str, grounding: list[str]) -> GroundingResult:
    corpus = "\n".join(grounding)
    corpus_lower = corpus.lower()
    corpus_numbers = {_digits(m.group(0)) for m in re.finditer(r"\d[\d,]*(?:\.\d+)?", corpus)}
    violations: list[str] = []
    for m in MONEY.finditer(answer):
        if _digits(m.group(0)) not in corpus_numbers:
            violations.append(f"ungrounded_amount:{m.group(0)}")
    for m in PERCENT.finditer(answer):
        if m.group(0).replace(" ", "") not in corpus.replace(" ", ""):
            violations.append(f"ungrounded_percentage:{m.group(0)}")
    for m in CLOCK.finditer(answer):
        token = m.group(0).lower().replace(".", ":").replace(" ", "")
        if token not in corpus_lower.replace(" ", "") and token.lstrip("0") not in corpus_lower:
            violations.append(f"ungrounded_time:{m.group(0)}")
    for m in COMMITMENTS.finditer(answer):
        if m.group(0).lower() not in corpus_lower:
            violations.append(f"ungrounded_commitment:{m.group(0)}")
    return GroundingResult(ok=not violations, violations=tuple(violations))


@dataclass(frozen=True)
class InputAssessment:
    security_request: bool
    injection_score: float
    signals: tuple[str, ...]


SECURITY_OPS = re.compile(
    r"\b(scan|pentest|pen[- ]test|nmap|nuclei|zap|exploit|ddos|brute[- ]?force|hack|block (?:ip|"
    r"country|traffic)|firewall|waf|siem|fatma|vulnerability scan|port scan)\b", re.IGNORECASE)
SERVICE_INTEREST = re.compile(r"\b(price|cost|quote|service|consult|assessment|offer|package|"
                              r"book|buy|purchase|interested)\b", re.IGNORECASE)


def assess_input(text: str) -> InputAssessment:
    a = assess_injection(text)
    wants_ops = bool(SECURITY_OPS.search(text))
    # "How much is your pentest service?" is a sales question, not an operational request.
    security_request = wants_ops and (
        "tool_coercion" in a.signals or "security_pivot" in a.signals
        or "privilege" in a.signals or not SERVICE_INTEREST.search(text))
    return InputAssessment(security_request=security_request, injection_score=a.score,
                           signals=a.signals)
