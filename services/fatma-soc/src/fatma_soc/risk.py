"""Deterministic risk scoring and classification.

FATMA's model may *explain* risk; it never *sets* it. Scores come from this module only."""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from platform_core.schemas.enums import RiskClass

CRITICALITY_MULTIPLIER = {1: 0.7, 2: 0.85, 3: 1.0, 4: 1.15, 5: 1.3}
CATEGORY_WEIGHT = {
    "malware": 1.3, "data_exfiltration": 1.4, "sql_injection": 1.15, "path_traversal": 1.1,
    "web_attack": 1.1, "credential_attack": 1.1, "auth_anomaly": 1.0, "xss": 1.0, "ddos": 1.2,
    "rate_anomaly": 0.9, "bot": 0.8, "vulnerability": 1.0, "misconfiguration": 0.8,
    "exposure": 0.9, "waf_block": 0.7, "info": 0.2,
}


@dataclass(frozen=True)
class Signal:
    name: str
    category: str
    severity: int          # 0-10
    confidence: float      # 0-1
    evidence: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {"name": self.name, "category": self.category, "severity": self.severity,
                "confidence": round(self.confidence, 3), "evidence": self.evidence}


def classify(score: int) -> RiskClass:
    if score >= 75:
        return RiskClass.CRITICAL
    if score >= 50:
        return RiskClass.HIGH_RISK
    if score >= 25:
        return RiskClass.SUSPICIOUS
    return RiskClass.NORMAL


def score_signals(signals: list[Signal], *, asset_criticality: int = 3, event_count: int = 1,
                  attack_succeeded_indicator: bool = False, blocked_ratio: float = 0.0) -> int:
    """Combine signals into a 0-100 score.

    * strongest signal dominates (severity × confidence × category weight),
    * corroboration by *distinct* categories raises the score,
    * volume adds logarithmically (floods can't dominate precision signals),
    * success indicators (e.g. 2xx on an injection attempt) raise it sharply,
    * attacks fully blocked at the edge are discounted.
    """
    if not signals:
        return 0
    strengths = sorted((s.severity * s.confidence * CATEGORY_WEIGHT.get(s.category, 1.0) * 10
                        for s in signals), reverse=True)
    base = strengths[0]
    corroboration = 8 * (len({s.category for s in signals if s.category != "info"}) - 1)
    volume = min(12.0, 4 * math.log10(max(1, event_count)))
    success = 20 if attack_succeeded_indicator else 0
    raw = (base + corroboration + volume + success) * CRITICALITY_MULTIPLIER.get(asset_criticality,
                                                                                 1.0)
    raw *= 1 - 0.35 * max(0.0, min(1.0, blocked_ratio))
    return max(0, min(100, round(raw)))


def confirmation_checklist(category: str) -> list[str]:
    """Evidence a human must record before an incident may be marked CONFIRMED."""
    common = ["Analyst reviewed raw evidence (not only FATMA's summary)",
              "Impact on confidentiality, integrity or availability demonstrated"]
    specific = {
        "sql_injection": ["Database query logs or data access confirming successful injection"],
        "malware": ["Sample verdict corroborated by a second engine or manual analysis",
                    "Presence on a production system confirmed"],
        "credential_attack": ["At least one successful login attributable to the attacker"],
        "data_exfiltration": ["Data transfer volume and destination verified"],
        "ddos": ["Service degradation observed in availability monitoring"],
    }
    return common + specific.get(category, ["Indicator corroborated by an independent source"])
