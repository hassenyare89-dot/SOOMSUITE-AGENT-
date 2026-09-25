from fatma_soc.risk import Signal, classify, confirmation_checklist, score_signals
from platform_core.schemas.enums import RiskClass


def test_classification_bands():
    assert classify(10) is RiskClass.NORMAL
    assert classify(30) is RiskClass.SUSPICIOUS
    assert classify(60) is RiskClass.HIGH_RISK
    assert classify(90) is RiskClass.CRITICAL


def test_success_indicator_and_criticality_raise_score():
    sig = [Signal("event:sqli", "sql_injection", 8, 0.85)]
    base = score_signals(sig, asset_criticality=3)
    assert score_signals(sig, asset_criticality=5) > base
    assert score_signals(sig, attack_succeeded_indicator=True) > base + 15


def test_blocked_attacks_are_discounted():
    sig = [Signal("event:sqli", "sql_injection", 8, 0.85)]
    assert score_signals(sig, blocked_ratio=1.0) < score_signals(sig, blocked_ratio=0.0)


def test_volume_is_logarithmic_not_dominant():
    weak = [Signal("bot", "bot", 2, 0.5)]
    assert score_signals(weak, event_count=1_000_000) < 50


def test_corroboration_across_categories():
    one = [Signal("a", "web_attack", 6, 0.8)]
    two = one + [Signal("b", "credential_attack", 5, 0.8)]
    assert score_signals(two) > score_signals(one)


def test_confirmation_checklist_is_specific():
    assert any("Database" in c for c in confirmation_checklist("sql_injection"))
    assert len(confirmation_checklist("unknown")) >= 3
