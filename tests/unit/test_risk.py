from datetime import UTC, datetime
from uuid import uuid4

from app.domain.schemas import IncidentClaim, Risk, SecurityEventIn
from app.services.risk import classify


def test_single_critical_signal_stays_suspected():
    e = SecurityEventIn(
        event_id=uuid4(),
        tenant_id=uuid4(),
        asset_id=uuid4(),
        source="waf",
        event_type="sqli",
        severity=10,
        confidence=0.95,
        timestamp=datetime.now(UTC),
    )
    assert classify(e) == (Risk.CRITICAL, IncidentClaim.SUSPECTED)
