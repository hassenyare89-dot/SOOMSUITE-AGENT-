from app.domain.schemas import IncidentClaim, Risk, SecurityEventIn


def classify(event: SecurityEventIn) -> tuple[Risk, IncidentClaim]:
    score = event.severity * event.confidence
    risk = (
        Risk.CRITICAL
        if score >= 8
        else Risk.HIGH_RISK
        if score >= 5
        else Risk.SUSPICIOUS
        if score >= 2
        else Risk.NORMAL
    )
    # Confirmation requires corroboration by the incident correlator; one event never confirms.
    return risk, IncidentClaim.SUSPECTED
