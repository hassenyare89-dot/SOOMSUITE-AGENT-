from app.domain.schemas import SecurityEventIn
from app.services.risk import classify


class FatmaService:
    async def analyze(self, event: SecurityEventIn) -> dict:
        risk, claim = classify(event)
        return {
            "risk": risk,
            "incident_claim": claim,
            "recommendation": (
                "Triage normalized evidence and seek human approval before containment."
            ),
        }
