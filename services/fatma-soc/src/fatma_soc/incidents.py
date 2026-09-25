"""Incident engine and lifecycle."""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from fatma_soc.detection import (
    DEFAULT_THRESHOLDS,
    Candidate,
    merge,
    per_event_candidates,
    summarize_signals,
    windowed_signals,
)
from fatma_soc.playbooks import playbook_for
from fatma_soc.risk import classify, confirmation_checklist, score_signals
from platform_core.db.models import Asset, Incident, IncidentEvent, SecurityEvent, Tenant
from platform_core.errors import Conflict, NotFound, ValidationFailed
from platform_core.schemas.enums import (
    INCIDENT_TRANSITIONS,
    IncidentClaim,
    IncidentStatus,
    RiskClass,
)

log = logging.getLogger(__name__)
RISK_ORDER = [RiskClass.NORMAL, RiskClass.SUSPICIOUS, RiskClass.HIGH_RISK, RiskClass.CRITICAL]


class IncidentEngine:
    async def process(self, s: AsyncSession, tenant_id: uuid.UUID, event_ids: list[uuid.UUID]
                      ) -> list[tuple[Incident, bool, RiskClass | None]]:
        """Returns (incident, created, previous_risk) for every incident touched."""
        events = (await s.scalars(select(SecurityEvent).where(
            SecurityEvent.event_id.in_(event_ids)))).all() if event_ids else []
        tenant = await s.get(Tenant, tenant_id)
        thresholds = {**DEFAULT_THRESHOLDS, **((tenant.settings or {}).get("detection", {})
                                               if tenant else {})}
        cands = per_event_candidates(tenant_id, list(events))
        asset_ids = {e.asset_id for e in events if e.asset_id}
        cands = merge(cands, await windowed_signals(s, tenant_id, asset_ids, thresholds))
        criticality = {a.id: a.criticality for a in (await s.scalars(
            select(Asset).where(Asset.id.in_({c.asset_id for c in cands.values()
                                              if c.asset_id})))).all()} if cands else {}
        touched = []
        for cand in cands.values():
            touched.append(await self._upsert(s, tenant_id, cand, criticality))
        # Per-event risk annotation for the events list view.
        for e in events:
            e.risk = classify(score_signals(
                [s for c in cands.values() if e.event_id in c.event_ids for s in c.signals
                 if s.name == f"event:{e.event_type}"],
                asset_criticality=criticality.get(e.asset_id, 3))).value
        return touched

    async def _upsert(self, s: AsyncSession, tenant_id: uuid.UUID, cand: Candidate,
                      criticality: dict) -> tuple[Incident, bool, RiskClass | None]:
        now = datetime.now(UTC)
        inc = await s.scalar(select(Incident).where(
            Incident.correlation_key == cand.correlation_key,
            Incident.status.not_in([IncidentStatus.CLOSED, IncidentStatus.FALSE_POSITIVE]))
            .with_for_update())
        created = inc is None
        previous = None if created else RiskClass(inc.risk_level)
        all_signals = [*(inc.signals if inc else []), *[x.as_dict() for x in cand.signals]]
        event_count = (inc.event_count if inc else 0) + len(cand.event_ids)
        from fatma_soc.risk import Signal

        sigs = [Signal(d["name"], d["category"], d["severity"], d["confidence"],
                       d.get("evidence", {})) for d in all_signals]
        blocked_ratio = cand.blocked / max(1, len(cand.event_ids)) if cand.event_ids else 0.0
        score = score_signals(sigs, asset_criticality=criticality.get(cand.asset_id, 3),
                              event_count=event_count,
                              attack_succeeded_indicator=cand.succeeded or bool(
                                  inc and inc.analysis.get("success_indicator")),
                              blocked_ratio=blocked_ratio)
        level = classify(score)
        pb = playbook_for(cand.category)
        recommendations = [{"type": "containment", "text": t} for t in pb.containment] + \
                          [{"type": "remediation", "text": t} for t in pb.remediation]
        summary_signals = summarize_signals(sigs)
        if created:
            inc = Incident(
                id=uuid.uuid4(), tenant_id=tenant_id, title=cand.title[:200],
                category=cand.category, asset_id=cand.asset_id, risk_level=level.value,
                risk_score=score, claim_status=IncidentClaim.SUSPECTED.value,
                status=IncidentStatus.NEW.value, correlation_key=cand.correlation_key,
                event_count=event_count, first_seen=cand.first_seen or now,
                last_seen=cand.last_seen or now, signals=summary_signals,
                recommendations=recommendations,
                analysis={"engine": "deterministic", "sources": sorted(cand.sources)[:50],
                          "success_indicator": cand.succeeded,
                          "confirmation_checklist": confirmation_checklist(cand.category)},
                summary=_summary(cand, level, score, len(cand.sources)))
            s.add(inc)
        else:
            # Risk never auto-decreases on an open incident; humans close or downgrade.
            if RISK_ORDER.index(level) < RISK_ORDER.index(previous):
                level, score = previous, max(score, inc.risk_score)
            inc.risk_level, inc.risk_score = level.value, max(score, inc.risk_score)
            inc.event_count = event_count
            inc.last_seen = max(inc.last_seen, cand.last_seen or now)
            inc.signals = summary_signals
            inc.analysis = {**inc.analysis,
                            "sources": sorted(set(inc.analysis.get("sources", [])) | cand.sources)[:50],
                            "success_indicator": inc.analysis.get("success_indicator")
                            or cand.succeeded}
            inc.summary = _summary(cand, level, inc.risk_score, len(inc.analysis["sources"]))
        await s.flush()
        if cand.event_ids:
            await s.execute(insert(IncidentEvent).values([
                {"id": uuid.uuid4(), "tenant_id": tenant_id, "incident_id": inc.id,
                 "security_event_id": eid, "entry_type": "event_linked", "actor_type": "agent",
                 "actor_id": "FATMA", "body": {}} for eid in cand.event_ids[:1000]])
                .on_conflict_do_nothing())
        if created or previous != level:
            s.add(IncidentEvent(tenant_id=tenant_id, incident_id=inc.id, entry_type="analysis",
                                actor_type="agent", actor_id="FATMA",
                                body={"risk_level": level.value, "risk_score": inc.risk_score,
                                      "previous": previous.value if previous else None}))
        return inc, created, previous

    # ------------------------------------------------------------------- lifecycle
    async def get(self, s: AsyncSession, incident_id: uuid.UUID) -> Incident:
        inc = await s.get(Incident, incident_id)
        if inc is None:
            raise NotFound()
        return inc

    async def transition(self, s: AsyncSession, incident_id: uuid.UUID, target: IncidentStatus,
                         actor: str, note: str | None) -> Incident:
        inc = await self.get(s, incident_id)
        current = IncidentStatus(inc.status)
        if target not in INCIDENT_TRANSITIONS[current]:
            raise Conflict(f"cannot move incident from {current} to {target}")
        now = datetime.now(UTC)
        inc.status = target.value
        if target is IncidentStatus.ACKNOWLEDGED and inc.acknowledged_at is None:
            inc.acknowledged_at = now
        if target is IncidentStatus.CONTAINED:
            inc.contained_at = now
        if target in (IncidentStatus.REMEDIATED, IncidentStatus.CLOSED,
                      IncidentStatus.FALSE_POSITIVE):
            inc.resolved_at = inc.resolved_at or now
            if inc.acknowledged_at is None:
                inc.acknowledged_at = now
        s.add(IncidentEvent(tenant_id=inc.tenant_id, incident_id=inc.id,
                            entry_type="status_change", actor_type="user", actor_id=actor,
                            body={"from": current.value, "to": target.value, "note": note}))
        return inc

    async def confirm(self, s: AsyncSession, incident_id: uuid.UUID, user_id: uuid.UUID,
                      evidence: dict[str, Any]) -> Incident:
        """Only a human security engineer can confirm, and only with recorded evidence."""
        inc = await self.get(s, incident_id)
        if inc.claim_status == IncidentClaim.CONFIRMED:
            raise Conflict("incident already confirmed")
        checklist = confirmation_checklist(inc.category)
        attested = evidence.get("checklist", [])
        missing = [c for c in checklist if c not in attested]
        if missing or not evidence.get("evidence_refs") or len(evidence.get("justification",
                                                                              "")) < 30:
            raise ValidationFailed("insufficient evidence to confirm this incident",
                                   details={"missing_checklist": missing,
                                            "requires": ["evidence_refs", "justification>=30"]})
        inc.claim_status = IncidentClaim.CONFIRMED.value
        inc.confirmed_by = user_id
        inc.confirmed_at = datetime.now(UTC)
        inc.confirmation_evidence = evidence
        s.add(IncidentEvent(tenant_id=inc.tenant_id, incident_id=inc.id,
                            entry_type="confirmation", actor_type="user", actor_id=str(user_id),
                            body={"evidence_refs": evidence.get("evidence_refs")}))
        return inc

    async def metrics(self, s: AsyncSession) -> dict[str, Any]:
        row = (await s.execute(select(
            func.avg(func.extract("epoch", Incident.acknowledged_at - Incident.created_at)),
            func.avg(func.extract("epoch", Incident.resolved_at - Incident.created_at)),
            func.count().filter(Incident.status.not_in(["CLOSED", "FALSE_POSITIVE",
                                                        "REMEDIATED"])),
            func.count().filter(Incident.claim_status == IncidentClaim.CONFIRMED.value),
        ))).one()
        return {"mean_time_to_acknowledge_seconds": round(float(row[0])) if row[0] else None,
                "mean_time_to_remediate_seconds": round(float(row[1])) if row[1] else None,
                "unresolved_incidents": int(row[2] or 0), "confirmed_incidents": int(row[3] or 0)}

    async def mark_events_processed(self, s: AsyncSession, event_ids: list[uuid.UUID]) -> None:
        await s.execute(update(SecurityEvent).where(SecurityEvent.event_id.in_(event_ids),
                                                    SecurityEvent.risk.is_(None))
                        .values(risk=RiskClass.NORMAL.value))


def _summary(cand: Candidate, level: RiskClass, score: int, n_sources: int) -> str:
    names = ", ".join(sorted({s.name.removeprefix("event:") for s in cand.signals})[:6])
    return (f"{level.value} ({score}/100) suspected {cand.category.replace('_', ' ')} "
            f"involving {n_sources or 'unknown'} source(s). Signals: {names}. "
            f"This is a SUSPECTED incident until a security engineer confirms it with evidence.")
