from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select, text

from fatma_soc.agent import FatmaAgent, notify_incident
from fatma_soc.defense import DefenseService, action_payload
from fatma_soc.incidents import IncidentEngine
from platform_core.app import RuntimeDep, ServiceRuntime, internal_caller
from platform_core.db.models import (
    Asset,
    Finding,
    Incident,
    IncidentEvent,
    MalwareResult,
    ScanJob,
    SecurityEvent,
    Tenant,
    WafAction,
)
from platform_core.errors import Conflict, Forbidden, NotFound
from platform_core.observability import instruments
from platform_core.schemas.common import Page, StrictModel
from platform_core.schemas.enums import (
    DefenseActionStatus,
    DefenseActionType,
    FalsePositiveStatus,
    IncidentStatus,
    RemediationStatus,
    RiskClass,
)
from platform_core.security.principal import ActorType, Principal
from platform_core.security.rbac import P
from platform_core.security.service_acl import GATEWAY_ADMIN, SCANNER_CONTROLLER, SECURITY_INGEST
from platform_core.security.service_auth import RequestContext

log = logging.getLogger(__name__)
router = APIRouter(prefix="/internal")
IngestCtx = Annotated[RequestContext, Depends(internal_caller(SECURITY_INGEST, SCANNER_CONTROLLER))]
AdminCtx = Annotated[RequestContext, Depends(internal_caller(GATEWAY_ADMIN))]
Limit = Annotated[int, Query(ge=1, le=200)]
Offset = Annotated[int, Query(ge=0)]


def _engine(rt: ServiceRuntime) -> IncidentEngine:
    return rt.extras["engine"]


def _defense(rt: ServiceRuntime) -> DefenseService:
    return rt.extras["defense"]


def _agent(rt: ServiceRuntime) -> FatmaAgent:
    return rt.extras["agent"]


def _user(ctx: RequestContext) -> uuid.UUID:
    if ctx.principal.actor_type is not ActorType.USER:
        raise Forbidden("a human user is required")
    return uuid.UUID(ctx.principal.subject)


# ------------------------------------------------------------------ event processing
class IngestedIn(StrictModel):
    event_ids: list[uuid.UUID] = Field(min_length=1, max_length=1000)


async def process_events(rt: ServiceRuntime, tenant_id: uuid.UUID, event_ids: list[uuid.UUID],
                         request_id: str) -> dict[str, Any]:
    async with rt.require_db().tenant_session(tenant_id, actor="agent:FATMA") as s:
        touched = await _engine(rt).process(s, tenant_id, event_ids)
        await _engine(rt).mark_events_processed(s, event_ids)
        results = [(inc.id, created, prev, RiskClass(inc.risk_level), inc.risk_score)
                   for inc, created, prev in touched]
    system = Principal.system(tenant_id, "fatma-soc")
    ctx = RequestContext(caller="fatma-soc", receiver="fatma-soc", principal=system,
                         request_id=request_id)
    order = [RiskClass.NORMAL, RiskClass.SUSPICIOUS, RiskClass.HIGH_RISK, RiskClass.CRITICAL]
    for inc_id, created, prev, level, score in results:
        if created:
            instruments().incidents.add(1, {"risk": level.value})
        await rt.realtime.publish(tenant_id, "fatma", "incident.updated",
                                  {"incident_id": inc_id, "risk_level": level.value,
                                   "created": created})
        escalated = created or (prev is not None and order.index(level) > order.index(prev))
        if escalated and order.index(level) >= order.index(RiskClass.HIGH_RISK):
            await notify_incident(rt, tenant_id, inc_id, request_id)
        if escalated and score >= rt.settings.llm_min_risk_score:  # type: ignore[attr-defined]
            task = asyncio.create_task(_safe_analyze(rt, ctx, inc_id))
            rt.extras.setdefault("tasks", set()).add(task)
            task.add_done_callback(rt.extras["tasks"].discard)
    return {"incidents": [{"id": str(i[0]), "created": i[1], "risk_level": i[3].value}
                          for i in results]}


async def _safe_analyze(rt: ServiceRuntime, ctx: RequestContext, incident_id: uuid.UUID) -> None:
    try:
        await _agent(rt).analyze_incident(ctx, incident_id)
    except Exception:
        log.exception("incident analysis failed")


class FindingsIngestedIn(StrictModel):
    scan_job_id: uuid.UUID


@router.post("/findings/ingested")
async def findings_ingested(body: FindingsIngestedIn, ctx: IngestCtx, rt: RuntimeDep) -> dict:
    """High/critical scanner findings become SUSPECTED vulnerability incidents."""
    rt.policy.require(ctx, P.INTERNAL_EXECUTE)
    from fatma_soc.detection import Candidate, correlation_key
    from fatma_soc.risk import Signal

    sev_num = {"critical": 9, "high": 7}
    created = []
    async with rt.require_db().tenant_session(ctx.tenant_id, actor="agent:FATMA") as s:
        rows = (await s.scalars(select(Finding).where(
            Finding.scan_job_id == body.scan_job_id, Finding.severity.in_(list(sev_num)),
            Finding.false_positive_status != "FALSE_POSITIVE"))).all()
        crit = {a.id: a.criticality for a in (await s.scalars(select(Asset))).all()}
        for f in rows:
            cand = Candidate(correlation_key(ctx.tenant_id, f.asset_id, "vulnerability", f.rule_id),
                             f.category if f.category in ("misconfiguration", "exposure")
                             else "vulnerability", f"Security weakness: {f.title}"[:200],
                             f.asset_id, first_seen=f.first_seen, last_seen=f.last_seen)
            cand.signals.append(Signal(f"finding:{f.rule_id}", cand.category,
                                       sev_num[f.severity], 0.7,
                                       {"scanner": f.scanner, "url": (f.url or "")[:200]}))
            inc, is_new, _ = await _engine(rt)._upsert(s, ctx.tenant_id, cand, crit)
            created.append((inc.id, is_new))
    for inc_id, is_new in created:
        await rt.realtime.publish(ctx.tenant_id, "fatma", "incident.updated",
                                  {"incident_id": inc_id, "created": is_new})
    return {"incidents": len(created)}


@router.post("/events/ingested")
async def events_ingested(body: IngestedIn, ctx: IngestCtx, rt: RuntimeDep) -> dict:
    rt.policy.require(ctx, P.INTERNAL_EXECUTE)
    return await process_events(rt, ctx.tenant_id, body.event_ids, ctx.request_id)


# ------------------------------------------------------------------------ overview
@router.get("/soc/overview")
async def overview(ctx: AdminCtx, rt: RuntimeDep) -> dict:
    rt.policy.require(ctx, P.INCIDENT_READ)
    async with rt.require_db().tenant_session(ctx.tenant_id) as s:
        q = lambda sql, **kw: s.execute(text(sql), kw)  # noqa: E731
        incidents = (await q("""SELECT risk_level, count(*) n FROM incidents
            WHERE status NOT IN ('CLOSED','FALSE_POSITIVE') GROUP BY risk_level""")).all()
        findings = (await q("""SELECT severity, count(*) n FROM findings
            WHERE remediation_status IN ('OPEN','IN_PROGRESS')
              AND false_positive_status <> 'FALSE_POSITIVE' GROUP BY severity""")).all()
        waf = await s.scalar(text("""SELECT count(*) FROM security_events WHERE action_taken IN
            ('block','drop') AND "timestamp" > now() - interval '24 hours'"""))
        ddos = (await q("""SELECT date_trunc('hour', "timestamp") h, count(*) n FROM security_events
            WHERE category IN ('ddos','rate_anomaly','bot') AND "timestamp" > now() - interval '24 hours'
            GROUP BY 1 ORDER BY 1""")).all()
        timeline = (await q("""SELECT date_trunc('hour', "timestamp") h, category, count(*) n
            FROM security_events WHERE "timestamp" > now() - interval '24 hours'
              AND category <> 'info' GROUP BY 1, 2 ORDER BY 1""")).all()
        malware = await s.scalar(text("""SELECT count(*) FROM malware_results
            WHERE verdict IN ('malicious','suspicious') AND created_at > now() - interval '30 days'"""))
        suspicious_ips = (await q("""SELECT host(src_ip) ip, count(*) n, max(severity) sev,
            array_agg(DISTINCT category) cats FROM security_events
            WHERE src_ip IS NOT NULL AND category <> 'info' AND "timestamp" > now() - interval '24 hours'
            GROUP BY src_ip ORDER BY n DESC LIMIT 10""")).all()
        scans = (await s.scalars(select(ScanJob).order_by(ScanJob.created_at.desc()).limit(5))).all()
        at_risk = (await q("""SELECT a.id, a.name, max(i.risk_score) score, count(i.id) incidents
            FROM assets a JOIN incidents i ON i.asset_id = a.id
            WHERE i.status NOT IN ('CLOSED','FALSE_POSITIVE') GROUP BY a.id, a.name
            ORDER BY score DESC LIMIT 5""")).all()
        risk_score = await s.scalar(text("""SELECT coalesce(max(risk_score), 0) FROM incidents
            WHERE status NOT IN ('CLOSED','FALSE_POSITIVE','REMEDIATED')"""))
        pending_actions = await s.scalar(select(func.count()).select_from(WafAction).where(
            WafAction.status.in_(["RECOMMENDED", "PENDING_APPROVAL"])))
        metrics = await _engine(rt).metrics(s)
        tenant = await s.get(Tenant, ctx.tenant_id)
    return {
        "fatma_mode": (tenant.settings or {}).get("fatma_mode", "recommend_only") if tenant else
        "recommend_only",
        "active_incidents": {r.risk_level: r.n for r in incidents},
        "critical_findings": next((r.n for r in findings if r.severity == "critical"), 0),
        "vulnerabilities_by_severity": {r.severity: r.n for r in findings},
        "waf_blocked_24h": int(waf or 0),
        "ddos_indicators_24h": [{"hour": r.h.isoformat(), "count": r.n} for r in ddos],
        "event_timeline_24h": [{"hour": r.h.isoformat(), "category": r.category, "count": r.n}
                               for r in timeline],
        "malware_detections_30d": int(malware or 0),
        "suspicious_ips": [{"ip": r.ip, "events": r.n, "max_severity": r.sev,
                            "categories": list(r.cats)} for r in suspicious_ips],
        "recent_scans": [{"id": str(j.id), "status": j.status, "profile": j.profile,
                          "target": j.target_url, "created_at": j.created_at.isoformat(),
                          "findings": j.findings_count} for j in scans],
        "assets_at_risk": [{"id": str(r.id), "name": r.name, "risk_score": r.score,
                            "open_incidents": r.incidents} for r in at_risk],
        "risk_score": int(risk_score or 0),
        "pending_recommendations": int(pending_actions or 0),
        **metrics,
    }


# -------------------------------------------------------------------------- events
class EventOut(BaseModel):
    event_id: uuid.UUID
    asset_id: uuid.UUID | None
    source: str
    event_type: str
    category: str
    severity: int
    confidence: float
    timestamp: datetime
    src_ip: str | None
    destination: str | None
    request_path: str | None
    http_method: str | None
    status_code: int | None
    country: str | None
    user_agent: str | None
    rule_id: str | None
    action_taken: str | None
    risk: str | None


def _event_out(e: SecurityEvent) -> EventOut:
    return EventOut(event_id=e.event_id, asset_id=e.asset_id, source=e.source,
                    event_type=e.event_type, category=e.category, severity=e.severity,
                    confidence=float(e.confidence), timestamp=e.timestamp,
                    src_ip=str(e.src_ip) if e.src_ip else None, destination=e.destination,
                    request_path=e.request_path, http_method=e.http_method,
                    status_code=e.status_code, country=e.country, user_agent=e.user_agent,
                    rule_id=e.rule_id, action_taken=e.action_taken, risk=e.risk)


@router.get("/events", response_model=Page[EventOut])
async def list_events(ctx: AdminCtx, rt: RuntimeDep, limit: Limit = 50, offset: Offset = 0,
                      category: Annotated[list[str] | None, Query()] = None,
                      source: Annotated[str | None, Query(max_length=32)] = None,
                      src_ip: Annotated[str | None, Query(max_length=45)] = None,
                      hours: Annotated[int, Query(ge=1, le=720)] = 24) -> Page[EventOut]:
    rt.policy.require(ctx, P.SECURITY_EVENT_READ)
    async with rt.require_db().tenant_session(ctx.tenant_id) as s:
        stmt = select(SecurityEvent).where(
            SecurityEvent.timestamp > datetime.now(UTC) - timedelta(hours=hours))
        if category:
            stmt = stmt.where(SecurityEvent.category.in_(category[:10]))
        if source:
            stmt = stmt.where(SecurityEvent.source == source)
        if src_ip:
            stmt = stmt.where(SecurityEvent.src_ip == src_ip)
        total = await s.scalar(select(func.count()).select_from(stmt.subquery()))
        rows = (await s.scalars(stmt.order_by(SecurityEvent.timestamp.desc()).limit(limit)
                                .offset(offset))).all()
        return Page(items=[_event_out(e) for e in rows], total=int(total or 0), limit=limit,
                    offset=offset)


# ----------------------------------------------------------------------- incidents
class IncidentOut(BaseModel):
    id: uuid.UUID
    title: str
    summary: str
    category: str
    asset_id: uuid.UUID | None
    risk_level: str
    risk_score: int
    claim_status: str
    status: str
    event_count: int
    first_seen: datetime
    last_seen: datetime
    signals: list
    recommendations: list
    analysis: dict
    assignee_id: uuid.UUID | None
    acknowledged_at: datetime | None
    resolved_at: datetime | None
    confirmed_by: uuid.UUID | None
    confirmed_at: datetime | None
    created_at: datetime
    updated_at: datetime


@router.get("/incidents", response_model=Page[IncidentOut])
async def list_incidents(ctx: AdminCtx, rt: RuntimeDep, limit: Limit = 50, offset: Offset = 0,
                         status: Annotated[str | None, Query(max_length=20)] = None,
                         open_only: bool = False,
                         risk_level: Annotated[str | None, Query(max_length=20)] = None
                         ) -> Page[IncidentOut]:
    rt.policy.require(ctx, P.INCIDENT_READ)
    async with rt.require_db().tenant_session(ctx.tenant_id) as s:
        stmt = select(Incident)
        if status:
            stmt = stmt.where(Incident.status == status)
        if open_only:
            stmt = stmt.where(Incident.status.not_in(["CLOSED", "FALSE_POSITIVE"]))
        if risk_level:
            stmt = stmt.where(Incident.risk_level == risk_level)
        total = await s.scalar(select(func.count()).select_from(stmt.subquery()))
        rows = (await s.scalars(stmt.order_by(Incident.risk_score.desc(),
                                              Incident.last_seen.desc())
                                .limit(limit).offset(offset))).all()
        return Page(items=[IncidentOut.model_validate(i, from_attributes=True) for i in rows],
                    total=int(total or 0), limit=limit, offset=offset)


@router.get("/incidents/{incident_id}")
async def get_incident(incident_id: uuid.UUID, ctx: AdminCtx, rt: RuntimeDep) -> dict:
    rt.policy.require(ctx, P.INCIDENT_READ)
    async with rt.require_db().tenant_session(ctx.tenant_id) as s:
        inc = await _engine(rt).get(s, incident_id)
        timeline = (await s.scalars(select(IncidentEvent).where(
            IncidentEvent.incident_id == incident_id, IncidentEvent.entry_type != "event_linked")
            .order_by(IncidentEvent.created_at))).all()
        events = (await s.scalars(select(SecurityEvent).join(
            IncidentEvent, IncidentEvent.security_event_id == SecurityEvent.event_id).where(
            IncidentEvent.incident_id == incident_id).order_by(SecurityEvent.timestamp.desc())
            .limit(100))).all()
        actions = (await s.scalars(select(WafAction).where(WafAction.incident_id == incident_id)
                                   .order_by(WafAction.created_at.desc()))).all()
        return {
            "incident": IncidentOut.model_validate(inc, from_attributes=True).model_dump(mode="json"),
            "timeline": [{"id": str(t.id), "type": t.entry_type, "actor_type": t.actor_type,
                          "actor_id": t.actor_id, "body": t.body,
                          "created_at": t.created_at.isoformat()} for t in timeline],
            "events": [_event_out(e).model_dump(mode="json") for e in events],
            "actions": [WafActionOut.model_validate(a, from_attributes=True).model_dump(mode="json")
                        for a in actions],
        }


class TransitionIn(StrictModel):
    status: IncidentStatus
    note: str | None = Field(default=None, max_length=2000)


@router.post("/incidents/{incident_id}/status", response_model=IncidentOut)
async def transition(incident_id: uuid.UUID, body: TransitionIn, ctx: AdminCtx, rt: RuntimeDep
                     ) -> IncidentOut:
    rt.policy.require(ctx, P.INCIDENT_TRIAGE)
    user = _user(ctx)
    async with rt.require_db().tenant_session(ctx.tenant_id, actor=f"user:{user}") as s:
        inc = await _engine(rt).transition(s, incident_id, body.status, str(user), body.note)
        out = IncidentOut.model_validate(inc, from_attributes=True)
    await rt.audit.record(ctx, action="incident.status", result="success",
                          target_type="incident", target_id=incident_id,
                          metadata={"status": body.status.value})
    await rt.realtime.publish(ctx.tenant_id, "fatma", "incident.updated",
                              {"incident_id": incident_id, "status": body.status.value})
    return out


class AssignIn(StrictModel):
    assignee_id: uuid.UUID | None


@router.post("/incidents/{incident_id}/assign", response_model=IncidentOut)
async def assign(incident_id: uuid.UUID, body: AssignIn, ctx: AdminCtx, rt: RuntimeDep
                 ) -> IncidentOut:
    rt.policy.require(ctx, P.INCIDENT_TRIAGE)
    user = _user(ctx)
    async with rt.require_db().tenant_session(ctx.tenant_id, actor=f"user:{user}") as s:
        inc = await _engine(rt).get(s, incident_id)
        inc.assignee_id = body.assignee_id
        s.add(IncidentEvent(tenant_id=ctx.tenant_id, incident_id=inc.id, entry_type="assignment",
                            actor_type="user", actor_id=str(user),
                            body={"assignee_id": str(body.assignee_id)}))
        await s.flush()
        await s.refresh(inc)
        return IncidentOut.model_validate(inc, from_attributes=True)


class NoteIn(StrictModel):
    note: str = Field(min_length=1, max_length=5000)


@router.post("/incidents/{incident_id}/notes", status_code=201)
async def add_note(incident_id: uuid.UUID, body: NoteIn, ctx: AdminCtx, rt: RuntimeDep) -> dict:
    rt.policy.require(ctx, P.INCIDENT_TRIAGE)
    user = _user(ctx)
    async with rt.require_db().tenant_session(ctx.tenant_id, actor=f"user:{user}") as s:
        await _engine(rt).get(s, incident_id)
        s.add(IncidentEvent(tenant_id=ctx.tenant_id, incident_id=incident_id, entry_type="note",
                            actor_type="user", actor_id=str(user), body={"note": body.note}))
    return {"ok": True}


class ConfirmIn(StrictModel):
    justification: str = Field(min_length=30, max_length=5000)
    evidence_refs: list[str] = Field(min_length=1, max_length=50)
    checklist: list[str] = Field(min_length=1, max_length=20)


@router.post("/incidents/{incident_id}/confirm", response_model=IncidentOut)
async def confirm(incident_id: uuid.UUID, body: ConfirmIn, ctx: AdminCtx, rt: RuntimeDep
                  ) -> IncidentOut:
    """The only path to CONFIRMED: a security engineer with MFA, recorded evidence and a
    completed checklist. The database trigger additionally rejects non-human confirmation."""
    rt.policy.require(ctx, P.INCIDENT_CONFIRM)
    user = _user(ctx)
    async with rt.require_db().tenant_session(ctx.tenant_id, actor=f"user:{user}") as s:
        inc = await _engine(rt).confirm(s, incident_id, user, body.model_dump())
        out = IncidentOut.model_validate(inc, from_attributes=True)
    await rt.audit.record(ctx, action="incident.confirm", result="success", risk_level="HIGH",
                          target_type="incident", target_id=incident_id,
                          metadata={"evidence_refs": body.evidence_refs})
    return out


@router.post("/incidents/{incident_id}/analyze")
async def analyze(incident_id: uuid.UUID, ctx: AdminCtx, rt: RuntimeDep) -> dict:
    rt.policy.require(ctx, P.FATMA_ASK)
    return await _agent(rt).analyze_incident(ctx, incident_id)


class AskIn(StrictModel):
    question: str = Field(min_length=3, max_length=2000)


@router.post("/ask")
async def ask(body: AskIn, ctx: AdminCtx, rt: RuntimeDep) -> dict:
    rt.policy.require(ctx, P.FATMA_ASK)
    async with rt.require_db().tenant_session(ctx.tenant_id) as s:
        tenant = await s.get(Tenant, ctx.tenant_id)
    return await _agent(rt).ask(ctx, body.question, tenant.name if tenant else "")


@router.get("/metrics")
async def incident_metrics(ctx: AdminCtx, rt: RuntimeDep) -> dict:
    rt.policy.require(ctx, P.INCIDENT_READ)
    async with rt.require_db().tenant_session(ctx.tenant_id) as s:
        return await _engine(rt).metrics(s)


# ------------------------------------------------------------------------- findings
class FindingOut(BaseModel):
    id: uuid.UUID
    scan_job_id: uuid.UUID | None
    asset_id: uuid.UUID
    scanner: str
    rule_id: str
    title: str
    description: str
    category: str
    severity: str
    cwe: str | None
    url: str | None
    evidence_redacted: dict
    remediation: str | None
    false_positive_status: str
    remediation_status: str
    first_seen: datetime
    last_seen: datetime


@router.get("/findings", response_model=Page[FindingOut])
async def list_findings(ctx: AdminCtx, rt: RuntimeDep, limit: Limit = 50, offset: Offset = 0,
                        severity: Annotated[str | None, Query(max_length=10)] = None,
                        open_only: bool = True, asset_id: uuid.UUID | None = None
                        ) -> Page[FindingOut]:
    rt.policy.require(ctx, P.FINDING_READ)
    async with rt.require_db().tenant_session(ctx.tenant_id) as s:
        stmt = select(Finding)
        if severity:
            stmt = stmt.where(Finding.severity == severity)
        if open_only:
            stmt = stmt.where(Finding.remediation_status.in_(["OPEN", "IN_PROGRESS"]))
        if asset_id:
            stmt = stmt.where(Finding.asset_id == asset_id)
        total = await s.scalar(select(func.count()).select_from(stmt.subquery()))
        order = text("CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' "
                     "THEN 2 WHEN 'low' THEN 3 ELSE 4 END")
        rows = (await s.scalars(stmt.order_by(order, Finding.last_seen.desc()).limit(limit)
                                .offset(offset))).all()
        return Page(items=[FindingOut.model_validate(f, from_attributes=True) for f in rows],
                    total=int(total or 0), limit=limit, offset=offset)


class FindingPatch(StrictModel):
    false_positive_status: FalsePositiveStatus | None = None
    remediation_status: RemediationStatus | None = None


@router.patch("/findings/{finding_id}", response_model=FindingOut)
async def review_finding(finding_id: uuid.UUID, body: FindingPatch, ctx: AdminCtx,
                         rt: RuntimeDep) -> FindingOut:
    rt.policy.require(ctx, P.FINDING_REVIEW)
    async with rt.require_db().tenant_session(ctx.tenant_id, actor=ctx.principal.subject) as s:
        f = await s.get(Finding, finding_id)
        if f is None:
            raise NotFound()
        if body.false_positive_status:
            f.false_positive_status = body.false_positive_status.value
        if body.remediation_status:
            f.remediation_status = body.remediation_status.value
            if body.remediation_status in (RemediationStatus.REMEDIATED,
                                           RemediationStatus.VERIFIED):
                f.remediated_at = datetime.now(UTC)
        f.reviewed_by = ctx.principal.subject
        await s.flush()
        await s.refresh(f)
        out = FindingOut.model_validate(f, from_attributes=True)
    await rt.audit.record(ctx, action="finding.review", result="success", target_type="finding",
                          target_id=finding_id, metadata=body.model_dump(mode="json"))
    return out


@router.get("/assets")
async def list_assets(ctx: AdminCtx, rt: RuntimeDep) -> list[dict]:
    rt.policy.require(ctx, P.ASSET_READ)
    async with rt.require_db().tenant_session(ctx.tenant_id) as s:
        rows = (await s.execute(text("""
            SELECT a.id, a.name, a.canonical_target, a.criticality, a.verification_status,
                   a.allowlisted, coalesce(max(i.risk_score) FILTER (
                     WHERE i.status NOT IN ('CLOSED','FALSE_POSITIVE')), 0) AS risk_score,
                   count(DISTINCT f.id) FILTER (WHERE f.remediation_status IN ('OPEN','IN_PROGRESS'))
                     AS open_findings
            FROM assets a
            LEFT JOIN incidents i ON i.asset_id = a.id
            LEFT JOIN findings f ON f.asset_id = a.id
            WHERE a.deleted_at IS NULL GROUP BY a.id ORDER BY risk_score DESC, a.name"""))).all()
    return [dict(r._mapping) for r in rows]


@router.get("/malware")
async def malware_events(ctx: AdminCtx, rt: RuntimeDep, limit: Limit = 50) -> list[dict]:
    rt.policy.require(ctx, P.MALWARE_READ)
    async with rt.require_db().tenant_session(ctx.tenant_id) as s:
        rows = (await s.scalars(select(MalwareResult).order_by(MalwareResult.created_at.desc())
                                .limit(limit))).all()
    return [{"id": str(r.id), "filename": r.filename_sanitized, "sha256": r.sha256,
             "verdict": r.verdict, "mime_detected": r.mime_detected,
             "clamav_signature": r.clamav_signature, "yara": [m.get("rule") for m in r.yara_matches],
             "quarantine_status": r.quarantine_status, "created_at": r.created_at.isoformat()}
            for r in rows]


# ------------------------------------------------------------------ defensive actions
class WafActionOut(BaseModel):
    id: uuid.UUID
    incident_id: uuid.UUID | None
    approval_id: uuid.UUID | None
    provider: str
    action_type: str
    target: str
    params: dict
    payload_hash: str
    risk_level: str
    rationale: str
    mode: str
    status: str
    ttl_seconds: int | None
    expires_at: datetime | None
    executed_at: datetime | None
    executed_by: str | None
    provider_ref: str | None
    error: str | None
    created_by: str
    created_at: datetime


@router.get("/actions", response_model=Page[WafActionOut])
async def list_actions(ctx: AdminCtx, rt: RuntimeDep, limit: Limit = 50, offset: Offset = 0,
                       status: Annotated[str | None, Query(max_length=20)] = None
                       ) -> Page[WafActionOut]:
    rt.policy.require(ctx, P.DEFENSE_READ)
    async with rt.require_db().tenant_session(ctx.tenant_id) as s:
        stmt = select(WafAction)
        if status:
            stmt = stmt.where(WafAction.status == status)
        total = await s.scalar(select(func.count()).select_from(stmt.subquery()))
        rows = (await s.scalars(stmt.order_by(WafAction.created_at.desc()).limit(limit)
                                .offset(offset))).all()
        return Page(items=[WafActionOut.model_validate(a, from_attributes=True) for a in rows],
                    total=int(total or 0), limit=limit, offset=offset)


class RecommendIn(StrictModel):
    incident_id: uuid.UUID | None = None
    action_type: DefenseActionType
    target: str = Field(max_length=200)
    ttl_seconds: int | None = Field(default=None, ge=60, le=604800)
    rationale: str = Field(min_length=10, max_length=2000)


@router.post("/actions", response_model=WafActionOut, status_code=201)
async def recommend_action(body: RecommendIn, ctx: AdminCtx, rt: RuntimeDep) -> WafActionOut:
    """A security engineer proposes an action manually (same approval path as FATMA's)."""
    rt.policy.require(ctx, P.DEFENSE_REQUEST)
    async with rt.require_db().tenant_session(ctx.tenant_id, actor=ctx.principal.subject) as s:
        action = await _defense(rt).recommend(
            s, ctx.tenant_id, incident_id=body.incident_id, action_type=body.action_type,
            target=body.target, ttl_seconds=body.ttl_seconds, rationale=body.rationale,
            confidence=1.0, created_by=ctx.principal.subject)
        return WafActionOut.model_validate(action, from_attributes=True)


@router.post("/actions/{action_id}/request-approval", response_model=WafActionOut)
async def request_approval(action_id: uuid.UUID, ctx: AdminCtx, rt: RuntimeDep) -> WafActionOut:
    rt.policy.require(ctx, P.DEFENSE_REQUEST)
    user = _user(ctx)
    async with rt.require_db().tenant_session(ctx.tenant_id, actor=f"user:{user}") as s:
        action = await _defense(rt).get(s, action_id)
        if action.status != DefenseActionStatus.RECOMMENDED.value:
            raise Conflict("approval was already requested or the action is closed")
        payload = action_payload(ctx.tenant_id, action)
        system = Principal.system(ctx.tenant_id, "fatma-soc")
        approval = await rt.client("approvals").post("/internal/approvals", principal=system,
                                                     request_id=ctx.request_id, json={
            "action_type": payload["action_type"], "payload": payload,
            "reason": action.rationale, "target_type": "waf_action", "target_id": str(action.id),
            "on_behalf_of": str(user)})
        action.approval_id = uuid.UUID(approval["id"])
        action.status = DefenseActionStatus.PENDING_APPROVAL.value
        action.mode = "human_approved"
        await s.flush()
        out = WafActionOut.model_validate(action, from_attributes=True)
    await rt.audit.record(ctx, action="defense.request_approval", result="pending",
                          risk_level=out.risk_level, approval_id=out.approval_id,
                          target_type="waf_action", target_id=action_id)
    return out


@router.post("/actions/{action_id}/execute", response_model=WafActionOut)
async def execute_action(action_id: uuid.UUID, ctx: AdminCtx, rt: RuntimeDep) -> WafActionOut:
    rt.policy.require(ctx, P.DEFENSE_EXECUTE)
    user = _user(ctx)
    async with rt.require_db().tenant_session(ctx.tenant_id, actor=f"user:{user}") as s:
        action = await _defense(rt).get(s, action_id)
        if action.approval_id is None:
            raise Conflict("action has no approval")
        system = Principal.system(ctx.tenant_id, "fatma-soc")
        # Single-use redemption of the approval with the exact payload (hash-bound).
        await rt.client("approvals").post(
            f"/internal/approvals/{action.approval_id}/consume", principal=system,
            request_id=ctx.request_id, json={"action_type": f"defense.{action.action_type}",
                                             "payload": action_payload(ctx.tenant_id, action)})
        action = await _defense(rt).execute(s, action, str(user))
        out = WafActionOut.model_validate(action, from_attributes=True)
    await rt.audit.record(ctx, action="defense.execute", result="success"
                          if out.status == "ACTIVE" else "failure", risk_level=out.risk_level,
                          approval_id=out.approval_id, target_type="waf_action",
                          target_id=action_id, metadata={"provider": out.provider,
                                                         "action_type": out.action_type,
                                                         "target": out.target})
    await rt.realtime.publish(ctx.tenant_id, "fatma", "action.updated",
                              {"action_id": action_id, "status": out.status})
    return out


@router.post("/actions/{action_id}/revert", response_model=WafActionOut)
async def revert_action(action_id: uuid.UUID, ctx: AdminCtx, rt: RuntimeDep) -> WafActionOut:
    rt.policy.require(ctx, P.DEFENSE_EXECUTE)
    async with rt.require_db().tenant_session(ctx.tenant_id, actor=ctx.principal.subject) as s:
        action = await _defense(rt).revert(s, await _defense(rt).get(s, action_id), expired=False)
        out = WafActionOut.model_validate(action, from_attributes=True)
    await rt.audit.record(ctx, action="defense.revert", result="success", risk_level="MEDIUM",
                          target_type="waf_action", target_id=action_id)
    return out


@router.post("/actions/{action_id}/dismiss", response_model=WafActionOut)
async def dismiss_action(action_id: uuid.UUID, ctx: AdminCtx, rt: RuntimeDep) -> WafActionOut:
    rt.policy.require(ctx, P.DEFENSE_REQUEST)
    async with rt.require_db().tenant_session(ctx.tenant_id, actor=ctx.principal.subject) as s:
        action = await _defense(rt).get(s, action_id)
        if action.status not in (DefenseActionStatus.RECOMMENDED.value,):
            raise Conflict("only recommendations can be dismissed")
        action.status = DefenseActionStatus.DISMISSED.value
        return WafActionOut.model_validate(action, from_attributes=True)
