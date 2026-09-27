"""FATMA's analysis agent: typed read-mostly tools, structured output, deterministic fallback."""

from __future__ import annotations

import json
import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from importlib import resources
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import select

from fatma_soc.defense import DefenseService
from fatma_soc.playbooks import playbook_for
from platform_core.app import ServiceRuntime
from platform_core.db.models import AgentRun, Asset, Finding, Incident, IncidentEvent, SecurityEvent, ToolCall
from platform_core.errors import NotFound, PlatformError, ValidationFailed
from platform_core.observability import instruments, tracer
from platform_core.schemas.enums import DefenseActionType
from platform_core.schemas.security import EventForAnalysis
from platform_core.security.crypto import canonical_json, sha256_hex
from platform_core.security.principal import AgentName, Principal
from platform_core.security.redaction import redact
from platform_core.security.service_acl import FATMA_SOC
from platform_core.security.service_auth import RequestContext
from platform_core.security.untrusted import fence

log = logging.getLogger(__name__)
AGENT = AgentName.FATMA
CONFIRMED_CLAIM = re.compile(r"\b(confirmed|definite|verified)\s+(breach|compromise|incident|"
                             r"intrusion|exfiltration)\b", re.I)


class FatmaAnalysis(BaseModel):
    model_config = ConfigDict(extra="forbid")
    summary: str = Field(max_length=1500)
    claim_status: Literal["SUSPECTED INCIDENT"]
    severity_assessment: Literal["NORMAL", "SUSPICIOUS", "HIGH RISK", "CRITICAL"]
    attack_hypotheses: list[str] = Field(max_length=6)
    evidence_gaps: list[str] = Field(max_length=6)
    recommended_next_steps: list[str] = Field(max_length=8)
    confidence: float = Field(ge=0, le=1)


def sanitize_analysis(a: FatmaAnalysis) -> FatmaAnalysis:
    """Output validation: FATMA may never assert confirmation, whatever the model produced."""
    def fix(text: str) -> str:
        return CONFIRMED_CLAIM.sub(lambda m: f"suspected {m.group(2)}", text)

    return a.model_copy(update={
        "summary": fix(a.summary), "claim_status": "SUSPECTED INCIDENT",
        "attack_hypotheses": [fix(x)[:300] for x in a.attack_hypotheses],
        "recommended_next_steps": [fix(x)[:300] for x in a.recommended_next_steps],
        "evidence_gaps": [x[:300] for x in a.evidence_gaps]})


# ------------------------------------------------------------------------ tool layer
class _Args(BaseModel):
    model_config = ConfigDict(extra="forbid")


class QueryEventsArgs(_Args):
    category: str | None = Field(pattern="^[a-z_]{2,32}$")
    src_ip: str | None = Field(max_length=45)
    minutes: int = Field(ge=1, le=1440)
    limit: int = Field(ge=1, le=50)


class IncidentArgs(_Args):
    incident_id: str = Field(pattern="^[0-9a-f-]{36}$")


class ListOpenArgs(_Args):
    limit: int = Field(ge=1, le=20)


class FindingsArgs(_Args):
    asset_id: str | None = Field(pattern="^[0-9a-f-]{36}$")
    severity: Literal["info", "low", "medium", "high", "critical"] | None


class AssetArgs(_Args):
    asset_id: str = Field(pattern="^[0-9a-f-]{36}$")


class NoteArgs(_Args):
    incident_id: str = Field(pattern="^[0-9a-f-]{36}$")
    note: str = Field(min_length=3, max_length=2000)


class RecommendArgs(_Args):
    incident_id: str = Field(pattern="^[0-9a-f-]{36}$")
    action_type: DefenseActionType
    target: str = Field(max_length=200)
    ttl_seconds: int | None = Field(ge=60, le=604800)
    rationale: str = Field(min_length=10, max_length=1000)


class NotifyArgs(_Args):
    incident_id: str = Field(pattern="^[0-9a-f-]{36}$")


@dataclass
class FatmaState:
    ctx: RequestContext
    run_id: uuid.UUID
    incident_id: uuid.UUID | None = None
    tools_used: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)


def _event_view(e: SecurityEvent) -> dict[str, Any]:
    return EventForAnalysis(
        event_id=e.event_id, source=e.source, category=e.category, event_type=e.event_type,
        severity=e.severity, confidence=float(e.confidence), timestamp=e.timestamp,
        src_ip=str(e.src_ip) if e.src_ip else None, request_path=(e.request_path or "")[:200],
        http_method=e.http_method, status_code=e.status_code, country=e.country,
        rule_id=e.rule_id, action_taken=e.action_taken).model_dump(mode="json")


class FatmaTools:
    def __init__(self, rt: ServiceRuntime, defense: DefenseService) -> None:
        self.rt = rt
        self.defense = defense
        self.handlers = {
            "security.query_events": (QueryEventsArgs, self.query_events),
            "incidents.get": (IncidentArgs, self.get_incident),
            "incidents.list_open": (ListOpenArgs, self.list_open),
            "findings.list": (FindingsArgs, self.findings),
            "assets.get": (AssetArgs, self.asset),
            "incidents.add_note": (NoteArgs, self.add_note),
            "defense.recommend_action": (RecommendArgs, self.recommend),
            "notifications.notify_security_team": (NotifyArgs, self.notify),
        }
        from platform_core.security.policy import TOOL_REGISTRY

        if set(self.handlers) != set(TOOL_REGISTRY[AGENT]):
            raise RuntimeError("FATMA tool implementations diverge from the policy registry")

    async def invoke(self, st: FatmaState, name: str, raw: dict[str, Any] | str) -> str:
        name = name.replace("_", ".", 1) if name not in self.handlers and "." not in name else name
        spec = self.handlers.get(name)
        args_dict = json.loads(raw) if isinstance(raw, str) else dict(raw)
        args_hash = sha256_hex(canonical_json(args_dict))
        decision = self.rt.policy.authorize_tool(st.ctx, FATMA_SOC, AGENT, name)
        if spec is None or not decision.allowed:
            reason = decision.reason if spec else "tool_not_registered_for_agent"
            instruments().tool_denials.add(1, {"agent": AGENT.value, "tool": name[:64]})
            await self._persist(st, name, args_dict, args_hash, "DENIED", reason, "denied", None)
            await self.rt.audit.record(st.ctx, action="agent.tool.denied", result="denied",
                                       agent_name=AGENT.value, tool_name=name[:64],
                                       risk_level="HIGH", metadata={"reason": reason})
            return "ERROR: tool not available."
        args_model, handler = spec
        try:
            args = args_model.model_validate(args_dict)
        except ValidationError:
            await self._persist(st, name, args_dict, args_hash, "ALLOWED", "allowlisted",
                                "invalid_arguments", None)
            return "ERROR: invalid arguments."
        started = time.perf_counter()
        status = "ok"
        with tracer().start_as_current_span(f"tool {name}") as span:
            span.set_attribute("agent.name", AGENT.value)
            try:
                result = await handler(st, args)
            except PlatformError as exc:
                status, result = "rejected", f"ERROR: {exc.message}"
        latency = int((time.perf_counter() - started) * 1000)
        instruments().tool_calls.add(1, {"agent": AGENT.value, "tool": name, "status": status})
        instruments().tool_latency.record(latency, {"agent": AGENT.value, "tool": name})
        st.tools_used.append(name)
        await self._persist(st, name, args_dict, args_hash, "ALLOWED", "allowlisted", status,
                            latency)
        if name in ("incidents.add_note", "defense.recommend_action",
                    "notifications.notify_security_team"):
            await self.rt.audit.record(st.ctx, action=f"agent.tool.{name}", agent_name=AGENT.value,
                                       tool_name=name, result="success" if status == "ok"
                                       else "failure", risk_level=decision.risk.value,
                                       metadata=redact(args_dict))
        return result

    async def _persist(self, st: FatmaState, name: str, args: dict, h: str, decision: str,
                       reason: str, status: str, latency: int | None) -> None:
        try:
            async with self.rt.require_db().tenant_session(st.ctx.tenant_id,
                                                           actor="agent:FATMA") as s:
                s.add(ToolCall(tenant_id=st.ctx.tenant_id, agent_run_id=st.run_id,
                               agent_name=AGENT.value, tool_name=name[:128],
                               arguments_redacted=redact(args), arguments_hash=h,
                               decision=decision, decision_reason=reason, status=status,
                               latency_ms=latency))
        except Exception:
            log.exception("failed to persist FATMA tool call")

    def _session(self, st: FatmaState, write: bool = False):  # noqa: ANN202
        return self.rt.require_db().tenant_session(st.ctx.tenant_id,
                                                   actor="agent:FATMA" if write else None)

    async def query_events(self, st: FatmaState, a: QueryEventsArgs) -> str:
        async with self._session(st) as s:
            stmt = select(SecurityEvent).where(
                SecurityEvent.timestamp > datetime.now(UTC) - timedelta(minutes=a.minutes))
            if a.category:
                stmt = stmt.where(SecurityEvent.category == a.category)
            if a.src_ip:
                stmt = stmt.where(SecurityEvent.src_ip == a.src_ip)
            rows = (await s.scalars(stmt.order_by(SecurityEvent.timestamp.desc())
                                    .limit(a.limit))).all()
        return fence(json.dumps([_event_view(e) for e in rows]), label="security_events",
                     max_len=20_000)

    async def get_incident(self, st: FatmaState, a: IncidentArgs) -> str:
        async with self._session(st) as s:
            inc = await s.get(Incident, uuid.UUID(a.incident_id))
            if inc is None:
                raise NotFound("incident not found")
            return json.dumps({"id": str(inc.id), "title": inc.title, "category": inc.category,
                               "risk_level": inc.risk_level, "risk_score": inc.risk_score,
                               "claim_status": inc.claim_status, "status": inc.status,
                               "event_count": inc.event_count,
                               "first_seen": inc.first_seen.isoformat(),
                               "last_seen": inc.last_seen.isoformat(), "signals": inc.signals,
                               "sources": inc.analysis.get("sources", [])[:20]}, default=str)

    async def list_open(self, st: FatmaState, a: ListOpenArgs) -> str:
        async with self._session(st) as s:
            rows = (await s.scalars(select(Incident).where(Incident.status.not_in(
                ["CLOSED", "FALSE_POSITIVE"])).order_by(Incident.risk_score.desc())
                .limit(a.limit))).all()
        return json.dumps([{"id": str(i.id), "title": i.title, "risk_level": i.risk_level,
                            "status": i.status} for i in rows])

    async def findings(self, st: FatmaState, a: FindingsArgs) -> str:
        async with self._session(st) as s:
            stmt = select(Finding).where(Finding.remediation_status.in_(["OPEN", "IN_PROGRESS"]))
            if a.asset_id:
                stmt = stmt.where(Finding.asset_id == uuid.UUID(a.asset_id))
            if a.severity:
                stmt = stmt.where(Finding.severity == a.severity)
            rows = (await s.scalars(stmt.limit(30))).all()
        return fence(json.dumps([{"title": f.title, "severity": f.severity, "rule_id": f.rule_id,
                                  "scanner": f.scanner, "url": f.url} for f in rows]),
                     label="scanner_findings")

    async def asset(self, st: FatmaState, a: AssetArgs) -> str:
        async with self._session(st) as s:
            asset = await s.get(Asset, uuid.UUID(a.asset_id))
            if asset is None:
                raise NotFound("asset not found")
            return json.dumps({"name": asset.name, "type": asset.asset_type,
                               "target": asset.canonical_target, "criticality": asset.criticality,
                               "environment": asset.environment})

    async def add_note(self, st: FatmaState, a: NoteArgs) -> str:
        async with self._session(st, write=True) as s:
            if await s.get(Incident, uuid.UUID(a.incident_id)) is None:
                raise NotFound("incident not found")
            s.add(IncidentEvent(tenant_id=st.ctx.tenant_id, incident_id=uuid.UUID(a.incident_id),
                                entry_type="note", actor_type="agent", actor_id="FATMA",
                                body={"note": CONFIRMED_CLAIM.sub("suspected \\2", a.note)}))
        return "NOTE_ADDED"

    async def recommend(self, st: FatmaState, a: RecommendArgs) -> str:
        async with self._session(st, write=True) as s:
            inc = await s.get(Incident, uuid.UUID(a.incident_id))
            if inc is None:
                raise NotFound("incident not found")
            confidence = max((sig.get("confidence", 0) for sig in inc.signals), default=0)
            try:
                action = await self.defense.recommend(
                    s, st.ctx.tenant_id, incident_id=inc.id, action_type=a.action_type,
                    target=a.target, ttl_seconds=a.ttl_seconds, rationale=a.rationale,
                    confidence=float(confidence), created_by="agent:FATMA")
            except ValueError as exc:
                raise ValidationFailed(str(exc)) from exc
            s.add(IncidentEvent(tenant_id=st.ctx.tenant_id, incident_id=inc.id,
                                entry_type="recommendation", actor_type="agent", actor_id="FATMA",
                                body={"waf_action_id": str(action.id),
                                      "action_type": action.action_type, "target": action.target}))
        from fatma_soc.preapproval import try_preapproved

        await try_preapproved(self.rt, st.ctx.tenant_id, action.id, st.ctx.request_id)
        return (f"RECOMMENDED: action {action.id} ({action.action_type} {action.target}) recorded "
                f"for human review. Nothing has been changed.")

    async def notify(self, st: FatmaState, a: NotifyArgs) -> str:
        await notify_incident(self.rt, st.ctx.tenant_id, uuid.UUID(a.incident_id),
                              st.ctx.request_id)
        return "NOTIFIED"


async def notify_incident(rt: ServiceRuntime, tenant_id: uuid.UUID, incident_id: uuid.UUID,
                          request_id: str) -> None:
    if "notifications" not in rt.clients:
        return
    async with rt.require_db().tenant_session(tenant_id) as s:
        inc = await s.get(Incident, incident_id)
        if inc is None:
            return
        asset = await s.get(Asset, inc.asset_id) if inc.asset_id else None
        variables = {"title": inc.title, "risk_level": inc.risk_level,
                     "risk_score": inc.risk_score, "claim_status": inc.claim_status,
                     "asset": asset.name if asset else "n/a",
                     "link": f"{rt.settings.console_base_url}/fatma/incidents/{inc.id}"}  # type: ignore[attr-defined]
    system = Principal.system(tenant_id, FATMA_SOC)
    for channel in ("email", "slack"):
        try:
            await rt.client("notifications").post("/internal/notifications", principal=system,
                                                  request_id=request_id, json={
                "template": "security.incident_alert", "channel": channel, "security_team": True,
                "variables": variables,
                "idempotency_key": f"incident:{incident_id}:{inc.risk_level}:{channel}",
                "related_type": "incident", "related_id": str(incident_id)})
        except PlatformError:
            log.warning("security notification failed")


# ---------------------------------------------------------------------- runtimes
class DeterministicAnalyst:
    name = "deterministic"
    model = None

    async def analyze(self, tools: FatmaTools, st: FatmaState, incident: dict[str, Any]
                      ) -> tuple[FatmaAnalysis, int, int]:
        pb = playbook_for(incident["category"])
        sigs = incident.get("signals", [])
        top = ", ".join(f"{s['name'].removeprefix('event:')} (x{s.get('count', 1)})"
                        for s in sigs[:5]) or "none"
        sources = incident.get("sources", [])
        # Low-risk, single-source recommendations are recorded for humans to review.
        if incident["risk_level"] in ("HIGH RISK", "CRITICAL") and len(sources) == 1 and \
                pb.actions and pb.actions[0] in (DefenseActionType.TEMP_BLOCK_IP,
                                                 DefenseActionType.CHALLENGE_IP):
            await tools.invoke(st, "defense.recommend_action", {
                "incident_id": incident["id"], "action_type": pb.actions[0].value,
                "target": sources[0], "ttl_seconds": 3600,
                "rationale": f"Single source responsible for {incident['category']} activity "
                             f"({incident['event_count']} events)."})
        analysis = FatmaAnalysis(
            summary=(f"{incident['risk_level']} ({incident['risk_score']}/100) suspected "
                     f"{incident['category'].replace('_', ' ')} involving {len(sources)} source(s) "
                     f"and {incident['event_count']} events between {incident['first_seen']} and "
                     f"{incident['last_seen']}. Strongest signals: {top}."),
            claim_status="SUSPECTED INCIDENT", severity_assessment=incident["risk_level"],
            attack_hypotheses=[f"Automated {incident['category'].replace('_', ' ')} attempt"],
            evidence_gaps=["Application/database logs for the affected time window",
                           "Confirmation whether any request succeeded"],
            recommended_next_steps=(pb.containment + pb.remediation)[:8],
            confidence=round(max((s.get("confidence", 0) for s in sigs), default=0.3), 2))
        return analysis, 0, 0


class OpenAIAnalyst:
    name = "openai-agents"

    def __init__(self, api_key: str, model: str, tracing: bool) -> None:
        from agents import set_default_openai_api, set_default_openai_client, set_tracing_disabled
        from openai import AsyncOpenAI

        set_default_openai_client(AsyncOpenAI(api_key=api_key), use_for_tracing=tracing)
        set_default_openai_api("responses")
        set_tracing_disabled(not tracing)
        self.model = model
        self.prompt = resources.files("fatma_soc").joinpath("prompts/fatma_system.md").read_text()

    def _tools(self, tools: FatmaTools) -> list:
        from agents import FunctionTool
        from agents.strict_schema import ensure_strict_json_schema

        out = []
        for name, (model_cls, _) in tools.handlers.items():
            async def invoke(tool_ctx: Any, args_json: str, _name: str = name) -> str:
                return await tools.invoke(tool_ctx.context, _name, args_json)

            out.append(FunctionTool(name=name.replace(".", "_"), description=f"FATMA tool {name}",
                                    params_json_schema=ensure_strict_json_schema(
                                        model_cls.model_json_schema()),
                                    on_invoke_tool=invoke, strict_json_schema=True,
                                    timeout_seconds=20))
        return out

    async def run(self, tools: FatmaTools, st: FatmaState, prompt: str, tenant_name: str,
                  output_type: type | None) -> tuple[Any, int, int]:
        from agents import Agent, ModelSettings, RunConfig, Runner

        agent = Agent[FatmaState](
            name="FATMA", instructions=self.prompt.format(tenant_name=tenant_name),
            model=self.model, tools=self._tools(tools), output_type=output_type,
            model_settings=ModelSettings(parallel_tool_calls=False, store=False))
        started = time.perf_counter()
        result = await Runner.run(agent, prompt, context=st, max_turns=10, run_config=RunConfig(
            workflow_name="fatma.analysis", trace_include_sensitive_data=False,
            trace_metadata={"tenant": str(st.ctx.tenant_id)}))
        instruments().llm_latency.record((time.perf_counter() - started) * 1000,
                                         {"agent": "FATMA", "model": self.model})
        usage = result.context_wrapper.usage
        return result.final_output, usage.input_tokens, usage.output_tokens

    async def analyze(self, tools: FatmaTools, st: FatmaState, incident: dict[str, Any]
                      ) -> tuple[FatmaAnalysis, int, int]:
        prompt = ("Analyse this SUSPECTED incident using your tools, then produce the structured "
                  "analysis. Recommend defensive actions only if the evidence supports them.\n"
                  + fence(json.dumps(incident, default=str), label="incident_record"))
        out, tin, tout = await self.run(tools, st, prompt, incident.get("tenant_name", ""),
                                        FatmaAnalysis)
        return out, tin, tout


class FatmaAgent:
    def __init__(self, rt: ServiceRuntime, tools: FatmaTools, analyst: Any) -> None:
        self.rt = rt
        self.tools = tools
        self.analyst = analyst

    async def _start_run(self, ctx: RequestContext, incident_id: uuid.UUID | None) -> uuid.UUID:
        run_id = uuid.uuid4()
        async with self.rt.require_db().tenant_session(ctx.tenant_id, actor="agent:FATMA") as s:
            s.add(AgentRun(id=run_id, tenant_id=ctx.tenant_id, agent_name="FATMA",
                           actor_type=ctx.principal.actor_type.value,
                           actor_id=ctx.principal.subject[:200], incident_id=incident_id,
                           runtime=self.analyst.name, model=self.analyst.model,
                           request_id=ctx.request_id))
        return run_id

    async def _finish(self, tenant_id: uuid.UUID, run_id: uuid.UUID, status: str, latency: int,
                      tin: int, tout: int, flags: list[str], error: str | None = None) -> None:
        async with self.rt.require_db().tenant_session(tenant_id, actor="agent:FATMA") as s:
            run = await s.get(AgentRun, run_id)
            if run:
                run.status, run.latency_ms, run.error = status, latency, error
                run.input_tokens, run.output_tokens = tin, tout
                run.guardrail_flags = flags
                run.completed_at = datetime.now(UTC)
        instruments().agent_runs.add(1, {"agent": "FATMA", "status": status})

    async def analyze_incident(self, ctx: RequestContext, incident_id: uuid.UUID) -> dict:
        run_id = await self._start_run(ctx, incident_id)
        st = FatmaState(ctx=RequestContext(caller=ctx.caller, receiver=ctx.receiver,
                                           principal=ctx.principal, request_id=ctx.request_id,
                                           agent_run_id=run_id), run_id=run_id,
                        incident_id=incident_id)
        async with self.rt.require_db().tenant_session(ctx.tenant_id) as s:
            inc = await s.get(Incident, incident_id)
            if inc is None:
                raise NotFound()
            snapshot = {"id": str(inc.id), "title": inc.title, "category": inc.category,
                        "risk_level": inc.risk_level, "risk_score": inc.risk_score,
                        "event_count": inc.event_count, "first_seen": inc.first_seen.isoformat(),
                        "last_seen": inc.last_seen.isoformat(), "signals": inc.signals,
                        "sources": inc.analysis.get("sources", [])[:20],
                        "asset_id": str(inc.asset_id) if inc.asset_id else None}
        started = time.perf_counter()
        try:
            analysis, tin, tout = await self.analyst.analyze(self.tools, st, snapshot)
            analysis = sanitize_analysis(FatmaAnalysis.model_validate(analysis))
            status, error = "COMPLETED", None
        except Exception as exc:
            log.exception("FATMA analysis failed; using deterministic analyst")
            analysis, tin, tout = await DeterministicAnalyst().analyze(self.tools, st, snapshot)
            status, error = "FAILED", type(exc).__name__
        latency = int((time.perf_counter() - started) * 1000)
        async with self.rt.require_db().tenant_session(ctx.tenant_id, actor="agent:FATMA") as s:
            inc = await s.get(Incident, incident_id)
            if inc is not None:
                inc.analysis = {**inc.analysis, "fatma": analysis.model_dump(),
                                "engine": self.analyst.name,
                                "analyzed_at": datetime.now(UTC).isoformat()}
                s.add(IncidentEvent(tenant_id=ctx.tenant_id, incident_id=incident_id,
                                    entry_type="analysis", actor_type="agent", actor_id="FATMA",
                                    body={"summary": analysis.summary[:500]}))
        await self._finish(ctx.tenant_id, run_id, status, latency, tin, tout, st.flags, error)
        return analysis.model_dump()

    async def ask(self, ctx: RequestContext, question: str, tenant_name: str) -> dict:
        """Analyst Q&A. Read-only tools + recommendations; answer is plain text."""
        run_id = await self._start_run(ctx, None)
        st = FatmaState(ctx=RequestContext(caller=ctx.caller, receiver=ctx.receiver,
                                           principal=ctx.principal, request_id=ctx.request_id,
                                           agent_run_id=run_id), run_id=run_id)
        started = time.perf_counter()
        if isinstance(self.analyst, OpenAIAnalyst):
            answer, tin, tout = await self.analyst.run(self.tools, st, fence(
                question, label="analyst_question"), tenant_name, None)
            answer = CONFIRMED_CLAIM.sub(lambda m: f"suspected {m.group(2)}", str(answer))
        else:
            open_list = json.loads(await self.tools.invoke(st, "incidents.list_open",
                                                           {"limit": 5}))
            answer = ("Deterministic mode (no model configured). Open incidents by risk:\n" +
                      "\n".join(f"- [{i['risk_level']}] {i['title']} ({i['status']})"
                                for i in open_list) if open_list else
                      "Deterministic mode: there are no open incidents.")
            tin = tout = 0
        await self._finish(ctx.tenant_id, run_id, "COMPLETED",
                           int((time.perf_counter() - started) * 1000), tin, tout, st.flags)
        return {"answer": answer, "tools_used": st.tools_used}
