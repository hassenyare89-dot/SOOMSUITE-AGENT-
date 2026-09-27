from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import func, select

from crm_service.service import (
    CompanyIn,
    CompanyOut,
    ContactIn,
    ContactOut,
    CrmNote,
    CrmService,
    CrmTask,
    NoteIn,
    OpportunityIn,
    OpportunityPatch,
    TaskIn,
    TaskPatch,
)
from platform_core.app import RuntimeDep, ServiceRuntime, internal_caller
from platform_core.db.models import Company, CrmActivity, Opportunity
from platform_core.errors import NotFound
from platform_core.observability import instruments
from platform_core.schemas.common import Page
from platform_core.schemas.crm import (
    ActivityIn,
    CaptureContactRequest,
    ContactDelivery,
    ContactRef,
    InternalStageEvent,
    OpportunityOut,
    QualifyLeadRequest,
    QualifyLeadResponse,
    StageChangeRequest,
)
from platform_core.schemas.enums import PipelineStage
from platform_core.security.principal import ActorType
from platform_core.security.rbac import P
from platform_core.security.service_acl import GATEWAY_ADMIN, NOTIFICATIONS, SAMIIR_AGENT, SCHEDULING
from platform_core.security.service_auth import RequestContext

router = APIRouter(prefix="/internal")
AgentCtx = Annotated[RequestContext, Depends(internal_caller(SAMIIR_AGENT))]
SystemCtx = Annotated[RequestContext, Depends(internal_caller(SAMIIR_AGENT, SCHEDULING))]
NotifyCtx = Annotated[RequestContext, Depends(internal_caller(NOTIFICATIONS))]
AdminCtx = Annotated[RequestContext, Depends(internal_caller(GATEWAY_ADMIN))]
Limit = Annotated[int, Query(ge=1, le=200)]
Offset = Annotated[int, Query(ge=0)]


def _svc(rt: ServiceRuntime) -> CrmService:
    return rt.extras["crm"]


def _actor(ctx: RequestContext) -> tuple[str, str]:
    return ctx.principal.actor_type.value, ctx.principal.subject


class ActivityOut(BaseModel):
    id: uuid.UUID
    contact_id: uuid.UUID | None
    opportunity_id: uuid.UUID | None
    actor_type: str
    actor_id: str
    activity_type: str
    summary: str
    details: dict
    occurred_at: object


# ------------------------------------------------------------------ SAMIIR tool endpoints
@router.post("/samiir/contacts", response_model=ContactRef)
async def capture_contact(body: CaptureContactRequest, ctx: AgentCtx, rt: RuntimeDep) -> ContactRef:
    rt.policy.require(ctx, P.CONTACT_SUBMIT)
    async with rt.require_db().tenant_session(ctx.tenant_id, actor="agent:SAMIIR") as s:
        ref = await _svc(rt).capture_contact(s, ctx.tenant_id, body, "SAMIIR")
    instruments().crm_activities.add(1, {"type": "contact.captured"})
    await rt.audit.record(ctx, action="crm.contact.capture", result="success", agent_name="SAMIIR",
                          target_type="contact", target_id=ref.contact_id,
                          metadata={"created": ref.created, "source": body.source})
    await rt.realtime.publish(ctx.tenant_id, "samiir", "lead.updated",
                              {"contact_id": ref.contact_id, "opportunity_id": ref.opportunity_id})
    return ref


@router.post("/samiir/qualify", response_model=QualifyLeadResponse)
async def qualify(body: QualifyLeadRequest, ctx: AgentCtx, rt: RuntimeDep) -> QualifyLeadResponse:
    rt.policy.require(ctx, P.CONTACT_SUBMIT)
    async with rt.require_db().tenant_session(ctx.tenant_id, actor="agent:SAMIIR") as s:
        resp = await _svc(rt).qualify(s, ctx.tenant_id, body, "SAMIIR")
    await rt.audit.record(ctx, action="crm.lead.qualify", result="success", agent_name="SAMIIR",
                          target_type="opportunity", target_id=resp.opportunity_id,
                          metadata={"stage": resp.stage, "missing": resp.missing})
    await rt.realtime.publish(ctx.tenant_id, "samiir", "lead.updated",
                              {"opportunity_id": resp.opportunity_id, "stage": resp.stage})
    return resp


@router.post("/activities", status_code=201)
async def add_activity(body: ActivityIn, ctx: SystemCtx, rt: RuntimeDep) -> dict:
    rt.policy.require(ctx, P.INTERNAL_EXECUTE)
    async with rt.require_db().tenant_session(ctx.tenant_id, actor=ctx.caller) as s:
        a = await _svc(rt).add_activity(s, ctx.tenant_id, actor_type="service", actor_id=ctx.caller,
                                        activity_type=body.activity_type, summary=body.summary,
                                        contact_id=body.contact_id,
                                        opportunity_id=body.opportunity_id, details=body.details)
        await s.flush()
        activity_id = a.id
    instruments().crm_activities.add(1, {"type": body.activity_type})
    return {"id": activity_id}


@router.post("/stage-events", response_model=OpportunityOut)
async def stage_event(body: InternalStageEvent, ctx: SystemCtx, rt: RuntimeDep) -> OpportunityOut:
    rt.policy.require(ctx, P.INTERNAL_EXECUTE)
    async with rt.require_db().tenant_session(ctx.tenant_id, actor=ctx.caller) as s:
        opp = await _svc(rt).system_stage_event(s, ctx.tenant_id, body.contact_id,
                                                body.opportunity_id, body.stage,
                                                body.activity_summary, body.details, ctx.caller)
        out = OpportunityOut.model_validate(opp, from_attributes=True)
    await rt.audit.record(ctx, action="crm.pipeline.system_stage", result="success",
                          target_type="opportunity", target_id=out.id,
                          metadata={"stage": body.stage.value})
    await rt.realtime.publish(ctx.tenant_id, "samiir", "pipeline.changed",
                              {"opportunity_id": out.id, "stage": out.stage})
    return out


@router.get("/contacts/{contact_id}/delivery", response_model=ContactDelivery)
async def delivery(contact_id: uuid.UUID, ctx: NotifyCtx, rt: RuntimeDep) -> ContactDelivery:
    rt.policy.require(ctx, P.INTERNAL_EXECUTE)
    async with rt.require_db().tenant_session(ctx.tenant_id, actor=ctx.caller) as s:
        return await _svc(rt).delivery(s, contact_id)


# ------------------------------------------------------------------------- admin
@router.get("/contacts", response_model=Page[ContactOut])
async def list_contacts(ctx: AdminCtx, rt: RuntimeDep, limit: Limit = 50, offset: Offset = 0,
                        q: Annotated[str | None, Query(max_length=200)] = None) -> Page[ContactOut]:
    rt.policy.require(ctx, P.CRM_READ)
    async with rt.require_db().tenant_session(ctx.tenant_id) as s:
        rows, total = await _svc(rt).list_contacts(s, ctx.tenant_id, q, limit, offset)
        return Page(items=[_svc(rt).contact_out(c) for c in rows], total=total, limit=limit,
                    offset=offset)


@router.post("/contacts", response_model=ContactOut, status_code=201)
async def create_contact(body: ContactIn, ctx: AdminCtx, rt: RuntimeDep) -> ContactOut:
    rt.policy.require(ctx, P.CRM_WRITE)
    async with rt.require_db().tenant_session(ctx.tenant_id, actor=ctx.principal.subject) as s:
        out = _svc(rt).contact_out(await _svc(rt).create_contact(s, ctx.tenant_id, body))
    await rt.audit.record(ctx, action="crm.contact.create", result="success",
                          target_type="contact", target_id=out.id)
    return out


@router.get("/contacts/{contact_id}")
async def get_contact(contact_id: uuid.UUID, ctx: AdminCtx, rt: RuntimeDep) -> dict:
    rt.policy.require(ctx, P.CRM_READ)
    async with rt.require_db().tenant_session(ctx.tenant_id) as s:
        svc = _svc(rt)
        contact = await svc._contact(s, contact_id)
        opps = (await s.scalars(select(Opportunity).where(
            Opportunity.contact_id == contact_id, Opportunity.deleted_at.is_(None)))).all()
        acts = (await s.scalars(select(CrmActivity).where(CrmActivity.contact_id == contact_id)
                                .order_by(CrmActivity.occurred_at.desc()).limit(100))).all()
        notes = (await s.scalars(select(CrmNote).where(CrmNote.contact_id == contact_id,
                                                        CrmNote.deleted_at.is_(None))
                                 .order_by(CrmNote.created_at.desc()))).all()
        return {
            "contact": svc.contact_out(contact).model_dump(mode="json"),
            "opportunities": [OpportunityOut.model_validate(o, from_attributes=True)
                              .model_dump(mode="json") for o in opps],
            "activities": [ActivityOut.model_validate(a, from_attributes=True)
                           .model_dump(mode="json") for a in acts],
            "notes": [{"id": str(n.id), "body": n.body, "author_id": n.author_id,
                       "created_at": n.created_at.isoformat()} for n in notes],
        }


@router.patch("/contacts/{contact_id}", response_model=ContactOut)
async def update_contact(contact_id: uuid.UUID, body: ContactIn, ctx: AdminCtx,
                         rt: RuntimeDep) -> ContactOut:
    rt.policy.require(ctx, P.CRM_WRITE)
    async with rt.require_db().tenant_session(ctx.tenant_id, actor=ctx.principal.subject) as s:
        out = _svc(rt).contact_out(await _svc(rt).update_contact(s, ctx.tenant_id, contact_id, body))
    await rt.audit.record(ctx, action="crm.contact.update", result="success",
                          target_type="contact", target_id=contact_id,
                          metadata={"fields": sorted(body.model_dump(exclude_unset=True))})
    return out


@router.delete("/contacts/{contact_id}", status_code=204)
async def delete_contact(contact_id: uuid.UUID, ctx: AdminCtx, rt: RuntimeDep) -> None:
    rt.policy.require(ctx, P.CRM_WRITE)
    async with rt.require_db().tenant_session(ctx.tenant_id, actor=ctx.principal.subject) as s:
        await _svc(rt).soft_delete_contact(s, contact_id)
    await rt.audit.record(ctx, action="crm.contact.erase", result="success",
                          target_type="contact", target_id=contact_id, risk_level="MEDIUM")


@router.get("/companies", response_model=Page[CompanyOut])
async def list_companies(ctx: AdminCtx, rt: RuntimeDep, limit: Limit = 50, offset: Offset = 0,
                         q: Annotated[str | None, Query(max_length=200)] = None) -> Page[CompanyOut]:
    rt.policy.require(ctx, P.CRM_READ)
    async with rt.require_db().tenant_session(ctx.tenant_id) as s:
        stmt = select(Company).where(Company.deleted_at.is_(None))
        if q:
            stmt = stmt.where(Company.name.ilike(f"%{q.replace('%', '')}%"))
        total = await s.scalar(select(func.count()).select_from(stmt.subquery()))
        rows = (await s.scalars(stmt.order_by(Company.name).limit(limit).offset(offset))).all()
        return Page(items=[CompanyOut.model_validate(c, from_attributes=True) for c in rows],
                    total=int(total or 0), limit=limit, offset=offset)


@router.post("/companies", response_model=CompanyOut, status_code=201)
async def create_company(body: CompanyIn, ctx: AdminCtx, rt: RuntimeDep) -> CompanyOut:
    rt.policy.require(ctx, P.CRM_WRITE)
    async with rt.require_db().tenant_session(ctx.tenant_id, actor=ctx.principal.subject) as s:
        c = Company(tenant_id=ctx.tenant_id, **body.model_dump())
        s.add(c)
        await s.flush()
        out = CompanyOut.model_validate(c, from_attributes=True)
    await rt.audit.record(ctx, action="crm.company.create", result="success",
                          target_type="company", target_id=out.id)
    return out


@router.patch("/companies/{company_id}", response_model=CompanyOut)
async def update_company(company_id: uuid.UUID, body: CompanyIn, ctx: AdminCtx,
                         rt: RuntimeDep) -> CompanyOut:
    rt.policy.require(ctx, P.CRM_WRITE)
    async with rt.require_db().tenant_session(ctx.tenant_id, actor=ctx.principal.subject) as s:
        c = await s.get(Company, company_id)
        if c is None or c.deleted_at is not None:
            raise NotFound()
        for k, v in body.model_dump(exclude_unset=True).items():
            setattr(c, k, v)
        await s.flush()
        return CompanyOut.model_validate(c, from_attributes=True)


@router.get("/opportunities", response_model=Page[OpportunityOut])
async def list_opportunities(ctx: AdminCtx, rt: RuntimeDep, limit: Limit = 50, offset: Offset = 0,
                             stage: PipelineStage | None = None,
                             leads_only: bool = False) -> Page[OpportunityOut]:
    rt.policy.require(ctx, P.CRM_READ)
    async with rt.require_db().tenant_session(ctx.tenant_id) as s:
        stmt = select(Opportunity).where(Opportunity.deleted_at.is_(None))
        if stage:
            stmt = stmt.where(Opportunity.stage == stage.value)
        if leads_only:
            stmt = stmt.where(Opportunity.stage.in_(["NEW_LEAD", "QUALIFIED"]))
        total = await s.scalar(select(func.count()).select_from(stmt.subquery()))
        rows = (await s.scalars(stmt.order_by(Opportunity.updated_at.desc())
                                .limit(limit).offset(offset))).all()
        return Page(items=[OpportunityOut.model_validate(o, from_attributes=True) for o in rows],
                    total=int(total or 0), limit=limit, offset=offset)


@router.post("/opportunities", response_model=OpportunityOut, status_code=201)
async def create_opportunity(body: OpportunityIn, ctx: AdminCtx, rt: RuntimeDep) -> OpportunityOut:
    rt.policy.require(ctx, P.CRM_WRITE)
    async with rt.require_db().tenant_session(ctx.tenant_id, actor=ctx.principal.subject) as s:
        o = Opportunity(tenant_id=ctx.tenant_id, **body.model_dump())
        s.add(o)
        await s.flush()
        await s.refresh(o)
        out = OpportunityOut.model_validate(o, from_attributes=True)
    await rt.audit.record(ctx, action="crm.opportunity.create", result="success",
                          target_type="opportunity", target_id=out.id)
    return out


@router.patch("/opportunities/{opp_id}", response_model=OpportunityOut)
async def update_opportunity(opp_id: uuid.UUID, body: OpportunityPatch, ctx: AdminCtx,
                             rt: RuntimeDep) -> OpportunityOut:
    rt.policy.require(ctx, P.CRM_WRITE)
    from platform_core.errors import Conflict

    async with rt.require_db().tenant_session(ctx.tenant_id, actor=ctx.principal.subject) as s:
        o = await _svc(rt)._opportunity(s, opp_id)
        if o.version != body.expected_version:
            raise Conflict("opportunity was modified concurrently")
        for k, v in body.model_dump(exclude_unset=True, exclude={"expected_version"}).items():
            setattr(o, k, v)
        o.version += 1
        await s.flush()
        await s.refresh(o)
        return OpportunityOut.model_validate(o, from_attributes=True)


@router.post("/opportunities/{opp_id}/stage", response_model=OpportunityOut)
async def change_stage(opp_id: uuid.UUID, body: StageChangeRequest, ctx: AdminCtx,
                       rt: RuntimeDep) -> OpportunityOut:
    rt.policy.require(ctx, P.CRM_WRITE)
    actor_type, actor_id = _actor(ctx)
    async with rt.require_db().tenant_session(ctx.tenant_id, actor=actor_id) as s:
        o = await _svc(rt).change_stage(s, ctx.tenant_id, opp_id, body.stage, actor_type=actor_type,
                                        actor_id=actor_id, reason=body.reason,
                                        expected_version=body.expected_version,
                                        human=ctx.principal.actor_type is ActorType.USER)
        await s.flush()
        await s.refresh(o)
        out = OpportunityOut.model_validate(o, from_attributes=True)
    await rt.audit.record(ctx, action="crm.pipeline.stage_change", result="success",
                          target_type="opportunity", target_id=opp_id,
                          metadata={"stage": body.stage.value})
    await rt.realtime.publish(ctx.tenant_id, "samiir", "pipeline.changed",
                              {"opportunity_id": opp_id, "stage": body.stage.value})
    return out


@router.get("/pipeline")
async def pipeline(ctx: AdminCtx, rt: RuntimeDep) -> dict:
    rt.policy.require(ctx, P.CRM_READ)
    async with rt.require_db().tenant_session(ctx.tenant_id) as s:
        return {"stages": await _svc(rt).pipeline(s)}


@router.get("/metrics")
async def metrics(ctx: AdminCtx, rt: RuntimeDep) -> dict:
    rt.policy.require(ctx, P.CRM_READ)
    async with rt.require_db().tenant_session(ctx.tenant_id) as s:
        return await _svc(rt).metrics(s)


@router.get("/activities", response_model=list[ActivityOut])
async def list_activities(ctx: AdminCtx, rt: RuntimeDep, limit: Limit = 50,
                          opportunity_id: uuid.UUID | None = None) -> list[ActivityOut]:
    rt.policy.require(ctx, P.CRM_READ)
    async with rt.require_db().tenant_session(ctx.tenant_id) as s:
        stmt = select(CrmActivity).order_by(CrmActivity.occurred_at.desc()).limit(limit)
        if opportunity_id:
            stmt = stmt.where(CrmActivity.opportunity_id == opportunity_id)
        return [ActivityOut.model_validate(a, from_attributes=True)
                for a in (await s.scalars(stmt)).all()]


@router.post("/notes", status_code=201)
async def add_note(body: NoteIn, ctx: AdminCtx, rt: RuntimeDep) -> dict:
    rt.policy.require(ctx, P.CRM_WRITE)
    actor_type, actor_id = _actor(ctx)
    async with rt.require_db().tenant_session(ctx.tenant_id, actor=actor_id) as s:
        n = CrmNote(tenant_id=ctx.tenant_id, contact_id=body.contact_id,
                    opportunity_id=body.opportunity_id, author_type=actor_type, author_id=actor_id,
                    body=body.body)
        s.add(n)
        await s.flush()
        return {"id": n.id}


@router.get("/tasks")
async def list_tasks(ctx: AdminCtx, rt: RuntimeDep, status: str = "OPEN", limit: Limit = 100
                     ) -> list[dict]:
    rt.policy.require(ctx, P.CRM_READ)
    async with rt.require_db().tenant_session(ctx.tenant_id) as s:
        rows = (await s.scalars(select(CrmTask).where(CrmTask.status == status)
                                .order_by(CrmTask.due_at.nulls_last()).limit(limit))).all()
        return [{"id": t.id, "title": t.title, "status": t.status, "due_at": t.due_at,
                 "contact_id": t.contact_id, "opportunity_id": t.opportunity_id,
                 "assignee_id": t.assignee_id} for t in rows]


@router.post("/tasks", status_code=201)
async def create_task(body: TaskIn, ctx: AdminCtx, rt: RuntimeDep) -> dict:
    rt.policy.require(ctx, P.CRM_WRITE)
    async with rt.require_db().tenant_session(ctx.tenant_id, actor=ctx.principal.subject) as s:
        t = CrmTask(tenant_id=ctx.tenant_id, **body.model_dump())
        s.add(t)
        await s.flush()
        return {"id": t.id}


@router.patch("/tasks/{task_id}")
async def update_task(task_id: uuid.UUID, body: TaskPatch, ctx: AdminCtx, rt: RuntimeDep) -> dict:
    rt.policy.require(ctx, P.CRM_WRITE)
    from datetime import UTC, datetime

    async with rt.require_db().tenant_session(ctx.tenant_id, actor=ctx.principal.subject) as s:
        t = await s.get(CrmTask, task_id)
        if t is None:
            raise NotFound()
        for k, v in body.model_dump(exclude_unset=True).items():
            setattr(t, k, v)
        if body.status == "DONE":
            t.completed_at = datetime.now(UTC)
        return {"id": t.id, "status": t.status}
