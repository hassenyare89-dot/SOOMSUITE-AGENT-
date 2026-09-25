from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from approval_service.policies import POLICIES, policy_for
from approval_service.service import ApprovalService
from platform_core.app import RuntimeDep, ServiceRuntime, internal_caller
from platform_core.db.models import ApprovalRequest
from platform_core.errors import Forbidden, ValidationFailed
from platform_core.schemas.common import Page, StrictModel
from platform_core.security.principal import ActorType
from platform_core.security.rbac import P
from platform_core.security.service_acl import FATMA_SOC, GATEWAY_ADMIN, SCANNER_CONTROLLER
from platform_core.security.service_auth import RequestContext

router = APIRouter(prefix="/internal/approvals")
RequesterCtx = Annotated[RequestContext, Depends(internal_caller(FATMA_SOC, SCANNER_CONTROLLER))]
ExecutorCtx = Annotated[RequestContext, Depends(internal_caller(FATMA_SOC, SCANNER_CONTROLLER))]
AdminCtx = Annotated[RequestContext, Depends(internal_caller(GATEWAY_ADMIN))]
FatmaCtx = Annotated[RequestContext, Depends(internal_caller(FATMA_SOC))]


def _svc(rt: ServiceRuntime) -> ApprovalService:
    return rt.extras["approvals"]


class ApprovalOut(BaseModel):
    id: uuid.UUID
    action_type: str
    action_payload: dict
    payload_hash: str
    target_type: str | None
    target_id: uuid.UUID | None
    requested_by: str
    requested_by_type: str
    requested_via: str
    requested_at: datetime
    reason: str
    risk_level: str
    expires_at: datetime
    status: str
    approved_by: str | None
    approved_at: datetime | None
    decision_comment: str | None
    approval_signature: str | None
    consumed_at: datetime | None


class CreateIn(StrictModel):
    action_type: str = Field(pattern=r"^[a-z_]+\.[a-z_]+$")
    payload: dict[str, Any]
    reason: str = Field(min_length=5, max_length=2000)
    target_type: str | None = Field(default=None, max_length=40)
    target_id: uuid.UUID | None = None
    # Human on whose behalf the request is made (when the requester service acts for a user).
    on_behalf_of: str | None = Field(default=None, max_length=256)


class DecideIn(StrictModel):
    decision: str = Field(pattern="^(approve|reject)$")
    payload_hash: str = Field(pattern="^[0-9a-f]{64}$")
    comment: str | None = Field(default=None, max_length=1000)


class ConsumeIn(StrictModel):
    action_type: str = Field(pattern=r"^[a-z_]+\.[a-z_]+$")
    payload: dict[str, Any]


def _requester(ctx: RequestContext, body: CreateIn) -> tuple[str, str]:
    p = ctx.principal
    if p.actor_type is ActorType.USER:
        return p.subject, "user"
    return body.on_behalf_of or f"agent:{ctx.caller}", "agent" if not body.on_behalf_of else "user"


@router.post("", response_model=ApprovalOut, status_code=201)
async def create(body: CreateIn, ctx: RequesterCtx, rt: RuntimeDep) -> ApprovalOut:
    rt.policy.require_any(ctx, {P.INTERNAL_EXECUTE, P.DEFENSE_REQUEST, P.SCAN_REQUEST})
    requested_by, rtype = _requester(ctx, body)
    async with rt.require_db().tenant_session(ctx.tenant_id, actor=requested_by) as s:
        req = await _svc(rt).create(s, ctx.tenant_id, action_type=body.action_type,
                                    payload=body.payload, reason=body.reason,
                                    target_type=body.target_type, target_id=body.target_id,
                                    requested_by=requested_by, requested_by_type=rtype,
                                    requested_via=ctx.caller)
        out = ApprovalOut.model_validate(req, from_attributes=True)
    await rt.audit.record(ctx, action="approval.request", result="pending", approval_id=out.id,
                          target_type=body.target_type, target_id=body.target_id,
                          risk_level=out.risk_level,
                          metadata={"action_type": body.action_type,
                                    "payload_hash": out.payload_hash})
    return out


@router.post("/preapproved", response_model=ApprovalOut, status_code=201)
async def preapproved(body: CreateIn, ctx: FatmaCtx, rt: RuntimeDep) -> ApprovalOut:
    rt.policy.require(ctx, P.INTERNAL_EXECUTE)
    async with rt.require_db().tenant_session(ctx.tenant_id, actor="agent:FATMA") as s:
        req = await _svc(rt).preapprove(s, ctx.tenant_id, action_type=body.action_type,
                                        payload=body.payload, reason=body.reason,
                                        target_type=body.target_type, target_id=body.target_id,
                                        requested_by="agent:FATMA")
        out = ApprovalOut.model_validate(req, from_attributes=True)
    await rt.audit.record(ctx, action="approval.preapproved", result="success", approval_id=out.id,
                          risk_level=out.risk_level, metadata={"action_type": body.action_type,
                                                               "payload_hash": out.payload_hash})
    return out


@router.post("/{approval_id}/decide", response_model=ApprovalOut)
async def decide(approval_id: uuid.UUID, body: DecideIn, ctx: AdminCtx, rt: RuntimeDep
                 ) -> ApprovalOut:
    if ctx.principal.actor_type is not ActorType.USER:
        raise Forbidden("approvals require a human decision")
    async with rt.require_db().tenant_session(ctx.tenant_id, actor=f"user:{ctx.principal.subject}"
                                              ) as s:
        existing = await _svc(rt).get(s, approval_id)
        pol = policy_for(existing.action_type)
        if pol is None:
            raise ValidationFailed("unknown action type")
        rt.policy.require(ctx, pol.approver_permission)
        req = await _svc(rt).decide(s, approval_id, approve=body.decision == "approve",
                                    approver=ctx.principal.subject, echoed_hash=body.payload_hash,
                                    comment=body.comment)
        out = ApprovalOut.model_validate(req, from_attributes=True)
    await rt.audit.record(ctx, action=f"approval.{body.decision}", result="success",
                          approval_id=approval_id, risk_level=out.risk_level,
                          metadata={"action_type": out.action_type,
                                    "payload_hash": out.payload_hash})
    await rt.realtime.publish(ctx.tenant_id, "fatma", "approval.decided",
                              {"approval_id": approval_id, "status": out.status})
    return out


@router.post("/{approval_id}/consume", response_model=ApprovalOut)
async def consume(approval_id: uuid.UUID, body: ConsumeIn, ctx: ExecutorCtx, rt: RuntimeDep
                  ) -> ApprovalOut:
    rt.policy.require_any(ctx, {P.INTERNAL_EXECUTE, P.DEFENSE_EXECUTE, P.SCAN_REQUEST})
    try:
        async with rt.require_db().tenant_session(ctx.tenant_id, actor=ctx.caller) as s:
            req = await _svc(rt).consume(s, approval_id, action_type=body.action_type,
                                         payload=body.payload, consumer=ctx.caller)
            out = ApprovalOut.model_validate(req, from_attributes=True)
    except Exception as exc:
        await rt.audit.record(ctx, action="approval.consume", result="denied",
                              approval_id=approval_id, risk_level="HIGH",
                              metadata={"reason": type(exc).__name__,
                                        "action_type": body.action_type})
        raise
    await rt.audit.record(ctx, action="approval.consume", result="success", approval_id=approval_id,
                          risk_level=out.risk_level, metadata={"action_type": out.action_type})
    return out


@router.post("/{approval_id}/cancel", response_model=ApprovalOut)
async def cancel(approval_id: uuid.UUID, ctx: AdminCtx, rt: RuntimeDep) -> ApprovalOut:
    async with rt.require_db().tenant_session(ctx.tenant_id, actor=ctx.principal.subject) as s:
        return ApprovalOut.model_validate(
            await _svc(rt).cancel(s, approval_id, ctx.principal.subject), from_attributes=True)


@router.get("", response_model=Page[ApprovalOut])
async def list_approvals(ctx: Annotated[RequestContext, Depends(internal_caller(GATEWAY_ADMIN,
                                                                                FATMA_SOC))],
                         rt: RuntimeDep,
                         status: Annotated[str | None, Query(max_length=20)] = None,
                         limit: Annotated[int, Query(ge=1, le=200)] = 50,
                         offset: Annotated[int, Query(ge=0)] = 0) -> Page[ApprovalOut]:
    rt.policy.require_any(ctx, {P.APPROVAL_READ, P.INTERNAL_EXECUTE})
    async with rt.require_db().tenant_session(ctx.tenant_id) as s:
        stmt = select(ApprovalRequest)
        if status:
            stmt = stmt.where(ApprovalRequest.status == status)
        total = await s.scalar(select(func.count()).select_from(stmt.subquery()))
        rows = (await s.scalars(stmt.order_by(ApprovalRequest.requested_at.desc())
                                .limit(limit).offset(offset))).all()
        return Page(items=[ApprovalOut.model_validate(r, from_attributes=True) for r in rows],
                    total=int(total or 0), limit=limit, offset=offset)


@router.get("/policies")
async def policies(ctx: AdminCtx, rt: RuntimeDep) -> list[dict]:
    rt.policy.require_any(ctx, {P.APPROVAL_READ, P.APPROVAL_POLICY_MANAGE})
    return [{"action_type": k, "risk": v.risk.value, "approver_permission": v.approver_permission,
             "ttl_seconds": int(v.ttl.total_seconds()), "preapprovable": v.preapprovable,
             "max_preapproved_ttl_seconds": v.max_preapproved_ttl_seconds}
            for k, v in sorted(POLICIES.items())]


@router.get("/{approval_id}", response_model=ApprovalOut)
async def get(approval_id: uuid.UUID, rt: RuntimeDep,
              ctx: Annotated[RequestContext, Depends(internal_caller(GATEWAY_ADMIN, FATMA_SOC,
                                                                     SCANNER_CONTROLLER))]
              ) -> ApprovalOut:
    rt.policy.require_any(ctx, {P.APPROVAL_READ, P.INTERNAL_EXECUTE, P.SCAN_READ})
    async with rt.require_db().tenant_session(ctx.tenant_id) as s:
        return ApprovalOut.model_validate(await _svc(rt).get(s, approval_id), from_attributes=True)
