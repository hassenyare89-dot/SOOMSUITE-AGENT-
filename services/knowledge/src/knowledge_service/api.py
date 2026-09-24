from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from knowledge_service.service import DocumentIn, DocumentOut, DocumentPatch, KnowledgeService
from platform_core.app import RuntimeDep, internal_caller
from platform_core.schemas.common import Page
from platform_core.schemas.knowledge import PricingAnswer, SearchRequest, SearchResponse
from platform_core.security.principal import ActorType
from platform_core.security.rbac import P
from platform_core.security.service_acl import GATEWAY_ADMIN, SAMIIR_AGENT
from platform_core.security.service_auth import RequestContext

router = APIRouter(prefix="/internal")
AgentCtx = Annotated[RequestContext, Depends(internal_caller(SAMIIR_AGENT))]
AdminCtx = Annotated[RequestContext, Depends(internal_caller(GATEWAY_ADMIN))]


def _svc(rt) -> KnowledgeService:  # noqa: ANN001
    return rt.extras["knowledge"]


def _user_id(ctx: RequestContext) -> uuid.UUID | None:
    if ctx.principal.actor_type is ActorType.USER:
        return uuid.UUID(ctx.principal.subject)
    return None


class ApproveBody(BaseModel):
    acknowledge_flags: bool = False


@router.post("/search", response_model=SearchResponse)
async def search(body: SearchRequest, ctx: AgentCtx, rt: RuntimeDep) -> SearchResponse:
    rt.policy.require(ctx, P.SAMIIR_CHAT)
    async with rt.require_db().tenant_session(ctx.tenant_id) as s:
        return await _svc(rt).search(s, body)


@router.get("/pricing", response_model=list[PricingAnswer])
async def pricing(ctx: AgentCtx, rt: RuntimeDep,
                  service: Annotated[str | None, Query(max_length=200)] = None
                  ) -> list[PricingAnswer]:
    rt.policy.require(ctx, P.SAMIIR_CHAT)
    async with rt.require_db().tenant_session(ctx.tenant_id) as s:
        return await _svc(rt).pricing(s, service)


@router.get("/documents", response_model=Page[DocumentOut])
async def list_documents(ctx: AdminCtx, rt: RuntimeDep,
                         status: Annotated[str | None, Query(max_length=32)] = None,
                         category: Annotated[str | None, Query(max_length=64)] = None,
                         q: Annotated[str | None, Query(max_length=100)] = None,
                         limit: Annotated[int, Query(ge=1, le=200)] = 50,
                         offset: Annotated[int, Query(ge=0)] = 0) -> Page[DocumentOut]:
    rt.policy.require(ctx, P.KNOWLEDGE_READ)
    async with rt.require_db().tenant_session(ctx.tenant_id) as s:
        rows, total = await _svc(rt).list(s, status=status, category=category, q=q,
                                          limit=limit, offset=offset)
        return Page(items=[DocumentOut.model_validate(r, from_attributes=True) for r in rows],
                    total=total, limit=limit, offset=offset)


@router.post("/documents", response_model=DocumentOut, status_code=201)
async def create_document(body: DocumentIn, ctx: AdminCtx, rt: RuntimeDep) -> DocumentOut:
    rt.policy.require(ctx, P.KNOWLEDGE_WRITE)
    async with rt.require_db().tenant_session(ctx.tenant_id, actor=ctx.principal.subject) as s:
        doc = await _svc(rt).create(s, ctx.tenant_id, body, _user_id(ctx))
        out = DocumentOut.model_validate(doc, from_attributes=True)
    await rt.audit.record(ctx, action="knowledge.create", result="success",
                          target_type="knowledge_document", target_id=out.id,
                          metadata={"category": out.category, "flags": out.injection_flags})
    return out


@router.get("/documents/{doc_id}", response_model=DocumentOut)
async def get_document(doc_id: uuid.UUID, ctx: AdminCtx, rt: RuntimeDep) -> DocumentOut:
    rt.policy.require(ctx, P.KNOWLEDGE_READ)
    async with rt.require_db().tenant_session(ctx.tenant_id) as s:
        return DocumentOut.model_validate(await _svc(rt).get(s, doc_id), from_attributes=True)


@router.get("/documents/{doc_id}/versions", response_model=list[DocumentOut])
async def versions(doc_id: uuid.UUID, ctx: AdminCtx, rt: RuntimeDep) -> list[DocumentOut]:
    rt.policy.require(ctx, P.KNOWLEDGE_READ)
    async with rt.require_db().tenant_session(ctx.tenant_id) as s:
        return [DocumentOut.model_validate(d, from_attributes=True)
                for d in await _svc(rt).versions(s, doc_id)]


@router.patch("/documents/{doc_id}", response_model=DocumentOut)
async def edit_document(doc_id: uuid.UUID, body: DocumentPatch, ctx: AdminCtx,
                        rt: RuntimeDep) -> DocumentOut:
    rt.policy.require(ctx, P.KNOWLEDGE_WRITE)
    async with rt.require_db().tenant_session(ctx.tenant_id, actor=ctx.principal.subject) as s:
        doc = await _svc(rt).edit(s, doc_id, body, _user_id(ctx))
        out = DocumentOut.model_validate(doc, from_attributes=True)
    await rt.audit.record(ctx, action="knowledge.edit", result="success",
                          target_type="knowledge_document", target_id=out.id,
                          metadata={"version": out.version})
    return out


@router.post("/documents/{doc_id}/submit", response_model=DocumentOut)
async def submit(doc_id: uuid.UUID, ctx: AdminCtx, rt: RuntimeDep) -> DocumentOut:
    rt.policy.require(ctx, P.KNOWLEDGE_WRITE)
    async with rt.require_db().tenant_session(ctx.tenant_id, actor=ctx.principal.subject) as s:
        return DocumentOut.model_validate(await _svc(rt).submit(s, doc_id), from_attributes=True)


@router.post("/documents/{doc_id}/approve", response_model=DocumentOut)
async def approve(doc_id: uuid.UUID, body: ApproveBody, ctx: AdminCtx,
                  rt: RuntimeDep) -> DocumentOut:
    rt.policy.require(ctx, P.KNOWLEDGE_APPROVE)
    approver = _user_id(ctx)
    if approver is None:
        from platform_core.errors import Forbidden

        raise Forbidden("approval requires a human user")
    async with rt.require_db().tenant_session(ctx.tenant_id, actor=ctx.principal.subject) as s:
        doc = await _svc(rt).approve(s, doc_id, approver, body.acknowledge_flags)
        out = DocumentOut.model_validate(doc, from_attributes=True)
    await rt.audit.record(ctx, action="knowledge.approve", result="success",
                          target_type="knowledge_document", target_id=out.id, risk_level="MEDIUM",
                          metadata={"version": out.version, "visibility": out.visibility})
    return out


@router.post("/documents/{doc_id}/archive", response_model=DocumentOut)
async def archive(doc_id: uuid.UUID, ctx: AdminCtx, rt: RuntimeDep) -> DocumentOut:
    rt.policy.require(ctx, P.KNOWLEDGE_APPROVE)
    async with rt.require_db().tenant_session(ctx.tenant_id, actor=ctx.principal.subject) as s:
        out = DocumentOut.model_validate(await _svc(rt).archive(s, doc_id), from_attributes=True)
    await rt.audit.record(ctx, action="knowledge.archive", result="success",
                          target_type="knowledge_document", target_id=out.id)
    return out
