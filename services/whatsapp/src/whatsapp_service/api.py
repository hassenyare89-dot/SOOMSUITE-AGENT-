from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.responses import PlainTextResponse
from pydantic import Field

from platform_core.app import RuntimeDep, ServiceRuntime, internal_caller
from platform_core.errors import Forbidden
from platform_core.schemas.common import StrictModel
from platform_core.security.rbac import P
from platform_core.security.service_acl import (
    GATEWAY_ADMIN,
    GATEWAY_PUBLIC,
    NOTIFICATIONS,
    SAMIIR_AGENT,
)
from platform_core.security.service_auth import RequestContext
from whatsapp_service.service import WhatsAppService

router = APIRouter(prefix="/internal")
EdgeCtx = Annotated[RequestContext, Depends(internal_caller(GATEWAY_PUBLIC))]
SendCtx = Annotated[RequestContext, Depends(internal_caller(NOTIFICATIONS, SAMIIR_AGENT,
                                                            GATEWAY_ADMIN))]


def _svc(rt: ServiceRuntime) -> WhatsAppService:
    return rt.extras["whatsapp"]


@router.get("/webhook", response_class=PlainTextResponse)
async def verify(request: Request, ctx: EdgeCtx, rt: RuntimeDep) -> str:
    q = request.query_params
    if not _svc(rt).check_verification(q.get("hub.mode"), q.get("hub.verify_token")):
        raise Forbidden("verification failed")
    challenge = q.get("hub.challenge", "")
    if not challenge.isdigit() or len(challenge) > 64:
        raise Forbidden("verification failed")
    return challenge


@router.post("/webhook")
async def webhook(request: Request, ctx: EdgeCtx, rt: RuntimeDep) -> dict:
    raw = await request.body()
    return await _svc(rt).receive(raw, request.headers.get("x-hub-signature-256"),
                                  ctx.request_id)


class SendIn(StrictModel):
    to: str = Field(pattern=r"^\+?[1-9]\d{6,14}$")
    text: str | None = Field(default=None, max_length=4096)
    template: str | None = Field(default=None, pattern="^[a-z0-9_]{1,512}$")
    template_params: list[str] = Field(default_factory=list, max_length=10)
    idempotency_key: str = Field(min_length=8, max_length=200)


@router.post("/send")
async def send(body: SendIn, ctx: SendCtx, rt: RuntimeDep) -> dict:
    rt.policy.require_any(ctx, {P.INTERNAL_EXECUTE, P.TENANT_INTEGRATION_MANAGE})
    message_id = await _svc(rt).send(ctx.tenant_id, to=body.to, text_body=body.text,
                                     template=body.template, params=body.template_params,
                                     idempotency_key=body.idempotency_key)
    await rt.audit.record(ctx, action="whatsapp.send", result="success",
                          target_type="whatsapp_message", target_id=message_id,
                          metadata={"template": body.template, "caller": ctx.caller})
    return {"message_id": message_id}


@router.get("/status")
async def status(rt: RuntimeDep,
                 ctx: Annotated[RequestContext, Depends(internal_caller(GATEWAY_ADMIN))]) -> dict:
    rt.policy.require_any(ctx, {P.CHANNEL_READ, P.TENANT_INTEGRATION_MANAGE})
    try:
        pnid, _, config = await _svc(rt).tenant_sender(ctx.tenant_id)
    except Exception:
        return {"configured": False}
    return {"configured": True, "phone_number_id": pnid,
            "approved_templates": config.get("approved_templates", []),
            "graph_version": rt.settings.meta_graph_version}  # type: ignore[attr-defined]
