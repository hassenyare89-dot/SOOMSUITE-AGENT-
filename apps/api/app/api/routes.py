from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status

from app.agents.fatma import FatmaService
from app.agents.samiir import SamiirService
from app.core.auth import PrincipalDep
from app.core.config import Settings, get_settings
from app.core.policy import PolicyEngine
from app.domain.schemas import ChatRequest, ChatResponse, SecurityEventIn
from app.integrations.whatsapp import parse_messages, verify_signature

router = APIRouter()
policy = PolicyEngine()


@router.get("/healthz")
async def health() -> dict:
    return {"status": "ok"}


@router.post("/v1/samiir/chat", response_model=ChatResponse)
async def chat(body: ChatRequest, principal: PrincipalDep) -> ChatResponse:
    policy.require(principal, "samiir:chat")
    return await SamiirService().respond(body)


@router.post("/v1/fatma/events/{tenant_id}")
async def event(tenant_id, body: SecurityEventIn, principal: PrincipalDep) -> dict:
    policy.require(principal, "fatma:analyze", body.tenant_id)
    if str(body.tenant_id) != tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "resource not found")
    return await FatmaService().analyze(body)


@router.get("/v1/whatsapp/webhook")
async def verify_webhook(
    hub_mode: str | None = None,
    hub_verify_token: str | None = None,
    hub_challenge: str | None = None,
    settings: Settings = Depends(get_settings),
):
    if hub_mode == "subscribe" and hub_verify_token == settings.meta_verify_token:
        return int(hub_challenge or 0)
    raise HTTPException(status.HTTP_403_FORBIDDEN, "verification failed")


@router.post("/v1/whatsapp/webhook")
async def whatsapp(
    request: Request,
    x_hub_signature_256: Annotated[str | None, Header()] = None,
    settings: Settings = Depends(get_settings),
):
    raw = await request.body()
    if not verify_signature(raw, x_hub_signature_256, settings):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid webhook signature")
    return {"accepted": True, "messages": len(parse_messages(await request.json()))}
