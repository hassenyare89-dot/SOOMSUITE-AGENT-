"""Internet-facing routes: website chat widget, WhatsApp webhook, security-ingest webhooks."""

from __future__ import annotations

import hashlib
import secrets
import time
import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Query, Request, Response
from fastapi.responses import PlainTextResponse
from pydantic import EmailStr, Field

from api_gateway.common import (
    check_csrf,
    client_ip,
    cookie_name,
    csrf_token,
    read_cookie,
    runtime,
    to_response,
)
from platform_core.app import ServiceRuntime
from platform_core.errors import Forbidden, NotFound, RateLimited, ValidationFailed
from platform_core.schemas.common import StrictModel
from platform_core.security.principal import ActorType, Principal, Role
from platform_core.security.ratelimit import Limit, enforce

router = APIRouter()
EDGE = Principal(subject="edge", tenant_id=uuid.UUID(int=0), actor_type=ActorType.SERVICE,
                 roles=frozenset({Role.SYSTEM_SERVICE}))


def _rid(request: Request) -> str:
    return getattr(request.state, "request_id", secrets.token_hex(16))


async def _resolve_site(rt: ServiceRuntime, key: str, request_id: str) -> dict[str, Any]:
    cache: dict = rt.extras.setdefault("site_cache", {})
    hit = cache.get(key)
    if hit and hit[0] > time.monotonic():
        return hit[1]
    try:
        site = await rt.client("samiir-agent").get("/internal/widget/resolve", principal=EDGE,
                                                   request_id=request_id, params={"key": key})
    except NotFound:
        site = None
    cache[key] = (time.monotonic() + 60, site)
    if site is None:
        raise NotFound()
    return site


def _origin_allowed(request: Request, site: dict[str, Any], console: list[str]) -> None:
    origin = request.headers.get("origin")
    if origin is None:
        raise Forbidden("origin required")
    if origin not in site["allowed_origins"] and origin not in console:
        raise Forbidden("origin not allowed for this widget")


async def _session(rt: ServiceRuntime, request: Request, sid: str | None) -> dict[str, Any]:
    data = await rt.extras["widget_sessions"].get(sid)
    if data is None:
        raise NotFound("session expired")
    check_csrf(request, rt.extras["csrf_key"], sid or "")
    return data


def _principal(data: dict[str, Any], sid: str) -> Principal:
    return Principal(subject=f"ws:{hashlib.sha256(sid.encode()).hexdigest()[:16]}",
                     tenant_id=uuid.UUID(data["tenant_id"]), actor_type=ActorType.CUSTOMER,
                     roles=frozenset({Role.ANONYMOUS_CUSTOMER}), session_id=data["ref"])


async def _limits(rt: ServiceRuntime, ip: str, tenant: str | None = None,
                  session_ref: str | None = None) -> None:
    s = rt.settings
    limiter = rt.extras["limiter"]
    await enforce(limiter, f"ip:{ip}", Limit(s.widget_ip_requests_per_minute, 60))  # type: ignore[attr-defined]
    if tenant:
        await enforce(limiter, f"tenant:{tenant}", Limit(s.widget_tenant_messages_per_minute, 60))  # type: ignore[attr-defined]
    if session_ref:
        await enforce(limiter, f"ws:{session_ref}", Limit(s.widget_messages_per_minute, 60))  # type: ignore[attr-defined]


# ------------------------------------------------------------------------ widget
@router.get("/v1/widget/config")
async def widget_config(request: Request,
                        key: Annotated[str, Query(pattern="^pk_[A-Za-z0-9_-]{16,64}$")]) -> dict:
    rt = runtime(request)
    await _limits(rt, client_ip(request, rt.settings.trusted_proxy_cidrs))  # type: ignore[attr-defined]
    site = await _resolve_site(rt, key, _rid(request))
    return {"tenant_name": site["tenant_name"], "greeting": site["greeting"],
            "theme": site["theme"], "allowed_origins": site["allowed_origins"]}


class SessionIn(StrictModel):
    key: str = Field(pattern="^pk_[A-Za-z0-9_-]{16,64}$")


@router.post("/v1/widget/session")
async def widget_session(body: SessionIn, request: Request, response: Response) -> dict:
    rt = runtime(request)
    ip = client_ip(request, rt.settings.trusted_proxy_cidrs)  # type: ignore[attr-defined]
    await _limits(rt, ip)
    site = await _resolve_site(rt, body.key, _rid(request))
    _origin_allowed(request, site, rt.settings.allowed_origins)  # type: ignore[attr-defined]
    ttl = rt.settings.widget_session_ttl_seconds  # type: ignore[attr-defined]
    data = {"tenant_id": str(site["tenant_id"]), "site_id": str(site["site_id"]),
            "ref": secrets.token_hex(16), "created": time.time(),
            "ip_hash": hashlib.sha256(ip.encode()).hexdigest()[:16], "last_text": "",
            "repeat": 0}
    sid = await rt.extras["widget_sessions"].create(data, ttl)
    response.set_cookie(cookie_name(rt, "samiir_ws"), sid, max_age=ttl, path="/", httponly=True,
                        secure=rt.settings.cookie_secure,  # type: ignore[attr-defined]
                        samesite="none" if rt.settings.cookie_secure else "lax")  # type: ignore[attr-defined]
    if rt.settings.cookie_secure:  # type: ignore[attr-defined]
        # CHIPS: the widget runs in a third-party iframe; partition its cookie per top site.
        response.headers["set-cookie"] = response.headers["set-cookie"] + "; Partitioned"
    return {"csrf_token": csrf_token(rt.extras["csrf_key"], sid), "greeting": site["greeting"],
            "tenant_name": site["tenant_name"], "expires_in": ttl}


class WidgetMessage(StrictModel):
    text: str = Field(min_length=1, max_length=2000)
    selected_slot_token: str | None = Field(default=None, max_length=2000)
    timezone: str | None = Field(default=None, max_length=64)
    website: str | None = Field(default=None, max_length=200)  # honeypot: must stay empty


@router.post("/v1/widget/messages")
async def widget_message(body: WidgetMessage, request: Request) -> dict:
    rt = runtime(request)
    sid = read_cookie(request, "samiir_ws")
    data = await _session(rt, request, sid)
    ip = client_ip(request, rt.settings.trusted_proxy_cidrs)  # type: ignore[attr-defined]
    await _limits(rt, ip, data["tenant_id"], data["ref"])
    # Bot mitigation (layered, all server-side):
    if body.website:                                   # honeypot filled → bot
        raise ValidationFailed("message rejected")
    if time.time() - float(data["created"]) < 0.8:     # faster than any human
        raise RateLimited(retry_after=2)
    normalized = " ".join(body.text.lower().split())
    data["repeat"] = data["repeat"] + 1 if normalized == data["last_text"] else 0
    data["last_text"] = normalized
    await rt.extras["widget_sessions"].put(sid or "", data,
                                           rt.settings.widget_session_ttl_seconds)  # type: ignore[attr-defined]
    if data["repeat"] >= 3:
        raise RateLimited(retry_after=30)
    return await rt.client("samiir-agent").post(
        "/internal/chat", principal=_principal(data, sid or ""), request_id=_rid(request),
        json={"channel": "web", "conversation_ref": data["ref"], "text": body.text,
              "selected_slot_token": body.selected_slot_token,
              "customer_timezone": body.timezone})


@router.get("/v1/widget/messages")
async def widget_history(request: Request) -> dict:
    rt = runtime(request)
    sid = read_cookie(request, "samiir_ws")
    data = await _session(rt, request, sid)
    return await rt.client("samiir-agent").get("/internal/chat/history",
                                               principal=_principal(data, sid or ""),
                                               request_id=_rid(request))


class ContactForm(StrictModel):
    full_name: str = Field(min_length=1, max_length=120)
    email: EmailStr
    phone: str | None = Field(default=None, pattern=r"^\+?[1-9]\d{6,14}$")
    company_name: str | None = Field(default=None, max_length=200)
    consent_contact: bool
    consent_whatsapp: bool = False
    website: str | None = Field(default=None, max_length=200)


@router.post("/v1/widget/contact")
async def widget_contact(body: ContactForm, request: Request) -> dict:
    rt = runtime(request)
    sid = read_cookie(request, "samiir_ws")
    data = await _session(rt, request, sid)
    await _limits(rt, client_ip(request, rt.settings.trusted_proxy_cidrs),  # type: ignore[attr-defined]
                  data["tenant_id"], data["ref"])
    if body.website:
        raise ValidationFailed("rejected")
    return await rt.client("samiir-agent").post(
        "/internal/chat/contact", principal=_principal(data, sid or ""), request_id=_rid(request),
        json=body.model_dump(exclude={"website"}))


@router.post("/v1/widget/escalate")
async def widget_escalate(request: Request) -> dict:
    rt = runtime(request)
    sid = read_cookie(request, "samiir_ws")
    data = await _session(rt, request, sid)
    return await rt.client("samiir-agent").post(
        "/internal/chat/escalate", principal=_principal(data, sid or ""), request_id=_rid(request),
        json={"reason": "customer_requested"})


# ----------------------------------------------------------------- WhatsApp webhook
@router.get("/v1/whatsapp/webhook", response_class=PlainTextResponse)
async def whatsapp_verify(request: Request) -> Response:
    rt = runtime(request)
    await _limits(rt, client_ip(request, rt.settings.trusted_proxy_cidrs))  # type: ignore[attr-defined]
    upstream = await rt.client("whatsapp").request(
        "GET", "/internal/webhook", principal=EDGE, request_id=_rid(request),
        params=dict(request.query_params), raw=True)
    return to_response(upstream)


@router.post("/v1/whatsapp/webhook")
async def whatsapp_webhook(request: Request) -> Response:
    rt = runtime(request)
    body = await request.body()
    headers = {"X-Hub-Signature-256": request.headers.get("x-hub-signature-256", "")}
    upstream = await rt.client("whatsapp").request(
        "POST", "/internal/webhook", principal=EDGE, request_id=_rid(request), content=body,
        headers={**headers, "Content-Type": "application/json"}, raw=True, retries=0)
    return to_response(upstream)


# --------------------------------------------------------------- security ingestion
@router.post("/v1/ingest/{kind}/{key}")
async def ingest(kind: str, key: str, request: Request) -> Response:
    rt = runtime(request)
    ip = client_ip(request, rt.settings.trusted_proxy_cidrs)  # type: ignore[attr-defined]
    await enforce(rt.extras["limiter"], f"ingest:{key}", Limit(600, 60))
    body = await request.body()
    forwarded = {h: request.headers[h] for h in ("x-signature", "x-ingest-token",
                                                  "x-amz-firehose-access-key",
                                                  "content-encoding", "content-type")
                 if h in request.headers}
    upstream = await rt.client("security-ingest").request(
        "POST", f"/internal/ingest/{kind}/{key}", principal=EDGE, request_id=_rid(request),
        content=body, headers=forwarded, raw=True, retries=0)
    del ip
    return to_response(upstream)
