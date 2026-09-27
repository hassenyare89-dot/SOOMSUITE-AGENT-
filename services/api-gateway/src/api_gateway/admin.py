"""Staff console backend-for-frontend: SSO, sessions, CSRF, proxying, SSE, identity admin."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import secrets
import time
import uuid
from collections.abc import AsyncIterator
from typing import Annotated, Any
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import RedirectResponse, StreamingResponse
from pydantic import Field
from sqlalchemy import delete, func, select, text

from api_gateway.common import (
    check_csrf,
    check_origin,
    client_ip,
    cookie_name,
    csrf_token,
    read_cookie,
    runtime,
    to_response,
)
from platform_core.app import ServiceRuntime
from platform_core.db.models import Integration, RoleRow, Tenant, User, UserRole, WidgetSite
from platform_core.errors import Conflict, Forbidden, NotFound, Unauthenticated, ValidationFailed
from platform_core.events import channel
from platform_core.schemas.common import StrictModel
from platform_core.schemas.enums import FatmaMode
from platform_core.security.oidc import has_mfa
from platform_core.security.principal import ActorType, Principal, Role
from platform_core.security.ratelimit import Limit, enforce
from platform_core.security.rbac import MFA_REQUIRED, ROLE_PERMISSIONS, P, permissions_for
from platform_core.security.service_auth import RequestContext

router = APIRouter()
STAFF_ROLES = frozenset(Role) - {Role.ANONYMOUS_CUSTOMER, Role.AUTHENTICATED_CUSTOMER,
                                 Role.SYSTEM_SERVICE}
SECURITY_SIDE = frozenset({Role.SECURITY_ANALYST, Role.SECURITY_ENGINEER, Role.TENANT_ADMIN,
                           Role.PLATFORM_ADMIN})

# prefix -> (audience, internal path prefix, roles allowed to reach it at all)
ROUTES: dict[str, tuple[str, str, frozenset[Role] | None]] = {
    "samiir": ("samiir-agent", "/internal", None),
    "crm": ("crm", "/internal", None),
    "scheduling": ("scheduling", "/internal", None),
    "knowledge": ("knowledge", "/internal", None),
    "notifications": ("notifications", "/internal", None),
    "whatsapp": ("whatsapp", "/internal", None),
    # FATMA side: blocked at the edge for staff without security or admin roles.
    "fatma": ("fatma-soc", "/internal", SECURITY_SIDE),
    "scanner": ("scanner-controller", "/internal", SECURITY_SIDE),
    "ingest": ("security-ingest", "/internal", SECURITY_SIDE),
    "approvals": ("approvals", "/internal/approvals", SECURITY_SIDE),
    "audit": ("audit", "/internal/audit", frozenset({Role.TENANT_ADMIN, Role.PLATFORM_ADMIN})),
}


# ------------------------------------------------------------------------ sessions
async def _load_session(rt: ServiceRuntime, sid: str | None) -> dict[str, Any]:
    store = rt.extras["admin_sessions"]
    data = await store.get(sid)
    if data is None:
        raise Unauthenticated("login required")
    now = time.time()
    s = rt.settings
    if now - data["created"] > s.admin_session_absolute_seconds:  # type: ignore[attr-defined]
        await store.delete(sid)
        raise Unauthenticated("session expired")
    if now - data["seen"] > s.admin_session_idle_seconds:  # type: ignore[attr-defined]
        await store.delete(sid)
        raise Unauthenticated("session idle timeout")
    data["seen"] = now
    await store.put(sid or "", data, s.admin_session_idle_seconds)  # type: ignore[attr-defined]
    return data


def _principal(data: dict[str, Any]) -> Principal:
    return Principal(subject=data["user_id"], tenant_id=uuid.UUID(data["tenant_id"]),
                     actor_type=ActorType.USER,
                     roles=frozenset(Role(r) for r in data["roles"] if r in Role._value2member_map_),
                     mfa=bool(data["mfa"]), session_id=data["sid_hash"],
                     display_name=data.get("name"))


async def staff(request: Request) -> Principal:
    rt = runtime(request)
    sid = read_cookie(request, "admin_session")
    data = await _load_session(rt, sid)
    check_origin(request, rt.settings.allowed_origins)  # type: ignore[attr-defined]
    check_csrf(request, rt.extras["csrf_key"], sid or "")
    principal = _principal(data)
    if not principal.roles & STAFF_ROLES:
        raise Forbidden()
    await enforce(rt.extras["limiter"], f"user:{principal.subject}",
                  Limit(rt.settings.admin_requests_per_minute, 60))  # type: ignore[attr-defined]
    request.state.principal = principal
    return principal


StaffDep = Annotated[Principal, Depends(staff)]


def _ctx(request: Request, p: Principal) -> RequestContext:
    rt = runtime(request)
    return RequestContext(caller="api-gateway-admin", receiver="api-gateway-admin", principal=p,
                          request_id=request.state.request_id,
                          source_ip=client_ip(request, rt.settings.trusted_proxy_cidrs))  # type: ignore[attr-defined]


async def _create_session(rt: ServiceRuntime, response: Response, *, user_id: uuid.UUID,
                          tenant_id: uuid.UUID, roles: list[str], mfa: bool, name: str) -> str:
    now = time.time()
    data = {"user_id": str(user_id), "tenant_id": str(tenant_id), "roles": roles, "mfa": mfa,
            "name": name, "created": now, "seen": now}
    store = rt.extras["admin_sessions"]
    sid = secrets.token_urlsafe(32)
    data["sid_hash"] = hashlib.sha256(sid.encode()).hexdigest()[:24]
    await store.put(sid, data, rt.settings.admin_session_idle_seconds)  # type: ignore[attr-defined]
    response.set_cookie(cookie_name(rt, "admin_session"), sid, path="/", httponly=True,
                        secure=rt.settings.cookie_secure, samesite="strict",  # type: ignore[attr-defined]
                        max_age=rt.settings.admin_session_absolute_seconds)  # type: ignore[attr-defined]
    return sid


async def _login_lookup(rt: ServiceRuntime, subject: str) -> Any:
    async with rt.require_db().system_session() as s:
        rows = (await s.execute(text("SELECT * FROM app_login_lookup(:s)"), {"s": subject})).all()
    if len(rows) != 1 or rows[0].status != "active":
        raise Forbidden("no active account for this identity")
    return rows[0]


# --------------------------------------------------------------------- SSO (OIDC)
@router.get("/auth/login")
async def login(request: Request) -> RedirectResponse:
    rt = runtime(request)
    s = rt.settings
    if not s.oidc_authorize_url:  # type: ignore[attr-defined]
        raise NotFound("SSO is not configured")
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()
                                         ).decode().rstrip("=")
    state, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    await rt.extras["admin_sessions"].put(f"oidc:{state}", {"verifier": verifier, "nonce": nonce},
                                          600)
    params = {"response_type": "code", "client_id": s.oidc_client_id,  # type: ignore[attr-defined]
              "redirect_uri": s.oidc_redirect_uri, "scope": s.oidc_scopes,  # type: ignore[attr-defined]
              "state": state, "nonce": nonce, "code_challenge": challenge,
              "code_challenge_method": "S256", "acr_values": "mfa"}
    return RedirectResponse(f"{s.oidc_authorize_url}?{urlencode(params)}", status_code=302)  # type: ignore[attr-defined]


@router.get("/auth/callback")
async def callback(request: Request, code: Annotated[str, Query(max_length=2048)],
                   state: Annotated[str, Query(max_length=128)]) -> RedirectResponse:
    rt = runtime(request)
    s = rt.settings
    store = rt.extras["admin_sessions"]
    pending = await store.get(f"oidc:{state}")
    await store.delete(f"oidc:{state}")
    if pending is None:
        raise Unauthenticated("invalid or expired login state")
    secret = await rt.secrets.get(s.oidc_client_secret_ref) if s.oidc_client_secret_ref else None  # type: ignore[attr-defined]
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(s.oidc_token_url, data={  # type: ignore[attr-defined]
            "grant_type": "authorization_code", "code": code, "redirect_uri": s.oidc_redirect_uri,  # type: ignore[attr-defined]
            "client_id": s.oidc_client_id, "code_verifier": pending["verifier"],  # type: ignore[attr-defined]
            **({"client_secret": secret} if secret else {})})
    if resp.status_code != 200:
        raise Unauthenticated("token exchange failed")
    claims = await rt.extras["oidc"].verify(resp.json()["id_token"])
    if claims.get("nonce") != pending["nonce"]:
        raise Unauthenticated("nonce mismatch")
    mfa = has_mfa(claims)
    if s.require_mfa and not mfa:  # type: ignore[attr-defined]
        raise Forbidden("multi-factor or passkey authentication is required")
    row = await _login_lookup(rt, str(claims["sub"]))
    redirect = RedirectResponse(s.post_login_redirect, status_code=302)  # type: ignore[attr-defined]
    await _create_session(rt, redirect, user_id=row.user_id, tenant_id=row.tenant_id,
                          roles=list(row.roles), mfa=mfa, name=row.display_name)
    await _audit_login(rt, request, row, "sso")
    return redirect


class DevLoginIn(StrictModel):
    subject: str = Field(pattern=r"^dev\|[a-z0-9-]+\|[a-z0-9]+$")


@router.post("/auth/dev-login")
async def dev_login(body: DevLoginIn, request: Request, response: Response) -> dict:
    """Local development only (settings validator forbids it elsewhere)."""
    rt = runtime(request)
    if not rt.settings.dev_login_enabled or rt.settings.is_production_like:  # type: ignore[attr-defined]
        raise NotFound()
    check_origin(request, rt.settings.allowed_origins)  # type: ignore[attr-defined]
    row = await _login_lookup(rt, body.subject)
    sid = await _create_session(rt, response, user_id=row.user_id, tenant_id=row.tenant_id,
                                roles=list(row.roles), mfa=True, name=row.display_name)
    await _audit_login(rt, request, row, "dev")
    return {"csrf_token": csrf_token(rt.extras["csrf_key"], sid)}


async def _audit_login(rt: ServiceRuntime, request: Request, row: Any, method: str) -> None:
    p = Principal(subject=str(row.user_id), tenant_id=row.tenant_id, actor_type=ActorType.USER,
                  roles=frozenset())
    ctx = RequestContext(caller="api-gateway-admin", receiver="api-gateway-admin", principal=p,
                         request_id=request.state.request_id,
                         source_ip=client_ip(request, rt.settings.trusted_proxy_cidrs))  # type: ignore[attr-defined]
    await rt.audit.record(ctx, action="auth.login", result="success", metadata={"method": method})


@router.post("/auth/logout")
async def logout(request: Request, response: Response) -> dict:
    rt = runtime(request)
    sid = read_cookie(request, "admin_session")
    check_origin(request, rt.settings.allowed_origins)  # type: ignore[attr-defined]
    await rt.extras["admin_sessions"].delete(sid)
    response.delete_cookie(cookie_name(rt, "admin_session"), path="/")
    return {"ok": True}


@router.get("/auth/me")
async def me(request: Request) -> dict:
    rt = runtime(request)
    sid = read_cookie(request, "admin_session")
    data = await _load_session(rt, sid)
    p = _principal(data)
    perms = sorted(permissions_for(p.roles))
    async with rt.require_db().tenant_session(p.tenant_id) as s:
        tenant = await s.get(Tenant, p.tenant_id)
    return {"user_id": p.subject, "display_name": p.display_name, "tenant_id": str(p.tenant_id),
            "tenant_name": tenant.name if tenant else None,
            "roles": sorted(r.value for r in p.roles), "permissions": perms, "mfa": p.mfa,
            "csrf_token": csrf_token(rt.extras["csrf_key"], sid or "")}


# ------------------------------------------------------------------ realtime (SSE)
@router.get("/v1/admin/stream")
async def stream(request: Request, principal: StaffDep,
                 streams: Annotated[str, Query(pattern="^(samiir|fatma)(,(samiir|fatma))?$")]
                 = "samiir,fatma") -> StreamingResponse:
    rt = runtime(request)
    perms = permissions_for(principal.roles)
    allowed = []
    for name in streams.split(","):
        if name == "samiir" and perms & {P.CONVERSATION_READ, P.CRM_READ}:
            allowed.append(channel(principal.tenant_id, "samiir"))
        if name == "fatma" and P.INCIDENT_READ in perms:
            allowed.append(channel(principal.tenant_id, "fatma"))
    if not allowed:
        raise Forbidden()

    async def events() -> AsyncIterator[bytes]:
        yield b"retry: 5000\n\n"
        if rt.redis is None:
            while not await request.is_disconnected():
                yield b": keepalive\n\n"
                await asyncio.sleep(15)
            return
        pubsub = rt.redis.pubsub()
        await pubsub.subscribe(*allowed)
        try:
            last = time.monotonic()
            while not await request.is_disconnected():
                msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=5)
                if msg and msg.get("type") == "message":
                    payload = json.loads(msg["data"])
                    yield (f"event: {payload['event']}\ndata: {json.dumps(payload['data'])}\n\n"
                           ).encode()
                if time.monotonic() - last > 15:
                    last = time.monotonic()
                    yield b": keepalive\n\n"
        finally:
            await pubsub.unsubscribe(*allowed)
            await pubsub.aclose()

    return StreamingResponse(events(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})


# ------------------------------------------------------------- identity & tenancy
def _require(request: Request, p: Principal, perm: P) -> RequestContext:
    ctx = _ctx(request, p)
    runtime(request).policy.require(ctx, perm)
    return ctx


class UserIn(StrictModel):
    external_subject: str = Field(min_length=3, max_length=256)
    email: str = Field(pattern=r"^[^@\s]{1,64}@[^@\s]{1,255}$")
    display_name: str = Field(min_length=1, max_length=120)
    roles: list[Role] = Field(min_length=1, max_length=5)


class RolesIn(StrictModel):
    roles: list[Role] = Field(min_length=0, max_length=5)


def _assignable(roles: list[Role]) -> None:
    forbidden = {Role.PLATFORM_ADMIN, Role.SYSTEM_SERVICE, Role.ANONYMOUS_CUSTOMER,
                 Role.AUTHENTICATED_CUSTOMER}
    if set(roles) & forbidden:
        raise Forbidden("role cannot be assigned by tenant administrators")


@router.get("/v1/admin/identity/users")
async def list_users(request: Request, p: StaffDep) -> list[dict]:
    _require(request, p, P.TENANT_USER_MANAGE)
    rt = runtime(request)
    enc = rt.extras["enc"]
    async with rt.require_db().tenant_session(p.tenant_id) as s:
        users = (await s.scalars(select(User).where(User.deleted_at.is_(None))
                                 .order_by(User.display_name))).all()
        roles = (await s.execute(select(UserRole.user_id, RoleRow.name).join(
            RoleRow, RoleRow.id == UserRole.role_id))).all()
    by_user: dict = {}
    for uid, name in roles:
        by_user.setdefault(uid, []).append(name)
    return [{"id": str(u.id), "display_name": u.display_name, "status": u.status,
             "email": enc.decrypt(u.email_ciphertext, u.tenant_id),
             "external_subject": u.external_subject, "roles": sorted(by_user.get(u.id, [])),
             "mfa_enforced": u.mfa_enforced, "last_login_at": u.last_login_at} for u in users]


@router.post("/v1/admin/identity/users", status_code=201)
async def create_user(body: UserIn, request: Request, p: StaffDep) -> dict:
    ctx = _require(request, p, P.TENANT_USER_MANAGE)
    _assignable(body.roles)
    rt = runtime(request)
    enc = rt.extras["enc"]
    async with rt.require_db().tenant_session(p.tenant_id, actor=p.subject) as s:
        if await s.scalar(select(User.id).where(User.external_subject == body.external_subject)):
            raise Conflict("user already exists")
        u = User(tenant_id=p.tenant_id, external_subject=body.external_subject,
                 email_ciphertext=enc.encrypt(body.email, p.tenant_id),
                 email_hash=enc.blind_index(body.email, p.tenant_id, "email"),
                 display_name=body.display_name, status="active", mfa_enforced=True)
        s.add(u)
        await s.flush()
        role_ids = (await s.execute(select(RoleRow.id, RoleRow.name).where(
            RoleRow.name.in_([r.value for r in body.roles])))).all()
        for rid, _ in role_ids:
            s.add(UserRole(tenant_id=p.tenant_id, user_id=u.id, role_id=rid,
                           granted_by=uuid.UUID(p.subject)))
        uid = u.id
    await rt.audit.record(ctx, action="identity.user.create", result="success",
                          target_type="user", target_id=uid, risk_level="MEDIUM",
                          metadata={"roles": [r.value for r in body.roles]})
    return {"id": str(uid)}


@router.put("/v1/admin/identity/users/{user_id}/roles")
async def set_roles(user_id: uuid.UUID, body: RolesIn, request: Request, p: StaffDep) -> dict:
    ctx = _require(request, p, P.TENANT_USER_MANAGE)
    _assignable(body.roles)
    if str(user_id) == p.subject and Role.TENANT_ADMIN not in body.roles:
        raise Conflict("administrators cannot remove their own admin role")
    rt = runtime(request)
    async with rt.require_db().tenant_session(p.tenant_id, actor=p.subject) as s:
        if await s.get(User, user_id) is None:
            raise NotFound()
        await s.execute(delete(UserRole).where(UserRole.user_id == user_id))
        for rid in (await s.scalars(select(RoleRow.id).where(
                RoleRow.name.in_([r.value for r in body.roles])))).all():
            s.add(UserRole(tenant_id=p.tenant_id, user_id=user_id, role_id=rid,
                           granted_by=uuid.UUID(p.subject)))
    await rt.audit.record(ctx, action="identity.user.roles", result="success", target_type="user",
                          target_id=user_id, risk_level="HIGH",
                          metadata={"roles": [r.value for r in body.roles]})
    return {"roles": [r.value for r in body.roles]}


@router.post("/v1/admin/identity/users/{user_id}/disable")
async def disable_user(user_id: uuid.UUID, request: Request, p: StaffDep) -> dict:
    ctx = _require(request, p, P.TENANT_USER_MANAGE)
    if str(user_id) == p.subject:
        raise Conflict("you cannot disable yourself")
    rt = runtime(request)
    async with rt.require_db().tenant_session(p.tenant_id, actor=p.subject) as s:
        u = await s.get(User, user_id)
        if u is None:
            raise NotFound()
        u.status = "disabled"
    await rt.audit.record(ctx, action="identity.user.disable", result="success",
                          target_type="user", target_id=user_id, risk_level="HIGH")
    return {"status": "disabled"}


@router.get("/v1/admin/identity/roles")
async def roles(request: Request, p: StaffDep) -> list[dict]:
    return [{"role": r.value, "permissions": sorted(ROLE_PERMISSIONS[r]),
             "mfa_required_permissions": sorted(ROLE_PERMISSIONS[r] & MFA_REQUIRED)}
            for r in Role]


class TenantSettingsIn(StrictModel):
    fatma_mode: FatmaMode | None = None
    preapproved_actions: list[str] | None = Field(default=None, max_length=4)
    appointment_rules: dict | None = None
    detection: dict[str, float] | None = None
    timezone: str | None = Field(default=None, max_length=64)


@router.get("/v1/admin/identity/tenant")
async def get_tenant(request: Request, p: StaffDep) -> dict:
    rt = runtime(request)
    async with rt.require_db().tenant_session(p.tenant_id) as s:
        t = await s.get(Tenant, p.tenant_id)
        users = await s.scalar(select(func.count()).select_from(User))
    if t is None:
        raise NotFound()
    return {"id": str(t.id), "name": t.name, "slug": t.slug, "status": t.status,
            "timezone": t.timezone, "settings": t.settings, "users": users}


@router.patch("/v1/admin/identity/tenant")
async def update_tenant(body: TenantSettingsIn, request: Request, p: StaffDep) -> dict:
    ctx = _require(request, p, P.TENANT_SETTINGS_MANAGE)
    allowed = {"defense.challenge_ip", "defense.rate_limit_path", "defense.temp_block_ip",
               "defense.revoke_app_session"}
    if body.preapproved_actions and not set(body.preapproved_actions) <= allowed:
        raise ValidationFailed("only low-risk actions can be pre-approved")
    rt = runtime(request)
    async with rt.require_db().tenant_session(p.tenant_id, actor=p.subject) as s:
        t = await s.get(Tenant, p.tenant_id)
        settings = dict(t.settings or {})
        changes = body.model_dump(exclude_unset=True, mode="json")
        tz = changes.pop("timezone", None)
        settings.update(changes)
        t.settings = settings
        if tz:
            t.timezone = tz
    await rt.audit.record(ctx, action="tenant.settings.update", result="success",
                          target_type="tenant", target_id=p.tenant_id,
                          risk_level="HIGH" if "fatma_mode" in changes else "MEDIUM",
                          metadata=changes)
    return {"settings": settings}


class IntegrationIn(StrictModel):
    kind: str = Field(pattern=r"^(calendar\.(google|microsoft365)|whatsapp\.cloud|"
                              r"defense\.(cloudflare|aws_waf)|ingest\.(cloudflare|aws_waf|siem|"
                              r"app_log|proxy|auth|scanner|malware)|email\.smtp)$")
    name: str = Field(min_length=2, max_length=120)
    external_key: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_.:-]{3,128}$")
    # Only a *reference* into the secret manager is accepted — never a raw credential.
    secret_ref: str | None = Field(default=None, pattern=r"^(file|vault|aws-sm|env)://[\w./#:-]+$")
    config: dict[str, Any] = Field(default_factory=dict)


@router.get("/v1/admin/identity/integrations")
async def list_integrations(request: Request, p: StaffDep) -> list[dict]:
    _require(request, p, P.TENANT_INTEGRATION_MANAGE)
    rt = runtime(request)
    async with rt.require_db().tenant_session(p.tenant_id) as s:
        rows = (await s.scalars(select(Integration).order_by(Integration.kind))).all()
    return [{"id": str(i.id), "kind": i.kind, "name": i.name, "external_key": i.external_key,
             "secret_ref": i.secret_ref, "config": i.config, "status": i.status,
             "updated_at": i.updated_at} for i in rows]


@router.post("/v1/admin/identity/integrations", status_code=201)
async def create_integration(body: IntegrationIn, request: Request, p: StaffDep) -> dict:
    ctx = _require(request, p, P.TENANT_INTEGRATION_MANAGE)
    rt = runtime(request)
    if body.secret_ref and body.secret_ref.startswith("env://") and rt.settings.is_production_like:
        raise ValidationFailed("env:// secret references are development-only")
    if body.kind.startswith("ingest.") and not body.external_key:
        body.external_key = f"ing_{secrets.token_hex(10)}"
    async with rt.require_db().tenant_session(p.tenant_id, actor=p.subject) as s:
        i = Integration(tenant_id=p.tenant_id, **body.model_dump())
        s.add(i)
        await s.flush()
        iid = i.id
    await rt.audit.record(ctx, action="integration.create", result="success",
                          target_type="integration", target_id=iid, risk_level="HIGH",
                          metadata={"kind": body.kind})
    return {"id": str(iid), "external_key": body.external_key}


@router.post("/v1/admin/identity/integrations/{integration_id}/disable")
async def disable_integration(integration_id: uuid.UUID, request: Request, p: StaffDep) -> dict:
    ctx = _require(request, p, P.TENANT_INTEGRATION_MANAGE)
    rt = runtime(request)
    async with rt.require_db().tenant_session(p.tenant_id, actor=p.subject) as s:
        i = await s.get(Integration, integration_id)
        if i is None:
            raise NotFound()
        i.status = "disabled"
    await rt.audit.record(ctx, action="integration.disable", result="success",
                          target_type="integration", target_id=integration_id)
    return {"status": "disabled"}


class WidgetIn(StrictModel):
    name: str = Field(min_length=2, max_length=120)
    allowed_origins: list[str] = Field(min_length=1, max_length=20)
    greeting: str = Field("Hi! How can I help you today?", max_length=300)
    theme: dict[str, str] = Field(default_factory=dict)


@router.get("/v1/admin/identity/widgets")
async def list_widgets(request: Request, p: StaffDep) -> list[dict]:
    _require(request, p, P.TENANT_SETTINGS_MANAGE)
    rt = runtime(request)
    async with rt.require_db().tenant_session(p.tenant_id) as s:
        rows = (await s.scalars(select(WidgetSite))).all()
    return [{"id": str(w.id), "name": w.name, "public_key": w.public_key,
             "allowed_origins": w.allowed_origins, "greeting": w.greeting, "active": w.active}
            for w in rows]


@router.post("/v1/admin/identity/widgets", status_code=201)
async def create_widget(body: WidgetIn, request: Request, p: StaffDep) -> dict:
    ctx = _require(request, p, P.TENANT_SETTINGS_MANAGE)
    for origin in body.allowed_origins:
        if not (origin.startswith("https://") or origin.startswith("http://localhost")) \
                or origin.count("/") != 2 or "*" in origin:
            raise ValidationFailed("origins must be exact https://host[:port] values")
    rt = runtime(request)
    key = f"pk_{secrets.token_urlsafe(24)}"
    async with rt.require_db().tenant_session(p.tenant_id, actor=p.subject) as s:
        w = WidgetSite(tenant_id=p.tenant_id, public_key=key, name=body.name,
                       allowed_origins=body.allowed_origins, greeting=body.greeting,
                       theme=body.theme)
        s.add(w)
        await s.flush()
        wid = w.id
    await rt.audit.record(ctx, action="widget.create", result="success", target_type="widget",
                          target_id=wid, metadata={"origins": body.allowed_origins})
    return {"id": str(wid), "public_key": key}


@router.get("/v1/admin/identity/security-settings")
async def security_settings(request: Request, p: StaffDep) -> dict:
    rt = runtime(request)
    s = rt.settings
    return {"sso": bool(s.oidc_issuer), "mfa_required": s.require_mfa,  # type: ignore[attr-defined]
            "session_idle_seconds": s.admin_session_idle_seconds,  # type: ignore[attr-defined]
            "session_absolute_seconds": s.admin_session_absolute_seconds,  # type: ignore[attr-defined]
            "cookie": {"name": cookie_name(rt, "admin_session"), "httponly": True, "secure": s.cookie_secure,  # type: ignore[attr-defined]
                       "samesite": "strict"},
            "csrf": "double-submit HMAC token (X-CSRF-Token) + Origin check",
            "rate_limit_per_user_per_minute": s.admin_requests_per_minute,  # type: ignore[attr-defined]
            "service_identity": "Ed25519 short-lived audience-bound tokens + mesh mTLS",
            "field_encryption": "AES-256-GCM keyring with blind indexes",
            "tenant_isolation": "PostgreSQL FORCE ROW LEVEL SECURITY per transaction"}


# ------------------------------------------------------------------ service proxy
# Registered last so explicit /v1/admin/identity/* and /v1/admin/stream routes take precedence.
@router.api_route("/v1/admin/{service}", methods=["GET", "POST"])
async def proxy_root(service: str, request: Request, principal: StaffDep) -> Response:
    return await proxy(service, "", request, principal)


@router.api_route("/v1/admin/{service}/{path:path}", methods=["GET", "POST", "PATCH", "DELETE"])
async def proxy(service: str, path: str, request: Request, principal: StaffDep) -> Response:
    route = ROUTES.get(service)
    if route is None:
        raise NotFound()
    audience, prefix, roles = route
    if roles is not None and not (principal.roles & roles):
        raise Forbidden()
    if ".." in path or "//" in path or not all(c.isalnum() or c in "-_/." for c in path):
        raise ValidationFailed("invalid path")
    rt = runtime(request)
    ctx = _ctx(request, principal)
    headers = {h: request.headers[h] for h in ("content-type", "x-filename", "x-declared-mime")
               if h in request.headers}
    upstream = await rt.client(audience).request(
        request.method, f"{prefix}/{path}".rstrip("/") if path else prefix, ctx=ctx,
        params=list(request.query_params.multi_items()) or None,  # type: ignore[arg-type]
        content=await request.body() if request.method != "GET" else None, headers=headers,
        raw=True)
    return to_response(upstream)
