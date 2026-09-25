"""Service runtime container and FastAPI application factory."""

from __future__ import annotations

import logging
import secrets
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from platform_core.audit import AuditClient, HttpAuditSink, MemoryAuditSink
from platform_core.config import BaseServiceSettings
from platform_core.db.engine import Database
from platform_core.errors import PlatformError, RateLimited, Unauthenticated
from platform_core.events import RealtimePublisher
from platform_core.http import (
    REQUEST_ID_HEADER,
    SERVICE_TOKEN_HEADER,
    ServiceClient,
    build_ssl_context,
)
from platform_core.logs import configure_logging
from platform_core.observability import configure_telemetry, instruments
from platform_core.security.policy import PolicyEngine
from platform_core.security.secret_manager import DefaultSecretManager
from platform_core.security.service_auth import (
    InMemoryReplayCache,
    RedisReplayCache,
    RequestContext,
    ServiceIdentity,
    ServiceTokenVerifier,
    load_private_key,
    load_trust_bundle,
)

log = logging.getLogger(__name__)


@dataclass
class ServiceRuntime:
    settings: BaseServiceSettings
    identity: ServiceIdentity
    verifier: ServiceTokenVerifier
    policy: PolicyEngine
    audit: AuditClient
    secrets: DefaultSecretManager
    db: Database | None = None
    redis: Any | None = None
    realtime: RealtimePublisher = field(default_factory=lambda: RealtimePublisher(None))
    clients: dict[str, ServiceClient] = field(default_factory=dict)
    extras: dict[str, Any] = field(default_factory=dict)

    def client(self, audience: str) -> ServiceClient:
        try:
            return self.clients[audience]
        except KeyError:
            raise RuntimeError(f"{self.settings.service_name} has no client for {audience}") from None

    def require_db(self) -> Database:
        if self.db is None:
            raise RuntimeError("database not configured for this service")
        return self.db

    async def aclose(self) -> None:
        for c in self.clients.values():
            await c.aclose()
        if self.db is not None:
            await self.db.dispose()
        if self.redis is not None:
            await self.redis.aclose()


def build_runtime(settings: BaseServiceSettings, downstream: dict[str, str | None]) -> ServiceRuntime:
    """Wire identity, verifier, DB, Redis and downstream clients from settings."""
    from redis.asyncio import Redis

    name = settings.service_name
    if settings.service_private_key_path and settings.service_trust_bundle_path:
        key = load_private_key(settings.service_private_key_path)
        bundle = load_trust_bundle(settings.service_trust_bundle_path)
    else:  # development convenience: ephemeral identity, trusts only itself
        from platform_core.security.service_auth import generate_keypair

        log.warning("no service keys configured; using an ephemeral development identity")
        from cryptography.hazmat.primitives import serialization

        pem, _ = generate_keypair()
        key = serialization.load_pem_private_key(pem, password=None)  # type: ignore[assignment]
        bundle = {name: key.public_key()}  # type: ignore[union-attr]
    identity = ServiceIdentity(name, key, settings.service_token_ttl_seconds)  # type: ignore[arg-type]
    redis = Redis.from_url(settings.redis_url.get_secret_value()) if settings.redis_url else None
    replay = RedisReplayCache(redis, name) if redis is not None else InMemoryReplayCache()
    verifier = ServiceTokenVerifier(name, bundle, replay)
    db = None
    if settings.database_url:
        db = Database(settings.database_url.get_secret_value(),
                      pool_size=settings.database_pool_size,
                      statement_timeout_ms=settings.database_statement_timeout_ms,
                      application_name=name)
    verify = build_ssl_context(
        str(settings.mtls_cert_path) if settings.mtls_cert_path else None,
        str(settings.mtls_key_path) if settings.mtls_key_path else None,
        str(settings.mtls_ca_path) if settings.mtls_ca_path else None,
    )
    clients = {aud: ServiceClient(aud, url, identity, verify=verify)
               for aud, url in downstream.items() if url}
    if settings.audit_url:
        clients["audit"] = ServiceClient("audit", settings.audit_url, identity, verify=verify)
        audit = AuditClient(name, HttpAuditSink(clients["audit"], name))
    else:
        if settings.is_production_like and name != "audit":
            raise RuntimeError("AUDIT_URL is mandatory outside development")
        audit = AuditClient(name, MemoryAuditSink())
    secret_manager = DefaultSecretManager(allow_env=not settings.is_production_like)
    return ServiceRuntime(settings=settings, identity=identity, verifier=verifier,
                          policy=PolicyEngine(), audit=audit, secrets=secret_manager, db=db,
                          redis=redis, realtime=RealtimePublisher(redis), clients=clients)


# ------------------------------------------------------------------------------ middleware
class BodySizeLimitMiddleware:
    """Rejects bodies over the limit even when Content-Length is absent (chunked uploads)."""

    def __init__(self, app: ASGIApp, max_bytes: int,
                 overrides: dict[str, int] | None = None) -> None:
        self.app = app
        self.max_bytes = max_bytes
        self.overrides = overrides or {}

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit = next((v for k, v in self.overrides.items() if scope["path"].startswith(k)),
                     self.max_bytes)
        for name, value in scope.get("headers", []):
            if name == b"content-length":
                try:
                    too_big = int(value) > limit
                except ValueError:
                    too_big = True
                if too_big:
                    await _send_json(send, 413, "payload_too_large", "Request body too large.")
                    return
        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise _BodyTooLarge
            return message

        try:
            await self.app(scope, limited_receive, send)
        except _BodyTooLarge:
            await _send_json(send, 413, "payload_too_large", "Request body too large.")


class _BodyTooLarge(Exception):
    pass


async def _send_json(send: Send, status: int, code: str, message: str) -> None:
    import json

    body = json.dumps({"error": {"code": code, "message": message}}).encode()
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"application/json"),
                            (b"content-length", str(len(body)).encode())]})
    await send({"type": "http.response.body", "body": body})


SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-site",
    "Cache-Control": "no-store",
}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Any]]
                       ) -> Any:
        rid = request.headers.get(REQUEST_ID_HEADER, "")
        if not (8 <= len(rid) <= 128) or not all(c.isalnum() or c in "-_" for c in rid):
            rid = secrets.token_hex(16)
        request.state.request_id = rid
        start = time.perf_counter()
        response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        response.headers[REQUEST_ID_HEADER] = rid
        instruments().http_requests.add(1, {"route": request.scope.get("route").path  # type: ignore[union-attr]
                                            if request.scope.get("route") else "unmatched",
                                            "status": str(response.status_code)})
        log.debug("request", extra={"ctx": {"path": request.url.path, "status":
                                           response.status_code, "ms": int(
                                               (time.perf_counter() - start) * 1000)}})
        return response


def _error_response(exc: PlatformError, request_id: str | None) -> JSONResponse:
    headers = {}
    if isinstance(exc, RateLimited):
        headers["Retry-After"] = str(exc.retry_after)
    body: dict[str, Any] = {"code": exc.code, "message": exc.message
                            if exc.status_code < 500 else exc.public_message}
    if exc.details:
        body["details"] = exc.details
    if request_id:
        body["request_id"] = request_id
    return JSONResponse({"error": body}, status_code=exc.status_code, headers=headers)


def create_app(
    *,
    settings: BaseServiceSettings,
    runtime_factory: Callable[[], ServiceRuntime],
    routers: list[Any],
    on_startup: Callable[[ServiceRuntime], Awaitable[None]] | None = None,
    on_shutdown: Callable[[ServiceRuntime], Awaitable[None]] | None = None,
    body_limit_overrides: dict[str, int] | None = None,
    title: str | None = None,
) -> FastAPI:
    configure_logging(settings.service_name, settings.log_level)
    configure_telemetry(settings.service_name, settings.otel_service_namespace,
                        settings.otel_exporter_otlp_endpoint, settings.environment.value)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        if getattr(app.state, "runtime", None) is None:
            app.state.runtime = runtime_factory()
        runtime: ServiceRuntime = app.state.runtime
        if on_startup:
            await on_startup(runtime)
        try:
            yield
        finally:
            if on_shutdown:
                await on_shutdown(runtime)
            await runtime.aclose()

    docs = None if settings.is_production_like else "/docs"
    app = FastAPI(title=title or settings.service_name, lifespan=lifespan, docs_url=docs,
                  redoc_url=None, openapi_url=None if settings.is_production_like
                  else "/openapi.json")
    app.state.runtime = None
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_request_bytes,
                       overrides=body_limit_overrides)

    @app.exception_handler(PlatformError)
    async def _platform_error(request: Request, exc: PlatformError) -> JSONResponse:
        return _error_response(exc, getattr(request.state, "request_id", None))

    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        # Echo field locations and messages only; never echo submitted values back.
        details = [{"loc": [str(p) for p in e.get("loc", [])], "msg": e.get("msg")}
                   for e in exc.errors()[:20]]
        return JSONResponse({"error": {"code": "validation_failed",
                                       "message": "The request is invalid.",
                                       "details": {"fields": details}}}, status_code=422)

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled error")
        return JSONResponse({"error": {"code": "internal_error",
                                       "message": "An internal error occurred.",
                                       "request_id": getattr(request.state, "request_id", None)}},
                            status_code=500)

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> dict[str, str]:
        return {"status": "ok", "service": settings.service_name}

    @app.get("/readyz", include_in_schema=False)
    async def readyz(request: Request) -> JSONResponse:
        runtime: ServiceRuntime = request.app.state.runtime
        checks: dict[str, str] = {}
        try:
            if runtime.db is not None:
                await runtime.db.ping()
                checks["database"] = "ok"
            if runtime.redis is not None:
                await runtime.redis.ping()
                checks["redis"] = "ok"
        except Exception:
            return JSONResponse({"status": "degraded", "checks": checks}, status_code=503)
        return JSONResponse({"status": "ready", "checks": checks})

    for router in routers:
        app.include_router(router)
    return app


# ---------------------------------------------------------------------------- dependencies
def get_runtime(request: Request) -> ServiceRuntime:
    return request.app.state.runtime


RuntimeDep = Annotated[ServiceRuntime, Depends(get_runtime)]


def internal_caller(*allowed: str) -> Callable[..., Awaitable[RequestContext]]:
    """Dependency verifying the inbound service token (optionally narrowing allowed callers)."""
    narrowed = frozenset(allowed) if allowed else None

    async def dependency(
        request: Request,
        x_service_token: Annotated[str | None, Header(alias=SERVICE_TOKEN_HEADER)] = None,
    ) -> RequestContext:
        if not x_service_token:
            raise Unauthenticated("service token required")
        runtime: ServiceRuntime = request.app.state.runtime
        ctx = await runtime.verifier.verify(x_service_token, allowed_callers=narrowed)
        request.state.request_id = ctx.request_id
        return ctx

    return dependency


CallerDep = Annotated[RequestContext, Depends(internal_caller())]
