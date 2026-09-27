from __future__ import annotations

import base64
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api_gateway.config import Settings
from api_gateway.sessions import SessionStore
from platform_core.app import ServiceRuntime, build_runtime, create_app
from platform_core.security.crypto import load_field_encryptor
from platform_core.security.oidc import OidcConfig, OidcVerifier
from platform_core.security.ratelimit import InMemoryRateLimiter, RedisRateLimiter
from platform_core.security.secret_manager import SecretNotFound


def _downstream(settings: Settings) -> dict[str, str | None]:
    if settings.gateway_mode == "public":
        # The public gateway holds no route to FATMA except the signed ingestion endpoints of
        # security-ingest (enforced again by security-ingest's caller ACL per route).
        return {"samiir-agent": settings.samiir_url, "whatsapp": settings.whatsapp_url,
                "security-ingest": settings.security_ingest_url}
    return {"samiir-agent": settings.samiir_url, "crm": settings.crm_url,
            "scheduling": settings.scheduling_url, "knowledge": settings.knowledge_url,
            "notifications": settings.notifications_url, "whatsapp": settings.whatsapp_url,
            "fatma-soc": settings.fatma_url, "scanner-controller": settings.scanner_controller_url,
            "security-ingest": settings.security_ingest_url, "approvals": settings.approvals_url,
            "audit": settings.audit_read_url}


def create(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    if settings.gateway_mode == "admin" and settings.service_name == "api-gateway-public":
        settings.service_name = "api-gateway-admin"

    async def startup(rt: ServiceRuntime) -> None:
        if "csrf_key" not in rt.extras:
            try:
                rt.extras["csrf_key"] = base64.b64decode(await rt.secrets.get(
                    settings.csrf_key_ref or ""))
            except SecretNotFound:
                if settings.is_production_like:
                    raise
                rt.extras["csrf_key"] = os.urandom(32)
        rt.extras.setdefault("limiter", RedisRateLimiter(rt.redis, settings.service_name)
                             if rt.redis is not None else InMemoryRateLimiter())
        if settings.gateway_mode == "public":
            rt.extras.setdefault("widget_sessions", SessionStore(rt.redis, "ws"))
            return
        rt.extras.setdefault("admin_sessions", SessionStore(rt.redis, "admin"))
        if "enc" not in rt.extras:
            rt.extras["enc"] = await load_field_encryptor(
                rt.secrets, settings.field_keyring_ref, settings.blind_index_key_ref,
                allow_ephemeral=not settings.is_production_like)
        if settings.oidc_issuer and settings.oidc_jwks_url and "oidc" not in rt.extras:
            rt.extras["oidc"] = OidcVerifier(OidcConfig(
                issuer=settings.oidc_issuer, audience=settings.oidc_client_id or "",
                jwks_url=settings.oidc_jwks_url))

    if settings.gateway_mode == "public":
        from api_gateway.public import router
    else:
        from api_gateway.admin import router
    app = create_app(settings=settings,
                     runtime_factory=lambda: build_runtime(settings, _downstream(settings)),
                     routers=[router], on_startup=startup,
                     body_limit_overrides={"/v1/ingest/": 5 * 1024 * 1024,
                                           "/v1/admin/ingest/malware/submit": 25 * 1024 * 1024},
                     title=f"API Gateway ({settings.gateway_mode})")
    app.add_middleware(CORSMiddleware, allow_origins=settings.allowed_origins,
                       allow_credentials=True, allow_methods=["GET", "POST", "PATCH", "PUT",
                                                              "DELETE"],
                       allow_headers=["Content-Type", "X-CSRF-Token", "X-Request-ID",
                                      "Idempotency-Key", "X-Filename", "X-Declared-Mime"],
                       max_age=600)
    return app


def create_public() -> FastAPI:
    return create(Settings(gateway_mode="public", service_name="api-gateway-public"))


def create_admin() -> FastAPI:
    return create(Settings(gateway_mode="admin", service_name="api-gateway-admin"))
