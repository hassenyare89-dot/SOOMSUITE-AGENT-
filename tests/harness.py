"""In-process platform harness: every service runs as its own ASGI app, authenticates with its
own Ed25519 identity and connects to PostgreSQL as its own least-privilege role."""

from __future__ import annotations

import base64
import importlib
import json
import os
import secrets
import uuid
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from platform_core.app import ServiceRuntime, build_runtime
from platform_core.audit import AuditClient, MemoryAuditSink
from platform_core.http import ServiceClient
from platform_core.security.crypto import FieldEncryptor, Keyring
from platform_core.security.principal import ActorType, Principal, Role
from platform_core.security.service_auth import (
    ServiceIdentity,
    generate_keypair,
    load_private_key,
)

# name -> (module, db role, downstream audiences)
SERVICES: dict[str, tuple[str, str | None, list[str]]] = {
    "knowledge": ("knowledge_service", "svc_knowledge", []),
    "crm": ("crm_service", "svc_crm", []),
    "scheduling": ("scheduling_service", "svc_scheduling", ["crm", "notifications"]),
    "notifications": ("notifications_service", "svc_notifications", ["crm", "whatsapp"]),
    "samiir-agent": ("samiir_agent", "svc_samiir",
                     ["knowledge", "crm", "scheduling", "notifications", "whatsapp"]),
    "whatsapp": ("whatsapp_service", "svc_whatsapp", ["samiir-agent", "notifications"]),
    "audit": ("audit_service", "svc_audit", []),
    "approvals": ("approval_service", "svc_approvals", []),
    "fatma-soc": ("fatma_soc", "svc_fatma", ["approvals", "notifications"]),
    "security-ingest": ("security_ingest", "svc_security_ingest", ["fatma-soc"]),
    "scanner-controller": ("scanner_controller", "svc_scanner_controller",
                           ["approvals", "fatma-soc"]),
    "api-gateway-public": ("api_gateway", None, ["samiir-agent", "whatsapp", "security-ingest"]),
    "api-gateway-admin": ("api_gateway", "svc_gateway_admin",
                          ["samiir-agent", "crm", "scheduling", "knowledge", "notifications",
                           "whatsapp", "fatma-soc", "scanner-controller", "security-ingest",
                           "approvals", "audit"]),
}

ALL_NAMES = ["api-gateway-public", "api-gateway-admin", "samiir-agent", "fatma-soc", "crm",
             "scheduling", "notifications", "knowledge", "whatsapp", "security-ingest",
             "scanner-controller", "approvals", "audit"]


def db_url(base: str, role: str, password: str) -> str:
    rest = base.split("@", 1)[1]
    return f"postgresql+asyncpg://{role}:{password}@{rest}"


@dataclass
class Platform:
    apps: dict[str, Any]
    runtimes: dict[str, ServiceRuntime]
    identities: dict[str, ServiceIdentity]
    audit: MemoryAuditSink
    enc: FieldEncryptor
    env: dict[str, str] = field(default_factory=dict)

    def client(self, caller: str, audience: str) -> ServiceClient:
        """A client that calls ``audience`` as service ``caller`` (used to simulate callers)."""
        return ServiceClient(audience, f"http://{audience}", self.identities[caller],
                             transport=httpx.ASGITransport(app=self.apps[audience]))

    def raw(self, audience: str) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.ASGITransport(app=self.apps[audience]),
                                 base_url=f"http://{audience}")


def customer(tenant_id: uuid.UUID, session: str | None = None,
             contact_id: uuid.UUID | None = None) -> Principal:
    session = session or secrets.token_hex(16)
    return Principal(subject=f"ws:{session[:12]}", tenant_id=tenant_id,
                     actor_type=ActorType.CUSTOMER, roles=frozenset({Role.ANONYMOUS_CUSTOMER}),
                     session_id=session, contact_id=contact_id)


def user(tenant_id: uuid.UUID, user_id: uuid.UUID, *roles: Role, mfa: bool = True) -> Principal:
    return Principal(subject=str(user_id), tenant_id=tenant_id, actor_type=ActorType.USER,
                     roles=frozenset(roles), mfa=mfa, session_id="test-session")


async def start_platform(stack: AsyncExitStack, tmp: Path, base_db_url: str,
                         passwords: dict[str, str], names: list[str] | None = None,
                         extra_env: dict[str, str] | None = None) -> Platform:
    keys_dir = tmp / "keys"
    keys_dir.mkdir(exist_ok=True)
    bundle: dict[str, str] = {}
    for name in ALL_NAMES:
        pem, pub = generate_keypair()
        (keys_dir / f"{name}.pem").write_bytes(pem)
        bundle[name] = pub
    (keys_dir / "trust.json").write_text(json.dumps({"keys": bundle}))
    identities = {n: ServiceIdentity(n, load_private_key(keys_dir / f"{n}.pem")) for n in ALL_NAMES}

    keyring = Keyring.generate()
    bik = os.urandom(32)
    env = {
        "FIELD_ENCRYPTION_KEYRING": keyring.to_json(),
        "BLIND_INDEX_KEY": base64.b64encode(bik).decode(),
        "SLOT_TOKEN_KEY": base64.b64encode(os.urandom(32)).decode(),
        "META_APP_SECRET": "test-meta-app-secret",
        "META_VERIFY_TOKEN": "test-verify-token",
        "WA_TOKEN_ACME": "test-wa-token",
        "INGEST_DEMO_SECRET": "test-ingest-secret-0123456789",
        **(extra_env or {}),
    }
    os.environ.update(env)
    audit_sink = MemoryAuditSink()
    apps: dict[str, Any] = {}
    runtimes: dict[str, ServiceRuntime] = {}
    for name in names or list(SERVICES):
        module, role, downstream = SERVICES[name]
        main = importlib.import_module(f"{module}.main")
        cfg = importlib.import_module(f"{module}.config")
        overrides: dict[str, Any] = {
            "environment": "test",
            "service_private_key_path": keys_dir / f"{name}.pem",
            "service_trust_bundle_path": keys_dir / "trust.json",
            "database_url": db_url(base_db_url, role, passwords[role]) if role else None,
            "redis_url": None,
            "audit_url": None,
        }
        if name.startswith("api-gateway"):
            overrides.update(service_name=name, gateway_mode=name.rsplit("-", 1)[1],
                             cookie_secure=False, dev_login_enabled=name.endswith("admin"),
                             allowed_origins=["http://localhost:3000"])
        if name == "notifications":
            overrides["run_worker"] = False
        if name == "fatma-soc":
            overrides["run_background"] = False
        if name == "security-ingest":
            overrides["raw_store_path"] = tmp / "raw"
            overrides["quarantine_path"] = tmp / "quarantine"
        settings = cfg.Settings(**overrides)
        rt = build_runtime(settings, {})
        rt.audit = AuditClient(name, audit_sink)
        rt.extras["_downstream"] = downstream
        app = main.create(settings)
        app.state.runtime = rt
        apps[name] = app
        runtimes[name] = rt
    for rt in runtimes.values():
        for aud in rt.extras["_downstream"]:
            if aud in apps:
                rt.clients[aud] = ServiceClient(aud, f"http://{aud}", rt.identity,
                                                transport=httpx.ASGITransport(app=apps[aud]))
    for app in apps.values():
        await stack.enter_async_context(app.router.lifespan_context(app))
    enc = FieldEncryptor(keyring, bik)
    return Platform(apps=apps, runtimes=runtimes, identities=identities, audit=audit_sink,
                    enc=enc, env=env)
