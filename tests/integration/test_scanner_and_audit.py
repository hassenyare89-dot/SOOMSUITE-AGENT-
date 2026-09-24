"""Scan authorization gate, approval-bound start, and the hash-chained audit log."""

from __future__ import annotations

import secrets
import uuid

import pytest
from harness import user

from platform_core.audit import AuditEvent
from platform_core.errors import Conflict, Forbidden
from platform_core.security.principal import Principal, Role

pytestmark = [pytest.mark.db, pytest.mark.asyncio(loop_scope="session")]


def scan_body(asset_id, **kw):  # noqa: ANN001
    return {"asset_id": str(asset_id), "profile": "safe-passive",
            "authorization_ticket": "SEC-1234", "scanners": ["nuclei"],
            "idempotency_key": secrets.token_hex(12), **kw}


async def test_scan_requires_all_preconditions_and_distinct_approver(platform):
    tenant = platform.seed.tenants["acme"]
    asset = platform.seed.assets["acme"]
    ctl = platform.client("api-gateway-admin", "scanner-controller")
    eng = user(tenant, platform.seed.users["acme:engineer"], Role.SECURITY_ENGINEER)
    eng2 = user(tenant, platform.seed.users["acme:engineer2"], Role.SECURITY_ENGINEER)
    analyst = user(tenant, platform.seed.users["acme:analyst"], Role.SECURITY_ANALYST)

    # Analysts cannot request scans at all.
    with pytest.raises(Forbidden):
        await ctl.post("/internal/scans", principal=analyst, request_id="t", json=scan_body(asset))
    # Not allowlisted yet → gate fails with the failing check named.
    check = await ctl.post("/internal/scans/gate-check", principal=eng, request_id="t",
                           json=scan_body(asset))
    assert check["passed"] is False and check["checks"]["4_target_allowlisted"] is False
    with pytest.raises(Forbidden):
        await ctl.post("/internal/scans", principal=eng, request_id="t", json=scan_body(asset))

    await ctl.post(f"/internal/assets/{asset}/allowlist", principal=eng, request_id="t",
                   json={"allowlisted": True})
    job = await ctl.post("/internal/scans", principal=eng, request_id="t", json=scan_body(asset))
    assert job["status"] == "PENDING_APPROVAL" and job["approval_id"]
    # Starting before approval fails: the approval cannot be consumed.
    with pytest.raises(Conflict):
        await ctl.post(f"/internal/scans/{job['id']}/start", principal=eng, request_id="t")
    approvals = platform.client("api-gateway-admin", "approvals")
    appr = await approvals.get(f"/internal/approvals/{job['approval_id']}", principal=eng2,
                               request_id="t")
    assert appr["action_payload"]["target_url"] == "https://www.acme.example/"
    await approvals.post(f"/internal/approvals/{appr['id']}/decide", principal=eng2,
                         request_id="t", json={"decision": "approve",
                                               "payload_hash": appr["payload_hash"]})
    started = await ctl.post(f"/internal/scans/{job['id']}/start", principal=eng, request_id="t")
    assert started["status"] == "QUEUED" and started["workflow_id"] == f"scan-{job['id']}"
    cancelled = await ctl.post(f"/internal/scans/{job['id']}/cancel", principal=eng,
                               request_id="t")
    assert cancelled["status"] == "CANCELLED"


async def test_asset_cannot_be_allowlisted_without_verification(platform):
    tenant = platform.seed.tenants["acme"]
    ctl = platform.client("api-gateway-admin", "scanner-controller")
    eng = user(tenant, platform.seed.users["acme:engineer"], Role.SECURITY_ENGINEER)
    asset = await ctl.post("/internal/assets", principal=eng, request_id="t", json={
        "name": "Marketing site", "canonical_target": f"m{secrets.token_hex(3)}.acme.example"})
    with pytest.raises(Conflict):
        await ctl.post(f"/internal/assets/{asset['id']}/allowlist", principal=eng,
                       request_id="t", json={"allowlisted": True})
    challenge = await ctl.post(f"/internal/assets/{asset['id']}/verifications", principal=eng,
                               request_id="t", json={"method": "dns_txt"})
    assert challenge["instructions"]["record_name"].startswith("_samiir-fatma-verify.")


async def test_private_scan_targets_are_rejected(platform):
    from platform_core.errors import ValidationFailed

    tenant = platform.seed.tenants["acme"]
    ctl = platform.client("api-gateway-admin", "scanner-controller")
    eng = user(tenant, platform.seed.users["acme:engineer"], Role.SECURITY_ENGINEER)
    for target in ("localhost", "10.0.0.5", "169.254.169.254", "db.internal", "svc.cluster.local"):
        with pytest.raises(ValidationFailed):
            await ctl.post("/internal/assets", principal=eng, request_id="t",
                           json={"name": "bad target", "canonical_target": target})


async def test_audit_chain_is_verifiable_and_append_only(platform):
    import asyncpg
    from conftest import ADMIN_URL

    tenant = platform.seed.tenants["globex"]
    audit = platform.client("crm", "audit")
    system = Principal.system(tenant, "crm")
    for i in range(3):
        await audit.post("/internal/audit/events", principal=system, request_id=f"r{i}",
                         json=AuditEvent(tenant_id=tenant, actor_type="user", actor_id="u1",
                                         service="crm", action="crm.contact.update",
                                         request_id=f"r{i}", result="success",
                                         metadata_redacted={"password": "hunter2"}
                                         ).model_dump(mode="json"))
    admin = user(tenant, platform.seed.users["globex:admin"], Role.TENANT_ADMIN)
    reader = platform.client("api-gateway-admin", "audit")
    logs = await reader.get("/internal/audit/logs", principal=admin, request_id="t")
    assert logs["total"] >= 3
    assert all(item["metadata_redacted"].get("password") == "[REDACTED]" for item in logs["items"])
    assert all(item["service"] == "crm" for item in logs["items"])  # writer from token, not body
    assert (await reader.get("/internal/audit/verify", principal=admin, request_id="t"))["valid"]
    # A service cannot write audit events into another tenant's chain.
    from platform_core.errors import NotFound

    with pytest.raises(NotFound):
        await audit.post("/internal/audit/events", principal=system, request_id="x",
                         json=AuditEvent(tenant_id=platform.seed.tenants["acme"],
                                         actor_type="user", actor_id="u", service="crm",
                                         action="x", request_id="x", result="success"
                                         ).model_dump(mode="json"))
    # Even the database superuser path cannot silently edit history (trigger).
    conn = await asyncpg.connect(ADMIN_URL.replace("+asyncpg", ""))
    try:
        with pytest.raises(asyncpg.RaiseError):
            await conn.execute("UPDATE audit_logs SET action = 'tampered'")
    finally:
        await conn.close()


async def test_expired_approval_cannot_be_consumed(platform):
    import asyncpg
    from conftest import ADMIN_URL

    tenant = platform.seed.tenants["acme"]
    fatma = platform.client("fatma-soc", "approvals")
    system = Principal.system(tenant, "fatma-soc")
    payload = {"tenant_id": str(tenant), "action_type": "defense.challenge_ip",
               "target": "198.51.100.99", "ttl_seconds": 600}
    req = await fatma.post("/internal/approvals", principal=system, request_id="t", json={
        "action_type": "defense.challenge_ip", "payload": payload, "reason": "expiry test"})
    eng2 = user(tenant, platform.seed.users["acme:engineer2"], Role.SECURITY_ENGINEER)
    await platform.client("api-gateway-admin", "approvals").post(
        f"/internal/approvals/{req['id']}/decide", principal=eng2, request_id="t",
        json={"decision": "approve", "payload_hash": req["payload_hash"]})
    conn = await asyncpg.connect(ADMIN_URL.replace("+asyncpg", ""))
    await conn.execute("UPDATE approval_requests SET expires_at = requested_at + interval '1 second'"
                       " WHERE id = $1", uuid.UUID(req["id"]))
    await conn.close()
    with pytest.raises(Conflict):
        await fatma.post(f"/internal/approvals/{req['id']}/consume", principal=system,
                         request_id="t", json={"action_type": "defense.challenge_ip",
                                               "payload": payload})
