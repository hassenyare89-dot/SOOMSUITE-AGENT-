"""FATMA end-to-end: signed ingestion → normalization → correlation → incidents → approvals."""

from __future__ import annotations

import gzip
import json
import secrets
import time
from datetime import UTC, datetime

import pytest
from harness import INGEST_TEST_SECRET, user

from platform_core.errors import Conflict, Forbidden, Unauthenticated, ValidationFailed
from platform_core.security.principal import ActorType, Principal, Role
from security_ingest.webhook_auth import sign

pytestmark = pytest.mark.db
SECRET = INGEST_TEST_SECRET


def edge(platform):  # noqa: ANN001
    return platform.client("api-gateway-public", "security-ingest")


def nil_principal() -> Principal:
    import uuid

    return Principal(subject="edge", tenant_id=uuid.UUID(int=0), actor_type=ActorType.SERVICE,
                     roles=frozenset({Role.SYSTEM_SERVICE}))


def cf_event(ip: str, path: str, query: str = "", action: str = "block") -> dict:
    return {"RayID": secrets.token_hex(8), "ClientIP": ip, "ClientRequestHost": "www.acme.example",
            "ClientRequestPath": path, "ClientRequestQuery": query, "ClientRequestMethod": "GET",
            "ClientRequestUserAgent": "sqlmap/1.8", "ClientCountry": "nl", "Action": action,
            "Source": "firewallManaged", "RuleID": "100000",
            "Datetime": datetime.now(UTC).isoformat()}


async def post_ingest(platform, kind: str, key: str, body: bytes, headers: dict):  # noqa: ANN001
    return await edge(platform).request("POST", f"/internal/ingest/{kind}/{key}",
                                        principal=nil_principal(), request_id=secrets.token_hex(8),
                                        content=body, headers=headers)


async def test_unsigned_or_replayed_ingest_is_rejected(platform):
    body = b'{"events": []}'
    with pytest.raises(Unauthenticated):
        await post_ingest(platform, "siem", "ing_acme_siem", body, {})
    with pytest.raises(Unauthenticated):
        await post_ingest(platform, "siem", "ing_acme_siem", body,
                          {"X-Signature": sign("wrong-secret", body)})
    stale = sign(SECRET, body, int(time.time()) - 3600)
    with pytest.raises(Unauthenticated):
        await post_ingest(platform, "siem", "ing_acme_siem", body, {"X-Signature": stale})
    good = sign(SECRET, body)
    await post_ingest(platform, "siem", "ing_acme_siem", body, {"X-Signature": good})
    with pytest.raises(Unauthenticated):  # replay of the exact same delivery
        await post_ingest(platform, "siem", "ing_acme_siem", body, {"X-Signature": good})


async def test_cloudflare_sqli_creates_suspected_incident(platform):
    tenant = platform.seed.tenants["acme"]
    events = [cf_event("198.51.100.23", "/products", "id=1%20UNION%20SELECT%20password%20FROM%20users")
              for _ in range(5)]
    body = gzip.compress("\n".join(json.dumps(e) for e in events).encode())
    resp = await post_ingest(platform, "cloudflare", "ing_acme_cloudflare", body,
                             {"X-Ingest-Token": SECRET, "Content-Encoding": "gzip"})
    assert resp["stored"] >= 5
    # Replaying the same batch is idempotent (dedupe keys), even with a new token delivery.
    again = await post_ingest(platform, "cloudflare", "ing_acme_cloudflare", body,
                              {"X-Ingest-Token": SECRET, "Content-Encoding": "gzip"})
    assert again["stored"] == 0
    analyst = user(tenant, platform.seed.users["acme:analyst"], Role.SECURITY_ANALYST)
    soc = platform.client("api-gateway-admin", "fatma-soc")
    incidents = await soc.get("/internal/incidents", principal=analyst, request_id="t",
                              params={"open_only": True})
    sqli = [i for i in incidents["items"] if i["category"] == "sql_injection"]
    assert sqli, incidents
    assert all(i["claim_status"] == "SUSPECTED INCIDENT" for i in incidents["items"])
    assert sqli[0]["risk_level"] in ("SUSPICIOUS", "HIGH RISK", "CRITICAL")


async def test_brute_force_detection(platform):
    body = "\n".join(json.dumps({"event": "login_failure", "user": f"user{i % 7}@acme.example",
                                 "ip": "203.0.113.77", "timestamp": datetime.now(UTC).isoformat(),
                                 "id": secrets.token_hex(6)}) for i in range(15)).encode()
    await post_ingest(platform, "auth", "ing_acme_auth", body, {"X-Signature": sign(SECRET, body)})
    tenant = platform.seed.tenants["acme"]
    analyst = user(tenant, platform.seed.users["acme:analyst"], Role.SECURITY_ANALYST)
    incidents = await platform.client("api-gateway-admin", "fatma-soc").get(
        "/internal/incidents", principal=analyst, request_id="t")
    cred = [i for i in incidents["items"] if i["category"] == "credential_attack"]
    assert cred
    names = {s["name"] for i in cred for s in i["signals"]}
    assert "credential_stuffing" in names or "brute_force" in names


async def test_cross_tenant_incident_access_is_404(platform):
    from platform_core.errors import NotFound

    acme, globex = platform.seed.tenants["acme"], platform.seed.tenants["globex"]
    soc = platform.client("api-gateway-admin", "fatma-soc")
    acme_eng = user(acme, platform.seed.users["acme:engineer"], Role.SECURITY_ENGINEER)
    items = (await soc.get("/internal/incidents", principal=acme_eng, request_id="t"))["items"]
    globex_eng = user(globex, platform.seed.users["globex:engineer"], Role.SECURITY_ENGINEER)
    with pytest.raises(NotFound):
        await soc.get(f"/internal/incidents/{items[0]['id']}", principal=globex_eng,
                      request_id="t")
    assert (await soc.get("/internal/incidents", principal=globex_eng, request_id="t"))[
        "total"] == 0


async def test_incident_confirmation_requires_human_evidence(platform):
    tenant = platform.seed.tenants["acme"]
    soc = platform.client("api-gateway-admin", "fatma-soc")
    eng = user(tenant, platform.seed.users["acme:engineer"], Role.SECURITY_ENGINEER)
    inc = (await soc.get("/internal/incidents", principal=eng, request_id="t"))["items"][0]
    analyst = user(tenant, platform.seed.users["acme:analyst"], Role.SECURITY_ANALYST)
    with pytest.raises(Forbidden):
        await soc.post(f"/internal/incidents/{inc['id']}/confirm", principal=analyst,
                       request_id="t", json={"justification": "x" * 40, "evidence_refs": ["a"],
                                             "checklist": ["x"]})
    with pytest.raises(ValidationFailed):
        await soc.post(f"/internal/incidents/{inc['id']}/confirm", principal=eng,
                       request_id="t", json={"justification": "Looks bad, trust me " * 3,
                                             "evidence_refs": ["ticket-1"], "checklist": ["x"]})
    no_mfa = user(tenant, platform.seed.users["acme:engineer"], Role.SECURITY_ENGINEER, mfa=False)
    with pytest.raises(Forbidden):
        await soc.post(f"/internal/incidents/{inc['id']}/confirm", principal=no_mfa,
                       request_id="t", json={"justification": "x" * 40, "evidence_refs": ["a"],
                                             "checklist": ["x"]})


async def test_defense_action_requires_distinct_human_approval_bound_to_payload(platform):
    tenant = platform.seed.tenants["acme"]
    soc = platform.client("api-gateway-admin", "fatma-soc")
    approvals = platform.client("api-gateway-admin", "approvals")
    eng1 = user(tenant, platform.seed.users["acme:engineer"], Role.SECURITY_ENGINEER)
    eng2 = user(tenant, platform.seed.users["acme:engineer2"], Role.SECURITY_ENGINEER)
    action = await soc.post("/internal/actions", principal=eng1, request_id="t", json={
        "action_type": "block_country", "target": "KP", "ttl_seconds": 3600,
        "rationale": "Layer-7 flood concentrated from one country"})
    assert action["status"] == "RECOMMENDED" and action["risk_level"] == "HIGH"
    with pytest.raises(Conflict):  # cannot execute without approval
        await soc.post(f"/internal/actions/{action['id']}/execute", principal=eng1, request_id="t")
    action = await soc.post(f"/internal/actions/{action['id']}/request-approval", principal=eng1,
                            request_id="t")
    appr = await approvals.get(f"/internal/approvals/{action['approval_id']}", principal=eng1,
                               request_id="t")
    # The requester cannot approve their own request.
    with pytest.raises(Forbidden):
        await approvals.post(f"/internal/approvals/{appr['id']}/decide", principal=eng1,
                             request_id="t", json={"decision": "approve",
                                                   "payload_hash": appr["payload_hash"]})
    # An approver who reviewed a different payload cannot approve.
    with pytest.raises(Conflict):
        await approvals.post(f"/internal/approvals/{appr['id']}/decide", principal=eng2,
                             request_id="t", json={"decision": "approve",
                                                   "payload_hash": "0" * 64})
    decided = await approvals.post(f"/internal/approvals/{appr['id']}/decide", principal=eng2,
                                   request_id="t", json={"decision": "approve",
                                                         "payload_hash": appr["payload_hash"]})
    assert decided["status"] == "APPROVED" and decided["approval_signature"]
    executed = await soc.post(f"/internal/actions/{action['id']}/execute", principal=eng1,
                              request_id="t")
    assert executed["status"] == "ACTIVE"  # manual provider → runbook reference
    # Single use: the approval cannot be redeemed twice.
    fatma = platform.client("fatma-soc", "approvals")
    from platform_core.security.principal import Principal as Pr

    with pytest.raises(Conflict):
        await fatma.post(f"/internal/approvals/{appr['id']}/consume",
                         principal=Pr.system(tenant, "fatma-soc"), request_id="t",
                         json={"action_type": appr["action_type"],
                               "payload": appr["action_payload"]})


async def test_changed_parameters_invalidate_approval(platform):
    tenant = platform.seed.tenants["acme"]
    fatma = platform.client("fatma-soc", "approvals")
    system = Principal.system(tenant, "fatma-soc")
    payload = {"tenant_id": str(tenant), "action_type": "defense.temp_block_ip",
               "target": "198.51.100.23", "ttl_seconds": 900}
    req = await fatma.post("/internal/approvals", principal=system, request_id="t", json={
        "action_type": "defense.temp_block_ip", "payload": payload, "reason": "test approval"})
    eng2 = user(tenant, platform.seed.users["acme:engineer2"], Role.SECURITY_ENGINEER)
    await platform.client("api-gateway-admin", "approvals").post(
        f"/internal/approvals/{req['id']}/decide", principal=eng2, request_id="t",
        json={"decision": "approve", "payload_hash": req["payload_hash"]})
    with pytest.raises(Forbidden):
        await fatma.post(f"/internal/approvals/{req['id']}/consume", principal=system,
                         request_id="t", json={"action_type": "defense.temp_block_ip",
                                               "payload": {**payload, "ttl_seconds": 86400}})
    ok = await fatma.post(f"/internal/approvals/{req['id']}/consume", principal=system,
                          request_id="t", json={"action_type": "defense.temp_block_ip",
                                                "payload": payload})
    assert ok["status"] == "EXECUTED"


async def test_malware_submission_quarantines_and_detects_eicar(platform):
    tenant = platform.seed.tenants["acme"]
    eicar = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    analyst = user(tenant, platform.seed.users["acme:analyst"], Role.SECURITY_ANALYST)
    ingest = platform.client("api-gateway-admin", "security-ingest")
    res = await ingest.post("/internal/malware/submit", principal=analyst, request_id="t",
                            content=eicar, headers={"X-Filename": "../../invoice.pdf.exe",
                                                    "X-Declared-Mime": "application/pdf"})
    assert res["filename_sanitized"] == "invoice.pdf.exe"
    sample = await ingest.get(f"/internal/malware/{res['id']}", principal=analyst, request_id="t")
    assert sample["verdict"] == "malicious"
    assert sample["quarantine_status"] == "QUARANTINED"
    raw_files = list((platform.runtimes["security-ingest"].extras["ingest"].quarantine.store.root)
                     .rglob("*.bin"))
    assert raw_files and all(eicar not in f.read_bytes() for f in raw_files)  # encrypted at rest
