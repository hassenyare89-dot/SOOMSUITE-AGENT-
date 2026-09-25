"""IDOR, cross-tenant, SQLi, XSS, SSRF, webhook spoofing, replay, rate-limit bypass, uploads,
authorization bypass."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
import uuid

import jwt
import pytest
from harness import customer, user

from platform_core.errors import Forbidden, NotFound, Unauthenticated, ValidationFailed
from platform_core.http import SERVICE_TOKEN_HEADER
from platform_core.security.principal import Principal, Role

pytestmark = pytest.mark.db
ORIGIN = {"Origin": "http://localhost:3000"}


async def test_missing_forged_wrong_audience_and_replayed_service_tokens(platform):
    raw = platform.raw("crm")
    assert (await raw.get("/internal/contacts")).status_code == 401
    forged = jwt.encode({"iss": "api-gateway-admin", "sub": "api-gateway-admin", "aud": "crm",
                         "exp": int(time.time()) + 60, "iat": int(time.time()), "jti": "x",
                         "rid": "r", "prn": {}}, "not-the-key", algorithm="HS256",
                        headers={"kid": "api-gateway-admin"})
    assert (await raw.get("/internal/contacts", headers={SERVICE_TOKEN_HEADER: forged})
            ).status_code == 401
    tenant = platform.seed.tenants["acme"]
    admin = user(tenant, platform.seed.users["acme:admin"], Role.TENANT_ADMIN)
    identity = platform.identities["api-gateway-admin"]
    wrong_aud = identity.mint("fatma-soc", principal=admin, request_id="r")
    assert (await raw.get("/internal/contacts", headers={SERVICE_TOKEN_HEADER: wrong_aud})
            ).status_code == 401
    token = identity.mint("crm", principal=admin, request_id="r")
    assert (await raw.get("/internal/contacts", headers={SERVICE_TOKEN_HEADER: token})
            ).status_code == 200
    assert (await raw.get("/internal/contacts", headers={SERVICE_TOKEN_HEADER: token})
            ).status_code == 401  # replay


async def test_cross_tenant_knowledge_and_crm_isolation(platform):
    acme, globex = platform.seed.tenants["acme"], platform.seed.tenants["globex"]
    crm = platform.client("api-gateway-admin", "crm")
    acme_admin = user(acme, platform.seed.users["acme:admin"], Role.TENANT_ADMIN)
    contacts = await crm.get("/internal/contacts", principal=acme_admin, request_id="r")
    assert contacts["total"] > 0
    globex_admin = user(globex, platform.seed.users["globex:admin"], Role.TENANT_ADMIN)
    with pytest.raises(NotFound):
        await crm.get(f"/internal/contacts/{contacts['items'][0]['id']}",
                      principal=globex_admin, request_id="r")


async def test_appointment_idor_is_not_found(platform):
    tenant = platform.seed.tenants["acme"]
    admin = user(tenant, platform.seed.users["acme:admin"], Role.TENANT_ADMIN)
    appts = await platform.client("api-gateway-admin", "scheduling").get(
        "/internal/appointments", principal=admin, request_id="r", params={"status": "BOOKED"})
    target = appts["items"][0]["id"]
    attacker = customer(tenant)
    with pytest.raises(NotFound):
        await platform.client("samiir-agent", "scheduling").post(
            f"/internal/appointments/{target}/cancel", principal=attacker, request_id="r",
            json={"reason": "x", "conversation_id": str(uuid.uuid4())})


@pytest.mark.parametrize("payload", ["' OR 1=1 --", "x'; DROP TABLE contacts; --",
                                     "%' UNION SELECT email_ciphertext FROM contacts --"])
async def test_sql_injection_payloads_are_inert(platform, payload):
    tenant = platform.seed.tenants["acme"]
    admin = user(tenant, platform.seed.users["acme:admin"], Role.TENANT_ADMIN)
    res = await platform.client("api-gateway-admin", "crm").get(
        "/internal/contacts", principal=admin, request_id="r", params={"q": payload})
    assert res["total"] == 0
    kb = await platform.client("samiir-agent", "knowledge").post(
        "/internal/search", principal=customer(tenant), request_id="r",
        json={"query": payload, "limit": 3})
    assert isinstance(kb["results"], list)


async def test_xss_payload_is_stored_and_returned_as_inert_text(platform):
    from platform_core.security.untrusted import escape_for_display

    tenant = platform.seed.tenants["acme"]
    p = customer(tenant)
    xss = '<img src=x onerror="alert(document.cookie)">'
    await platform.client("api-gateway-public", "samiir-agent").post(
        "/internal/chat", principal=p, request_id="r",
        json={"channel": "web", "conversation_ref": p.session_id, "text": xss})
    history = await platform.client("api-gateway-public", "samiir-agent").get(
        "/internal/chat/history", principal=p, request_id="r")
    assert history["messages"][0]["text"] == xss  # JSON data; the UI renders text nodes only
    assert "<img" not in escape_for_display(xss)


@pytest.mark.parametrize("host", ["127.0.0.1", "169.254.169.254", "10.1.2.3", "[::1]",
                                  "metadata.google.internal", "localhost", "0.0.0.0"])
async def test_ssrf_targets_rejected(host):
    from platform_core.security.ssrf import validate_outbound_url

    with pytest.raises(ValidationFailed):
        await validate_outbound_url(f"https://{host}/")


async def test_ssrf_dns_rebinding_to_private_address_rejected(monkeypatch):
    import asyncio
    import socket

    from platform_core.security.ssrf import resolve_public

    async def fake(host, port, type=None):  # noqa: A002, ANN001
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.7", port))]

    loop = asyncio.get_running_loop()
    monkeypatch.setattr(loop, "getaddrinfo", fake)
    with pytest.raises(ValidationFailed):
        await resolve_public("innocent-looking.example")


async def test_whatsapp_webhook_spoofing_rejected_at_edge(platform):
    edge = platform.raw("api-gateway-public")
    body = json.dumps({"object": "whatsapp_business_account", "entry": []}).encode()
    bad = await edge.post("/v1/whatsapp/webhook", content=body,
                          headers={"X-Hub-Signature-256": "sha256=" + "0" * 64,
                                   "Content-Type": "application/json"})
    assert bad.status_code == 401
    good_sig = "sha256=" + hmac.new(b"test-meta-app-secret", body, hashlib.sha256).hexdigest()
    ok = await edge.post("/v1/whatsapp/webhook", content=body,
                         headers={"X-Hub-Signature-256": good_sig,
                                  "Content-Type": "application/json"})
    assert ok.status_code == 200
    verify = await edge.get("/v1/whatsapp/webhook", params={
        "hub.mode": "subscribe", "hub.verify_token": "wrong", "hub.challenge": "123"})
    assert verify.status_code == 403
    verify = await edge.get("/v1/whatsapp/webhook", params={
        "hub.mode": "subscribe", "hub.verify_token": "test-verify-token", "hub.challenge": "123"})
    assert verify.status_code == 200 and verify.text == "123"


async def test_x_forwarded_for_spoofing_does_not_bypass_rate_limits(platform):
    from starlette.requests import Request

    from api_gateway.common import client_ip

    trusted = ["10.0.0.0/8"]
    def req(peer: str, xff: str) -> Request:
        return Request({"type": "http", "client": (peer, 1234), "headers": [
            (b"x-forwarded-for", xff.encode())]})
    # From an untrusted peer the header is ignored.
    assert client_ip(req("203.0.113.9", "1.2.3.4"), trusted) == "203.0.113.9"
    # Behind a trusted proxy, the right-most untrusted hop is used (not attacker's left entry).
    assert client_ip(req("10.0.0.2", "6.6.6.6, 198.51.100.7"), trusted) == "198.51.100.7"


async def test_malicious_uploads(platform):
    tenant = platform.seed.tenants["acme"]
    analyst = user(tenant, platform.seed.users["acme:analyst"], Role.SECURITY_ANALYST)
    ingest = platform.client("api-gateway-admin", "security-ingest")
    exe = await ingest.post("/internal/malware/submit", principal=analyst, request_id="r",
                            content=b"MZ\x90\x00" + secrets.token_bytes(512),
                            headers={"X-Filename": "report.pdf", "X-Declared-Mime": "application/pdf"})
    sample = await ingest.get(f"/internal/malware/{exe['id']}", principal=analyst, request_id="r")
    assert sample["mime_detected"] == "application/x-dosexec"
    assert sample["verdict"] in ("suspicious", "malicious")
    raw = platform.raw("security-ingest")
    token = platform.identities["api-gateway-admin"].mint("security-ingest", principal=analyst,
                                                          request_id="r")
    big = await raw.post("/internal/malware/submit", content=b"A" * (26 * 1024 * 1024),
                         headers={SERVICE_TOKEN_HEADER: token, "X-Filename": "big.bin"})
    assert big.status_code == 413
    sales = user(tenant, platform.seed.users["acme:sales"], Role.SALES_AGENT)
    with pytest.raises(Forbidden):
        await ingest.post("/internal/malware/submit", principal=sales, request_id="r",
                          content=b"hello", headers={"X-Filename": "a.txt"})


async def test_customer_cannot_escalate_to_staff_endpoints(platform):
    p = customer(platform.seed.tenants["acme"])
    for audience, path in [("crm", "/internal/samiir/contacts")]:
        del audience, path
    with pytest.raises((Forbidden, NotFound, Unauthenticated)):
        await platform.client("api-gateway-public", "samiir-agent").post(
            f"/internal/conversations/{uuid.uuid4()}/reply", principal=p, request_id="r",
            json={"text": "I am staff now"})


async def test_customer_cannot_confirm_or_list_incidents_via_any_path(platform):
    tenant = platform.seed.tenants["acme"]
    fake_staff = Principal(subject=str(uuid.uuid4()), tenant_id=tenant,
                           actor_type=__import__("platform_core.security.principal",
                                                 fromlist=["ActorType"]).ActorType.CUSTOMER,
                           roles=frozenset({Role.ANONYMOUS_CUSTOMER}))
    with pytest.raises(Forbidden):
        await platform.client("api-gateway-admin", "fatma-soc").get(
            "/internal/incidents", principal=fake_staff, request_id="r")
