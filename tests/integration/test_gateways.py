"""Edge behaviour through the real gateways (cookies, CSRF, origin checks, RBAC routing)."""

from __future__ import annotations

import asyncio

import pytest

pytestmark = pytest.mark.db
ORIGIN = {"Origin": "http://localhost:3000"}


async def widget_client(platform):  # noqa: ANN001
    client = platform.raw("api-gateway-public")
    key = platform.seed.widget_keys["acme"]
    resp = await client.post("/v1/widget/session", json={"key": key}, headers=ORIGIN)
    assert resp.status_code == 200, resp.text
    assert "httponly" in resp.headers["set-cookie"].lower()
    await asyncio.sleep(0.85)  # below this, messages are rejected as bot-like
    return client, resp.json()["csrf_token"]


async def test_widget_chat_requires_session_csrf_and_rejects_honeypot(platform):
    client, csrf = await widget_client(platform)
    no_csrf = await client.post("/v1/widget/messages", json={"text": "hello"}, headers=ORIGIN)
    assert no_csrf.status_code == 403
    ok = await client.post("/v1/widget/messages", json={"text": "What services do you offer?"},
                           headers={**ORIGIN, "X-CSRF-Token": csrf})
    assert ok.status_code == 200, ok.text
    assert ok.json()["text"]
    bot = await client.post("/v1/widget/messages", json={"text": "hi", "website": "spam.example"},
                            headers={**ORIGIN, "X-CSRF-Token": csrf})
    assert bot.status_code == 422
    history = await client.get("/v1/widget/messages")
    assert len(history.json()["messages"]) >= 2
    fresh = platform.raw("api-gateway-public")
    assert (await fresh.get("/v1/widget/messages")).status_code == 404  # no cookie → no history


async def test_widget_session_rejects_unknown_origin_and_key(platform):
    client = platform.raw("api-gateway-public")
    key = platform.seed.widget_keys["acme"]
    bad = await client.post("/v1/widget/session", json={"key": key},
                            headers={"Origin": "https://evil.example"})
    assert bad.status_code == 403
    unknown = await client.post("/v1/widget/session", json={"key": "pk_unknown_key_0000000000"},
                                headers=ORIGIN)
    assert unknown.status_code == 404


async def test_repeated_messages_are_throttled(platform):
    client, csrf = await widget_client(platform)
    codes = []
    for _ in range(5):
        r = await client.post("/v1/widget/messages", json={"text": "spam spam"},
                              headers={**ORIGIN, "X-CSRF-Token": csrf})
        codes.append(r.status_code)
    assert 429 in codes


async def admin_login(platform, handle: str):  # noqa: ANN001
    client = platform.raw("api-gateway-admin")
    r = await client.post("/auth/dev-login", json={"subject": f"dev|acme|{handle}"},
                          headers=ORIGIN)
    assert r.status_code == 200, r.text
    return client, {**ORIGIN, "X-CSRF-Token": r.json()["csrf_token"]}


async def test_sales_agent_cannot_reach_fatma_routes(platform):
    client, headers = await admin_login(platform, "sales")
    assert (await client.get("/v1/admin/crm/pipeline", headers=headers)).status_code == 200
    assert (await client.get("/v1/admin/fatma/incidents", headers=headers)).status_code == 403
    assert (await client.get("/v1/admin/scanner/scans", headers=headers)).status_code == 403
    assert (await client.get("/v1/admin/approvals", headers=headers)).status_code == 403


async def test_security_engineer_sees_soc_but_not_crm_writes(platform):
    client, headers = await admin_login(platform, "engineer")
    overview = await client.get("/v1/admin/fatma/soc/overview", headers=headers)
    assert overview.status_code == 200
    assert overview.json()["fatma_mode"] == "recommend_only"
    create = await client.post("/v1/admin/crm/contacts", json={"full_name": "X"}, headers=headers)
    assert create.status_code == 403


async def test_admin_mutations_require_csrf_and_origin(platform):
    client, headers = await admin_login(platform, "admin")
    body = {"fatma_mode": "recommend_only"}
    no_csrf = await client.patch("/v1/admin/identity/tenant", json=body, headers=ORIGIN)
    assert no_csrf.status_code == 403
    bad_origin = await client.patch("/v1/admin/identity/tenant", json=body,
                                    headers={**headers, "Origin": "https://evil.example"})
    assert bad_origin.status_code == 403
    ok = await client.patch("/v1/admin/identity/tenant", json=body, headers=headers)
    assert ok.status_code == 200


async def test_raw_secrets_are_never_accepted_for_integrations(platform):
    client, headers = await admin_login(platform, "admin")
    r = await client.post("/v1/admin/identity/integrations", headers=headers, json={
        "kind": "whatsapp.cloud", "name": "WA", "external_key": "123456789",
        "secret_ref": "EAAG-raw-access-token-value"})
    assert r.status_code == 422


async def test_path_traversal_through_proxy_is_blocked(platform):
    client, headers = await admin_login(platform, "admin")
    r = await client.get("/v1/admin/crm/..%2F..%2Finternal%2Faudit/logs", headers=headers)
    assert r.status_code in (404, 422)
