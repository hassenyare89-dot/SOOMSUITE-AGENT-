"""End-to-end SAMIIR flows across knowledge, CRM, scheduling and notifications services."""

from __future__ import annotations

import secrets

import pytest
from harness import customer

pytestmark = [pytest.mark.db, pytest.mark.asyncio(loop_scope="session")]


async def chat(platform, principal, text, **extra):  # noqa: ANN001
    client = platform.client("api-gateway-public", "samiir-agent")
    return await client.post("/internal/chat", principal=principal, request_id=secrets.token_hex(8),
                             json={"channel": "web", "conversation_ref": principal.session_id,
                                   "text": text, **extra})


async def test_answers_from_approved_knowledge(platform):
    p = customer(platform.seed.tenants["acme"])
    reply = await chat(platform, p, "How long does onboarding take for monitoring?")
    assert "five business days" in reply["text"].lower()
    assert any(c["type"] == "sources" for c in reply["cards"])


async def test_pricing_comes_only_from_structured_data(platform):
    p = customer(platform.seed.tenants["acme"])
    reply = await chat(platform, p, "How much does Website Security Monitoring cost?")
    assert "USD 499" in reply["text"]


async def test_unknown_topic_escalates_instead_of_inventing(platform):
    p = customer(platform.seed.tenants["acme"])
    reply = await chat(platform, p, "Do you offer quantum blockchain penetration insurance xyzzy?")
    assert reply["escalated"] is True, reply


async def test_booking_flow_moves_pipeline_and_schedules_notifications(platform):
    tenant = platform.seed.tenants["acme"]
    p = customer(tenant)
    reply = await chat(platform, p, "I'd like to book a consultation")
    slots = next(c for c in reply["cards"] if c["type"] == "slots")["data"]["slots"]
    assert 2 <= len(slots) <= 5
    # Customer picks a slot button before giving contact details → asked for details.
    reply = await chat(platform, p, "slot 2")
    assert "email" in reply["text"].lower()
    reply = await chat(platform, p, "My name is Layla Hassan, layla@example.org")
    assert "confirmed" in reply["text"].lower()
    admin = platform.seed.users["acme:admin"]
    from harness import user

    from platform_core.security.principal import Role

    staff = user(tenant, admin, Role.TENANT_ADMIN)
    crm = platform.client("api-gateway-admin", "crm")
    opps = await crm.get("/internal/opportunities", principal=staff, request_id="t-1",
                         params={"stage": "APPOINTMENT_BOOKED"})
    assert opps["total"] >= 1
    sched = platform.client("api-gateway-admin", "scheduling")
    appts = await sched.get("/internal/appointments", principal=staff, request_id="t-2")
    assert any(a["status"] == "BOOKED" for a in appts["items"])
    notif = platform.client("api-gateway-admin", "notifications")
    notes = await notif.get("/internal/notifications", principal=staff, request_id="t-3")
    templates = {n["template"] for n in notes["items"]}
    assert {"customer.appointment_confirmation", "customer.appointment_reminder"} <= templates


async def test_offered_slot_cannot_be_double_booked(platform):
    tenant = platform.seed.tenants["acme"]
    a, b = customer(tenant), customer(tenant)
    ra = await chat(platform, a, "book a consultation please")
    rb = await chat(platform, b, "book a consultation please")
    slot_a = next(c for c in ra["cards"] if c["type"] == "slots")["data"]["slots"][0]
    slot_b = next(c for c in rb["cards"] if c["type"] == "slots")["data"]["slots"][0]
    assert slot_a["display"] == slot_b["display"]  # both were offered the same time
    await chat(platform, a, "I'm Ali, ali@example.org")
    await chat(platform, b, "I'm Bea, bea@example.org")
    first = await chat(platform, a, "x", selected_slot_token=slot_a["slot_token"])
    second = await chat(platform, b, "x", selected_slot_token=slot_b["slot_token"])
    assert "confirmed" in first["text"].lower()
    assert "confirmed" not in second["text"].lower()


async def test_customer_cannot_use_another_sessions_conversation(platform):
    from platform_core.errors import NotFound

    p = customer(platform.seed.tenants["acme"])
    client = platform.client("api-gateway-public", "samiir-agent")
    with pytest.raises(NotFound):
        await client.post("/internal/chat", principal=p, request_id="t", json={
            "channel": "web", "conversation_ref": "someone-elses-session-0001", "text": "hi"})
