import hashlib
import hmac
import time

import pytest

from platform_core.errors import Unauthenticated
from platform_core.security.service_auth import InMemoryReplayCache
from security_ingest import webhook_auth
from whatsapp_service.meta import parse_webhook, verify_signature


def meta_sig(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def test_meta_signature_validation():
    body = b'{"object":"whatsapp_business_account"}'
    assert verify_signature(body, meta_sig("s3cret", body), "s3cret")
    assert not verify_signature(body, meta_sig("wrong", body), "s3cret")
    assert not verify_signature(body + b" ", meta_sig("s3cret", body), "s3cret")
    assert not verify_signature(body, None, "s3cret")
    assert not verify_signature(body, meta_sig("", body), "")  # unconfigured secret fails closed


def test_meta_payload_parsing():
    payload = {"object": "whatsapp_business_account", "entry": [{"changes": [{
        "field": "messages", "value": {
            "metadata": {"phone_number_id": "123"},
            "contacts": [{"wa_id": "15551234567", "profile": {"name": "Ana"}}],
            "messages": [
                {"from": "15551234567", "id": "wamid.1", "timestamp": "1700000000", "type": "text",
                 "text": {"body": "Hello"}},
                {"from": "15551234567", "id": "wamid.2", "type": "interactive",
                 "interactive": {"list_reply": {"id": "slot_abc", "title": "Mon 09:00"}}},
                {"from": "15551234567", "id": "wamid.3", "type": "image", "image": {"id": "m"}},
                {"from": "not-a-number", "id": "wamid.4", "type": "text", "text": {"body": "x"}},
            ],
            "statuses": [{"id": "wamid.9", "status": "delivered", "recipient_id": "1"}]}}]}]}
    msgs, statuses = parse_webhook(payload)
    assert [m.kind for m in msgs] == ["text", "interactive", "unsupported"]
    assert msgs[1].reply_id == "slot_abc" and msgs[0].profile_name == "Ana"
    assert statuses[0].status == "delivered"


async def test_ingest_signature_timestamp_and_replay():
    cache = InMemoryReplayCache()
    body = b"[]"
    good = webhook_auth.sign("secret", body)
    await webhook_auth.verify("siem", {"x-signature": good}, body, "secret", cache, 300)
    with pytest.raises(Unauthenticated):
        await webhook_auth.verify("siem", {"x-signature": good}, body, "secret", cache, 300)
    old = webhook_auth.sign("secret", body, int(time.time()) - 1000)
    with pytest.raises(Unauthenticated):
        await webhook_auth.verify("siem", {"x-signature": old}, body, "secret", cache, 300)
    with pytest.raises(Unauthenticated):  # token auth only for vendors that cannot sign
        await webhook_auth.verify("siem", {"x-ingest-token": "secret"}, body, "secret", cache, 300)
    await webhook_auth.verify("cloudflare", {"x-ingest-token": "secret"}, body, "secret", cache,
                              300)
