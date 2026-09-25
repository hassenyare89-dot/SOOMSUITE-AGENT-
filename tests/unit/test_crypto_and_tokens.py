import uuid

import pytest

from platform_core.errors import Conflict
from platform_core.security.crypto import FieldEncryptor, Keyring, sign_token, verify_token
from platform_core.security.idempotency import IdempotencyStore


def test_field_encryption_binds_tenant_and_rotates():
    kr = Keyring.generate("k1")
    enc = FieldEncryptor(kr, b"x" * 32)
    t1, t2 = uuid.uuid4(), uuid.uuid4()
    ct = enc.encrypt("alice@example.com", t1)
    assert enc.decrypt(ct, t1) == "alice@example.com"
    from cryptography.exceptions import InvalidTag

    with pytest.raises(InvalidTag):
        enc.decrypt(ct, t2)  # transplanted into another tenant → authentication failure
    rotated = Keyring(active="k2", keys={**kr.keys, "k2": Keyring.generate("k2").keys["k2"]})
    enc2 = FieldEncryptor(rotated, b"x" * 32)
    assert enc2.decrypt(ct, t1) == "alice@example.com"
    assert enc2.needs_rotation(ct)


def test_blind_index_is_normalized_and_tenant_scoped():
    enc = FieldEncryptor(Keyring.generate(), b"y" * 32)
    t = uuid.uuid4()
    assert enc.blind_index(" Alice@Example.com ", t, "email") == enc.blind_index(
        "alice@example.com", t, "email")
    assert enc.blind_index("a@b.co", t, "email") != enc.blind_index("a@b.co", uuid.uuid4(), "email")


def test_signed_tokens_reject_tampering():
    tok = sign_token(b"k" * 32, {"slot": "2026-09-28T09:00"})
    assert verify_token(b"k" * 32, tok) == {"slot": "2026-09-28T09:00"}
    body, sig = tok.rsplit(".", 1)
    assert verify_token(b"k" * 32, body + "." + "0" * len(sig)) is None
    assert verify_token(b"other" * 8, tok) is None


async def test_idempotency_same_key_same_result_different_request_conflicts():
    store = IdempotencyStore(None, "t")
    calls = []

    async def work():
        calls.append(1)
        return {"id": "abc"}

    key = "k" * 20
    assert await store.run(scope="s", key=key, request={"a": 1}, func=work) == {"id": "abc"}
    assert await store.run(scope="s", key=key, request={"a": 1}, func=work) == {"id": "abc"}
    assert len(calls) == 1
    with pytest.raises(Conflict):
        await store.run(scope="s", key=key, request={"a": 2}, func=work)
