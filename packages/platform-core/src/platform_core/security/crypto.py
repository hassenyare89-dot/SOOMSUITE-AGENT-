"""Field-level encryption (AES-256-GCM keyring) and keyed blind indexes.

Ciphertext format: ``v1.<key_id>.<base64url(nonce || ciphertext || tag)>``. The tenant id is
bound as associated data so a ciphertext cannot be transplanted into another tenant's row.
Keys come from the secret manager as ``{"active": "k2", "keys": {"k1": "<b64>", "k2": ...}}``
which supports rotation: decrypt with any listed key, encrypt with the active one.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import unicodedata
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      default=str).encode()


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def _b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


@dataclass(frozen=True)
class Keyring:
    active: str
    keys: dict[str, bytes]

    @classmethod
    def from_json(cls, raw: str) -> Keyring:
        data = json.loads(raw)
        keys = {kid: base64.b64decode(v) for kid, v in data["keys"].items()}
        if data["active"] not in keys or any(len(k) != 32 for k in keys.values()):
            raise ValueError("keyring requires an active 256-bit key")
        return cls(active=data["active"], keys=keys)

    @classmethod
    def generate(cls, kid: str = "k1") -> Keyring:
        return cls(active=kid, keys={kid: AESGCM.generate_key(bit_length=256)})

    def to_json(self) -> str:
        return json.dumps({"active": self.active,
                           "keys": {k: base64.b64encode(v).decode() for k, v in self.keys.items()}})


class FieldEncryptor:
    def __init__(self, keyring: Keyring, blind_index_key: bytes) -> None:
        if len(blind_index_key) < 32:
            raise ValueError("blind index key must be at least 256 bits")
        self._keyring = keyring
        self._bik = blind_index_key

    def encrypt(self, plaintext: str | None, tenant_id: UUID) -> str | None:
        if plaintext is None:
            return None
        nonce = os.urandom(12)
        kid = self._keyring.active
        ct = AESGCM(self._keyring.keys[kid]).encrypt(nonce, plaintext.encode(), tenant_id.bytes)
        return f"v1.{kid}.{_b64e(nonce + ct)}"

    def decrypt(self, token: str | None, tenant_id: UUID) -> str | None:
        if token is None:
            return None
        version, kid, body = token.split(".", 2)
        if version != "v1" or kid not in self._keyring.keys:
            raise ValueError("unknown ciphertext version or key")
        raw = _b64d(body)
        return AESGCM(self._keyring.keys[kid]).decrypt(raw[:12], raw[12:], tenant_id.bytes).decode()

    def needs_rotation(self, token: str) -> bool:
        return token.split(".", 2)[1] != self._keyring.active

    def blind_index(self, value: str | None, tenant_id: UUID, purpose: str) -> str | None:
        """Deterministic keyed hash for equality lookups (e.g. find contact by email)."""
        if value is None:
            return None
        normalized = unicodedata.normalize("NFKC", value).strip().lower()
        msg = f"{tenant_id}:{purpose}:{normalized}".encode()
        return hmac.new(self._bik, msg, hashlib.sha256).hexdigest()


def hmac_sign(key: bytes, message: bytes) -> str:
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def hmac_verify(key: bytes, message: bytes, signature_hex: str) -> bool:
    return hmac.compare_digest(hmac_sign(key, message), signature_hex)


def sign_token(key: bytes, payload: dict[str, Any]) -> str:
    """Compact HMAC-signed token (used for slot offers and CSRF tokens)."""
    body = _b64e(canonical_json(payload))
    return f"{body}.{hmac_sign(key, body.encode())}"


def verify_token(key: bytes, token: str) -> dict[str, Any] | None:
    try:
        body, sig = token.rsplit(".", 1)
    except ValueError:
        return None
    if not hmac_verify(key, body.encode(), sig):
        return None
    try:
        return json.loads(_b64d(body))
    except (ValueError, json.JSONDecodeError):
        return None


async def load_field_encryptor(secret_manager, keyring_ref: str | None,  # noqa: ANN001
                               blind_index_ref: str | None, *, allow_ephemeral: bool
                               ) -> FieldEncryptor:
    """Build the encryptor from secret-manager references (ephemeral only in development)."""
    from platform_core.security.secret_manager import SecretNotFound

    if keyring_ref and blind_index_ref:
        try:
            keyring = Keyring.from_json(await secret_manager.get(keyring_ref))
            bik = base64.b64decode(await secret_manager.get(blind_index_ref))
            return FieldEncryptor(keyring, bik)
        except SecretNotFound:
            if not allow_ephemeral:
                raise
    if not allow_ephemeral:
        raise RuntimeError("field encryption keys are required outside development")
    import logging

    logging.getLogger(__name__).warning("using EPHEMERAL field-encryption keys (development)")
    return FieldEncryptor(Keyring.generate(), os.urandom(32))
