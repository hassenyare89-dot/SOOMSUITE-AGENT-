"""Service identities: short-lived, audience-bound, single-use Ed25519 JWTs.

In production these tokens ride on top of mesh mTLS (SPIFFE identities); they provide an
application-layer identity that survives proxies and carries the delegated principal.
"""

from __future__ import annotations

import base64
import json
import secrets
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol
from uuid import UUID

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from platform_core.errors import Forbidden, Unauthenticated
from platform_core.security.principal import AgentName, Principal
from platform_core.security.service_acl import AGENT_FOR_SERVICE, accepted_callers

ALGORITHM = "EdDSA"
LEEWAY_SECONDS = 5


@dataclass(frozen=True)
class RequestContext:
    """Verified context of an internal request."""

    caller: str
    receiver: str
    principal: Principal
    request_id: str
    source_ip: str | None = None
    agent_run_id: UUID | None = None

    @property
    def tenant_id(self) -> UUID:
        return self.principal.tenant_id

    @property
    def calling_agent(self) -> AgentName | None:
        return AGENT_FOR_SERVICE.get(self.caller)


def load_private_key(path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("service key must be Ed25519")
    return key


def public_key_to_b64(key: Ed25519PublicKey) -> str:
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode()


def load_trust_bundle(path: Path) -> dict[str, Ed25519PublicKey]:
    data = json.loads(path.read_text())
    return {
        name: Ed25519PublicKey.from_public_bytes(base64.b64decode(b64))
        for name, b64 in data["keys"].items()
    }


class ServiceIdentity:
    """Mints tokens for outbound calls. Holds this service's private key only."""

    def __init__(self, name: str, private_key: Ed25519PrivateKey, ttl_seconds: int = 60) -> None:
        self.name = name
        self._key = private_key
        self._ttl = ttl_seconds

    def mint(
        self,
        audience: str,
        *,
        principal: Principal,
        request_id: str,
        source_ip: str | None = None,
        agent_run_id: UUID | None = None,
    ) -> str:
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": self.name,
            "sub": self.name,
            "aud": audience,
            "iat": now,
            "nbf": now - 1,
            "exp": now + self._ttl,
            "jti": secrets.token_urlsafe(18),
            "rid": request_id,
            "prn": principal.to_claims(),
        }
        if source_ip:
            claims["sip"] = source_ip
        if agent_run_id:
            claims["arn"] = str(agent_run_id)
        return jwt.encode(claims, self._key, algorithm=ALGORITHM, headers={"kid": self.name})


class ReplayCache(Protocol):
    async def first_use(self, key: str, ttl_seconds: int) -> bool: ...


class InMemoryReplayCache:
    """Bounded in-process cache; used in tests and single-replica development."""

    def __init__(self, max_items: int = 100_000) -> None:
        self._items: OrderedDict[str, float] = OrderedDict()
        self._max = max_items

    async def first_use(self, key: str, ttl_seconds: int) -> bool:
        now = time.monotonic()
        while self._items:
            oldest_key, expires = next(iter(self._items.items()))
            if expires > now and len(self._items) < self._max:
                break
            self._items.pop(oldest_key)
        if key in self._items:
            return False
        self._items[key] = now + ttl_seconds
        return True


class RedisReplayCache:
    def __init__(self, redis: Any, prefix: str) -> None:
        self._redis = redis
        self._prefix = prefix

    async def first_use(self, key: str, ttl_seconds: int) -> bool:
        return bool(await self._redis.set(f"{self._prefix}:jti:{key}", "1", nx=True,
                                          ex=ttl_seconds))


@dataclass
class ServiceTokenVerifier:
    """Verifies inbound tokens addressed to ``receiver``."""

    receiver: str
    trust_bundle: dict[str, Ed25519PublicKey]
    replay_cache: ReplayCache = field(default_factory=InMemoryReplayCache)

    async def verify(self, token: str, *, allowed_callers: frozenset[str] | None = None
                     ) -> RequestContext:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise Unauthenticated("malformed service token") from exc
        kid = header.get("kid")
        if header.get("alg") != ALGORITHM or kid not in self.trust_bundle:
            raise Unauthenticated("untrusted service token")
        try:
            claims = jwt.decode(
                token,
                self.trust_bundle[kid],
                algorithms=[ALGORITHM],
                audience=self.receiver,
                leeway=LEEWAY_SECONDS,
                options={"require": ["iss", "aud", "exp", "iat", "jti", "prn", "rid"]},
            )
        except jwt.PyJWTError as exc:
            raise Unauthenticated("invalid service token") from exc
        caller = claims["iss"]
        if caller != kid or claims.get("sub") != caller:
            raise Unauthenticated("service token identity mismatch")
        accepted = accepted_callers(self.receiver)
        if allowed_callers is not None:
            accepted = accepted & allowed_callers
        if caller not in accepted:
            raise Forbidden("caller not permitted")
        ttl = max(1, int(claims["exp"]) - int(time.time()) + LEEWAY_SECONDS)
        if not await self.replay_cache.first_use(f"{caller}:{claims['jti']}", ttl):
            raise Unauthenticated("service token replayed")
        try:
            principal = Principal.from_claims(claims["prn"])
        except (KeyError, ValueError) as exc:
            raise Unauthenticated("invalid principal claims") from exc
        return RequestContext(
            caller=caller,
            receiver=self.receiver,
            principal=principal,
            request_id=str(claims["rid"])[:128],
            source_ip=claims.get("sip"),
            agent_run_id=UUID(claims["arn"]) if claims.get("arn") else None,
        )


def generate_keypair() -> tuple[bytes, str]:
    """Return (private PEM, public raw base64). Used by the bootstrap script and tests."""
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return pem, public_key_to_b64(key.public_key())
