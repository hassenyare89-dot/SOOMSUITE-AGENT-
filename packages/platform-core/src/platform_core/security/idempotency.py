"""Idempotency keys: same key + same request → same stored response; same key + different
request → 409. Backed by Redis with a lock to prevent concurrent double execution."""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import Any

from platform_core.errors import Conflict, ValidationFailed
from platform_core.security.crypto import canonical_json, sha256_hex


def validate_key(key: str | None) -> str:
    if not key or not (16 <= len(key) <= 128) or not all(c.isalnum() or c in "-_:." for c in key):
        raise ValidationFailed("a valid Idempotency-Key header (16-128 chars) is required")
    return key


class IdempotencyStore:
    def __init__(self, redis: Any | None, prefix: str, ttl_seconds: int = 86_400) -> None:
        self._redis = redis
        self._prefix = prefix
        self._ttl = ttl_seconds
        self._memory: dict[str, str] = {}

    async def _get(self, k: str) -> str | None:
        if self._redis is None:
            return self._memory.get(k)
        v = await self._redis.get(k)
        return v.decode() if isinstance(v, bytes) else v

    async def _set(self, k: str, v: str, *, nx: bool = False, ex: int | None = None) -> bool:
        if self._redis is None:
            if nx and k in self._memory:
                return False
            self._memory[k] = v
            return True
        return bool(await self._redis.set(k, v, nx=nx, ex=ex or self._ttl))

    async def _delete(self, k: str) -> None:
        if self._redis is None:
            self._memory.pop(k, None)
        else:
            await self._redis.delete(k)

    async def run(
        self,
        *,
        scope: str,
        key: str,
        request: Any,
        func: Callable[[], Awaitable[dict[str, Any]]],
    ) -> dict[str, Any]:
        validate_key(key)
        request_hash = sha256_hex(canonical_json(request))
        rkey = f"{self._prefix}:idem:{scope}:{key}"
        existing = await self._get(rkey)
        if existing:
            record = json.loads(existing)
            if record["request_hash"] != request_hash:
                raise Conflict("idempotency key reused with a different request")
            if record["state"] == "done":
                return record["response"]
            raise Conflict("a request with this idempotency key is in progress")
        lock = json.dumps({"state": "pending", "request_hash": request_hash})
        if not await self._set(rkey, lock, nx=True, ex=120):
            raise Conflict("a request with this idempotency key is in progress")
        try:
            response = await func()
        except Exception:
            await self._delete(rkey)
            raise
        await self._set(rkey, json.dumps({"state": "done", "request_hash": request_hash,
                                          "response": response}, default=str))
        return response
