"""Server-side session store (Redis in deployments, memory in tests). Session ids are 256-bit
random values; only their SHA-256 is used as the storage key."""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from typing import Any


class SessionStore:
    def __init__(self, redis: Any | None, prefix: str) -> None:
        self._redis = redis
        self._prefix = prefix
        self._mem: dict[str, tuple[float, str]] = {}

    def _key(self, sid: str) -> str:
        return f"{self._prefix}:{hashlib.sha256(sid.encode()).hexdigest()}"

    async def create(self, data: dict[str, Any], ttl: int) -> str:
        sid = secrets.token_urlsafe(32)
        await self.put(sid, data, ttl)
        return sid

    async def put(self, sid: str, data: dict[str, Any], ttl: int) -> None:
        raw = json.dumps(data, default=str)
        if self._redis is not None:
            await self._redis.set(self._key(sid), raw, ex=ttl)
        else:
            self._mem[self._key(sid)] = (time.time() + ttl, raw)

    async def get(self, sid: str | None) -> dict[str, Any] | None:
        if not sid or len(sid) > 100:
            return None
        if self._redis is not None:
            raw = await self._redis.get(self._key(sid))
        else:
            item = self._mem.get(self._key(sid))
            raw = item[1] if item and item[0] > time.time() else None
        return json.loads(raw) if raw else None

    async def delete(self, sid: str | None) -> None:
        if not sid:
            return
        if self._redis is not None:
            await self._redis.delete(self._key(sid))
        else:
            self._mem.pop(self._key(sid), None)
