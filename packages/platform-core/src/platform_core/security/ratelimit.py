"""Distributed rate limiting (sliding-window log in Redis via an atomic Lua script)."""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any, Protocol

from platform_core.errors import RateLimited

_SLIDING_WINDOW_LUA = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = ARGV[4]
redis.call('ZREMRANGEBYSCORE', key, 0, now - window)
local count = redis.call('ZCARD', key)
if count >= limit then
  local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
  local retry = window
  if oldest[2] then retry = math.ceil((tonumber(oldest[2]) + window - now) / 1000) end
  return {0, count, retry}
end
redis.call('ZADD', key, now, member)
redis.call('PEXPIRE', key, window)
return {1, count + 1, 0}
"""


@dataclass(frozen=True)
class Limit:
    requests: int
    window_seconds: int


class RateLimiter(Protocol):
    async def hit(self, key: str, limit: Limit) -> tuple[bool, int]: ...


class RedisRateLimiter:
    def __init__(self, redis: Any, prefix: str) -> None:
        self._redis = redis
        self._prefix = prefix
        self._script = redis.register_script(_SLIDING_WINDOW_LUA)
        self._seq = 0

    async def hit(self, key: str, limit: Limit) -> tuple[bool, int]:
        now_ms = int(time.time() * 1000)
        self._seq += 1
        allowed, _count, retry = await self._script(
            keys=[f"{self._prefix}:rl:{key}"],
            args=[now_ms, limit.window_seconds * 1000, limit.requests, f"{now_ms}-{self._seq}"],
        )
        return bool(allowed), int(retry)


class InMemoryRateLimiter:
    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    async def hit(self, key: str, limit: Limit) -> tuple[bool, int]:
        now = time.monotonic()
        q = self._hits[key]
        while q and q[0] <= now - limit.window_seconds:
            q.popleft()
        if len(q) >= limit.requests:
            return False, max(1, int(q[0] + limit.window_seconds - now))
        q.append(now)
        return True, 0


async def enforce(limiter: RateLimiter, key: str, limit: Limit) -> None:
    allowed, retry = await limiter.hit(key, limit)
    if not allowed:
        raise RateLimited(retry_after=max(1, retry))
