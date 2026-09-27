"""Realtime fan-out to dashboards via Redis pub/sub (consumed by the admin gateway's SSE)."""

from __future__ import annotations

import json
import logging
from typing import Any, Literal
from uuid import UUID

log = logging.getLogger(__name__)

Stream = Literal["samiir", "fatma"]


def channel(tenant_id: UUID, stream: Stream) -> str:
    return f"rt:{stream}:{tenant_id}"


class RealtimePublisher:
    def __init__(self, redis: Any | None) -> None:
        self._redis = redis

    async def publish(self, tenant_id: UUID, stream: Stream, event: str,
                      data: dict[str, Any]) -> None:
        if self._redis is None:
            return
        try:
            await self._redis.publish(channel(tenant_id, stream),
                                      json.dumps({"event": event, "data": data}, default=str))
        except Exception:  # realtime is best-effort; never fail the business operation
            log.warning("realtime publish failed", exc_info=True)
