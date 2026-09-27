"""Structured JSON logging with mandatory redaction."""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime

from platform_core.observability import current_trace_id
from platform_core.security.redaction import redact, redact_text


class JsonFormatter(logging.Formatter):
    def __init__(self, service: str) -> None:
        super().__init__()
        self.service = service

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "service": self.service,
            "logger": record.name,
            "msg": redact_text(record.getMessage()),
        }
        if trace_id := current_trace_id():
            payload["trace_id"] = trace_id
        extra = getattr(record, "ctx", None)
        if isinstance(extra, dict):
            payload["ctx"] = redact(extra)
        if record.exc_info:
            payload["exc"] = redact_text(self.formatException(record.exc_info))[-4000:]
        return json.dumps(payload, default=str)


def configure_logging(service: str, level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter(service))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
    for noisy in ("httpx", "httpcore", "uvicorn.access"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
