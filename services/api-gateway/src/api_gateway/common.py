from __future__ import annotations

import hashlib
import hmac
import ipaddress
from typing import Any

from fastapi import Request
from fastapi.responses import Response

from platform_core.app import ServiceRuntime
from platform_core.errors import Forbidden

HOP_HEADERS = {"content-length", "transfer-encoding", "connection", "keep-alive", "server",
               "date", "x-service-token"}


def client_ip(request: Request, trusted: list[str]) -> str:
    """Only honour X-Forwarded-For when the direct peer is a trusted proxy."""
    peer = request.client.host if request.client else "0.0.0.0"  # noqa: S104
    try:
        peer_addr = ipaddress.ip_address(peer)
    except ValueError:
        return "0.0.0.0"  # noqa: S104
    if any(peer_addr in ipaddress.ip_network(c) for c in trusted):
        xff = request.headers.get("x-forwarded-for", "")
        for hop in reversed([h.strip() for h in xff.split(",") if h.strip()]):
            try:
                addr = ipaddress.ip_address(hop)
            except ValueError:
                break
            if not any(addr in ipaddress.ip_network(c) for c in trusted):
                return str(addr)
    return str(peer_addr)


def csrf_token(key: bytes, session_id: str) -> str:
    return hmac.new(key, f"csrf:{session_id}".encode(), hashlib.sha256).hexdigest()


def check_csrf(request: Request, key: bytes, session_id: str) -> None:
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    token = request.headers.get("x-csrf-token", "")
    if not hmac.compare_digest(token, csrf_token(key, session_id)):
        raise Forbidden("CSRF validation failed")


def check_origin(request: Request, allowed: list[str]) -> None:
    """Unsafe methods must come from an allowlisted browser origin (defence in depth)."""
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    origin = request.headers.get("origin") or request.headers.get("referer", "")
    if not any(origin == o or origin.startswith(o + "/") for o in allowed):
        raise Forbidden("origin not allowed")


def to_response(upstream: Any) -> Response:
    headers = {k: v for k, v in upstream.headers.items() if k.lower() not in HOP_HEADERS}
    return Response(content=upstream.content, status_code=upstream.status_code, headers=headers,
                    media_type=upstream.headers.get("content-type"))


def runtime(request: Request) -> ServiceRuntime:
    return request.app.state.runtime
