"""Ingestion webhook authentication.

Preferred: ``X-Signature: t=<unix>,v1=<hex HMAC-SHA256(secret, "<t>." + body)>`` with a
timestamp tolerance and a replay cache on the signature. Some vendors cannot sign requests:
Cloudflare Logpush (custom header) and AWS Firehose (``X-Amz-Firehose-Access-Key``) use a
shared-secret header compared in constant time; those endpoints must additionally be
restricted to the vendor's egress ranges at the edge.
"""

from __future__ import annotations

import hashlib
import hmac
import time

from platform_core.errors import Unauthenticated
from platform_core.security.service_auth import ReplayCache

TOKEN_HEADER_SOURCES = {"cloudflare": "x-ingest-token", "aws_waf": "x-amz-firehose-access-key"}


def sign(secret: str, body: bytes, ts: int | None = None) -> str:
    ts = ts or int(time.time())
    mac = hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return f"t={ts},v1={mac}"


async def verify(kind: str, headers: dict[str, str], body: bytes, secret: str,
                 replay: ReplayCache, tolerance: int) -> None:
    if not secret:
        raise Unauthenticated("ingest source is not configured")
    signature = headers.get("x-signature")
    if signature:
        parts = dict(p.split("=", 1) for p in signature.split(",") if "=" in p)
        try:
            ts = int(parts["t"])
        except (KeyError, ValueError) as exc:
            raise Unauthenticated("malformed signature") from exc
        if abs(time.time() - ts) > tolerance:
            raise Unauthenticated("signature timestamp outside tolerance")
        expected = hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(parts.get("v1", ""), expected):
            raise Unauthenticated("invalid signature")
        if not await replay.first_use(f"ingest:{expected}", tolerance * 2):
            raise Unauthenticated("replayed delivery")
        return
    header = TOKEN_HEADER_SOURCES.get(kind)
    token = headers.get(header or "", "")
    if header and token and hmac.compare_digest(token, secret):
        return
    raise Unauthenticated("missing or invalid ingest credentials")
