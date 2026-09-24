"""Authenticated service-to-service HTTP client."""

from __future__ import annotations

import asyncio
import ssl
from typing import Any
from uuid import UUID

import httpx

from platform_core.errors import (
    Conflict,
    Forbidden,
    NotFound,
    PlatformError,
    RateLimited,
    Unauthenticated,
    UpstreamUnavailable,
    ValidationFailed,
)
from platform_core.security.principal import Principal
from platform_core.security.service_auth import RequestContext, ServiceIdentity

SERVICE_TOKEN_HEADER = "X-Service-Token"  # noqa: S105 - header name
REQUEST_ID_HEADER = "X-Request-ID"

_STATUS_ERRORS: dict[int, type[PlatformError]] = {
    401: Unauthenticated, 403: Forbidden, 404: NotFound, 409: Conflict, 422: ValidationFailed,
}


def build_ssl_context(cert: str | None, key: str | None, ca: str | None) -> ssl.SSLContext | bool:
    if not (cert and key):
        return True
    ctx = ssl.create_default_context(cafile=ca)
    ctx.load_cert_chain(cert, key)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    return ctx


class ServiceClient:
    """Calls one downstream service. Every request carries a fresh audience-bound token."""

    def __init__(self, audience: str, base_url: str, identity: ServiceIdentity, *,
                 timeout: float = 10.0, verify: ssl.SSLContext | bool = True,
                 transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.audience = audience
        self._identity = identity
        self._client = httpx.AsyncClient(
            base_url=base_url, timeout=httpx.Timeout(timeout, connect=3.0), verify=verify,
            transport=transport, follow_redirects=False,
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    def _headers(self, principal: Principal, request_id: str, source_ip: str | None,
                 agent_run_id: UUID | None, extra: dict[str, str] | None) -> dict[str, str]:
        token = self._identity.mint(self.audience, principal=principal, request_id=request_id,
                                    source_ip=source_ip, agent_run_id=agent_run_id)
        headers = {SERVICE_TOKEN_HEADER: token, REQUEST_ID_HEADER: request_id}
        if extra:
            headers.update(extra)
        return headers

    async def request(
        self,
        method: str,
        path: str,
        *,
        ctx: RequestContext | None = None,
        principal: Principal | None = None,
        request_id: str | None = None,
        json: Any = None,
        params: dict[str, Any] | None = None,
        content: bytes | None = None,
        headers: dict[str, str] | None = None,
        agent_run_id: UUID | None = None,
        retries: int | None = None,
        raw: bool = False,
    ) -> Any:
        if ctx is not None:
            principal = principal or ctx.principal
            request_id = request_id or ctx.request_id
            agent_run_id = agent_run_id or ctx.agent_run_id
        if principal is None or request_id is None:
            raise ValueError("principal and request_id are required")
        idempotent = method.upper() in {"GET", "HEAD", "PUT", "DELETE"} or (
            headers is not None and "Idempotency-Key" in headers)
        attempts = (retries if retries is not None else (2 if idempotent else 0)) + 1
        last_exc: Exception | None = None
        for attempt in range(attempts):
            try:
                resp = await self._client.request(
                    method, path, json=json, params=params, content=content,
                    headers=self._headers(principal, request_id,
                                          ctx.source_ip if ctx else None, agent_run_id, headers),
                )
            except httpx.TransportError as exc:
                last_exc = exc
                await asyncio.sleep(0.2 * (2**attempt))
                continue
            if resp.status_code >= 500 and attempt + 1 < attempts:
                await asyncio.sleep(0.2 * (2**attempt))
                continue
            return resp if raw else self._handle(resp)
        raise UpstreamUnavailable(f"{self.audience} unreachable") from last_exc

    def _handle(self, resp: httpx.Response) -> Any:
        if resp.status_code == 204:
            return None
        if resp.status_code < 400:
            return resp.json() if resp.content else None
        detail: dict[str, Any] = {}
        try:
            detail = resp.json().get("error", {})
        except ValueError:
            pass
        if resp.status_code == 429:
            raise RateLimited(int(resp.headers.get("Retry-After", "30")))
        err = _STATUS_ERRORS.get(resp.status_code)
        if err is not None:
            raise err(detail.get("message"), details=detail.get("details"))
        raise UpstreamUnavailable(f"{self.audience} returned {resp.status_code}")

    async def get(self, path: str, **kw: Any) -> Any:
        return await self.request("GET", path, **kw)

    async def post(self, path: str, **kw: Any) -> Any:
        return await self.request("POST", path, **kw)

    async def patch(self, path: str, **kw: Any) -> Any:
        return await self.request("PATCH", path, **kw)

    async def delete(self, path: str, **kw: Any) -> Any:
        return await self.request("DELETE", path, **kw)
