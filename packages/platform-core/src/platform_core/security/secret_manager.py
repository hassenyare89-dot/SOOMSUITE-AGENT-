"""Secret-manager abstraction. Integration records store only a *reference* (``secret_ref``).

Supported reference schemes:
* ``env://NAME``           — environment variable (development only)
* ``file:///run/secrets/x`` — mounted secret file (Kubernetes/Docker secrets, CSI driver)
* ``vault://mount/path#field`` — HashiCorp Vault KV v2 (token from VAULT_TOKEN / agent sink)
* ``aws-sm://secret-id#field`` — AWS Secrets Manager (requires boto3 in the image)
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path
from typing import Protocol
from urllib.parse import urlsplit

import httpx

from platform_core.errors import PlatformError


def _read_file(path: Path) -> str | None:
    return path.read_text().strip() if path.is_file() else None


class SecretNotFound(PlatformError):
    status_code = 500
    code = "secret_unavailable"
    public_message = "A required credential is not configured."


class SecretManager(Protocol):
    async def get(self, ref: str) -> str: ...


class DefaultSecretManager:
    """Resolves references by scheme with a short in-memory TTL cache."""

    def __init__(self, *, allow_env: bool, vault_addr: str | None = None,
                 vault_token_path: str | None = None, cache_ttl: int = 300) -> None:
        self._allow_env = allow_env
        self._vault_addr = vault_addr
        self._vault_token_path = vault_token_path
        self._cache: dict[str, tuple[float, str]] = {}
        self._ttl = cache_ttl

    async def get(self, ref: str) -> str:
        hit = self._cache.get(ref)
        if hit and hit[0] > time.monotonic():
            return hit[1]
        value = await self._resolve(ref)
        self._cache[ref] = (time.monotonic() + self._ttl, value)
        return value

    def invalidate(self, ref: str | None = None) -> None:
        if ref is None:
            self._cache.clear()
        else:
            self._cache.pop(ref, None)

    async def _resolve(self, ref: str) -> str:
        parts = urlsplit(ref)
        field = parts.fragment or None
        match parts.scheme:
            case "env":
                if not self._allow_env:
                    raise SecretNotFound("env secrets are disabled in this environment")
                value = os.environ.get(parts.netloc or parts.path.lstrip("/"))
            case "file":
                value = await asyncio.to_thread(_read_file, Path(parts.path))
            case "vault":
                value = await self._vault(parts.netloc + parts.path)
            case "aws-sm":
                value = await asyncio.to_thread(self._aws, parts.netloc + parts.path)
            case _:
                raise SecretNotFound("unsupported secret reference scheme")
        if value is None or value == "":
            raise SecretNotFound()
        if field:
            try:
                value = str(json.loads(value)[field])
            except (ValueError, KeyError) as exc:
                raise SecretNotFound() from exc
        return value

    async def _vault(self, path: str) -> str | None:
        if not self._vault_addr or not self._vault_token_path:
            raise SecretNotFound("vault is not configured")
        token = await asyncio.to_thread(_read_file, Path(self._vault_token_path))
        mount, _, key = path.partition("/")
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(f"{self._vault_addr}/v1/{mount}/data/{key}",
                                    headers={"X-Vault-Token": token})
        if resp.status_code != 200:
            return None
        return json.dumps(resp.json()["data"]["data"])

    @staticmethod
    def _aws(secret_id: str) -> str | None:
        try:
            import boto3  # type: ignore[import-not-found]
        except ImportError as exc:
            raise SecretNotFound("boto3 not installed") from exc
        resp = boto3.client("secretsmanager").get_secret_value(SecretId=secret_id)
        return resp.get("SecretString")
