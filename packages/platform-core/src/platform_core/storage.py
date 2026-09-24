"""Object storage for raw (redacted) event batches and quarantined samples.

``FilesystemObjectStore`` backs local development (a dedicated volume). Production uses an
S3-compatible bucket with SSE-KMS, object lock and no public access; the interface is the same.
Quarantined samples are additionally encrypted with AES-256-GCM so they are inert at rest.
"""

from __future__ import annotations

import asyncio
import gzip
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class ObjectStore(Protocol):
    async def put(self, key: str, data: bytes) -> str: ...

    async def get(self, ref: str) -> bytes: ...


class FilesystemObjectStore:
    def __init__(self, root: Path) -> None:
        self.root = root

    def _path(self, key: str) -> Path:
        path = (self.root / key).resolve()
        if not str(path).startswith(str(self.root.resolve())):
            raise ValueError("invalid object key")
        return path

    async def put(self, key: str, data: bytes) -> str:
        path = self._path(key)

        def _write() -> None:
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            tmp = path.with_suffix(".tmp")
            tmp.write_bytes(data)
            os.chmod(tmp, 0o600)
            tmp.replace(path)

        await asyncio.to_thread(_write)
        return f"fs://{key}"

    async def get(self, ref: str) -> bytes:
        return await asyncio.to_thread(self._path(ref.removeprefix("fs://")).read_bytes)


async def store_raw(store: ObjectStore, tenant_id: uuid.UUID, source: str, data: bytes) -> str:
    now = datetime.now(UTC)
    key = f"raw/{tenant_id}/{source}/{now:%Y/%m/%d}/{uuid.uuid4()}.json.gz"
    return await store.put(key, gzip.compress(data))


class Quarantine:
    def __init__(self, store: ObjectStore, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("quarantine key must be 256 bits")
        self.store = store
        self._aead = AESGCM(key)

    async def put(self, tenant_id: uuid.UUID, sample_id: uuid.UUID, data: bytes) -> str:
        nonce = os.urandom(12)
        blob = nonce + self._aead.encrypt(nonce, data, sample_id.bytes)
        return await self.store.put(f"quarantine/{tenant_id}/{sample_id}.bin", blob)

    async def get(self, ref: str, sample_id: uuid.UUID) -> bytes:
        blob = await self.store.get(ref)
        return self._aead.decrypt(blob[:12], blob[12:], sample_id.bytes)
