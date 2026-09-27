"""Embedding providers. Knowledge text is company-approved content, never customer data."""

from __future__ import annotations

import hashlib
import math
import re
from typing import Protocol

import httpx

from platform_core.db.models import EMBEDDING_DIMENSIONS
from platform_core.errors import UpstreamUnavailable

_TOKEN = re.compile(r"[a-z0-9]+")
_STOPWORDS = frozenset(
    "a an and are as at be but by can do does for from have how i if in is it me my of on or our "
    "please so that the their there this to us we what when where which who why will with you "
    "your yours am was were been being has had did any some tell about".split())


class Embedder(Protocol):
    model_name: str

    async def embed(self, texts: list[str]) -> list[list[float]]: ...


class HashingEmbedder:
    """Deterministic feature-hashing embedder (unigrams + bigrams), L2-normalized.

    Used when no embedding API is configured; gives keyword-level semantic recall that is
    good enough for local development and fully reproducible tests."""

    model_name = f"local-hash-{EMBEDDING_DIMENSIONS}"

    async def embed(self, texts: list[str]) -> list[list[float]]:
        return [self._one(t) for t in texts]

    @staticmethod
    def _one(text: str) -> list[float]:
        vec = [0.0] * EMBEDDING_DIMENSIONS
        tokens = [t for t in _TOKEN.findall(text.lower()) if t not in _STOPWORDS]
        feats = tokens + [f"{a}_{b}" for a, b in zip(tokens, tokens[1:], strict=False)]
        for f in feats:
            h = hashlib.blake2b(f.encode(), digest_size=8).digest()
            idx = int.from_bytes(h[:4], "big") % EMBEDDING_DIMENSIONS
            vec[idx] += 1.0 if h[4] & 1 else -1.0
        norm = math.sqrt(sum(v * v for v in vec)) or 1.0
        return [v / norm for v in vec]


class OpenAIEmbedder:
    def __init__(self, api_key: str, model: str, base_url: str) -> None:
        self.model_name = model
        self._client = httpx.AsyncClient(base_url=base_url, timeout=30,
                                         headers={"Authorization": f"Bearer {api_key}"})

    async def embed(self, texts: list[str]) -> list[list[float]]:
        out: list[list[float]] = []
        for i in range(0, len(texts), 64):
            batch = texts[i:i + 64]
            resp = await self._client.post("/embeddings", json={
                "model": self.model_name, "input": batch, "dimensions": EMBEDDING_DIMENSIONS})
            if resp.status_code != 200:
                raise UpstreamUnavailable("embedding provider error")
            data = sorted(resp.json()["data"], key=lambda d: d["index"])
            out.extend(d["embedding"] for d in data)
        return out


def chunk_text(text: str, size: int = 900, overlap: int = 150) -> list[str]:
    """Paragraph-aware chunking with character overlap."""
    paragraphs = [p.strip() for p in re.split(r"\n\s*\n", text) if p.strip()]
    chunks: list[str] = []
    current = ""
    for para in paragraphs:
        while len(para) > size:
            head, para = para[:size], para[size - overlap:]
            if current:
                chunks.append(current)
                current = ""
            chunks.append(head)
        if len(current) + len(para) + 2 <= size:
            current = f"{current}\n\n{para}" if current else para
        else:
            if current:
                chunks.append(current)
            tail = current[-overlap:] if current else ""
            current = f"{tail}\n\n{para}".strip() if tail else para
    if current:
        chunks.append(current)
    return chunks or [text[:size]]
