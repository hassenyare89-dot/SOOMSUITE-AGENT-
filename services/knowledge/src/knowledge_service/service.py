"""Knowledge domain logic: drafting, versioning, approval, retrieval."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import func, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from knowledge_service.embeddings import Embedder, chunk_text
from platform_core.db.models import KnowledgeChunk, KnowledgeDocument
from platform_core.errors import Conflict, Forbidden, NotFound, ValidationFailed
from platform_core.schemas.common import StrictModel
from platform_core.schemas.enums import KnowledgeCategory, KnowledgeStatus, Visibility
from platform_core.schemas.knowledge import (
    PricingAnswer,
    PricingData,
    RetrievedChunk,
    SearchRequest,
    SearchResponse,
)
from platform_core.security.crypto import sha256_hex
from platform_core.security.untrusted import assess_injection, normalize_text


class DocumentIn(StrictModel):
    title: str = Field(min_length=3, max_length=300)
    content: str = Field(min_length=10, max_length=200_000)
    category: KnowledgeCategory
    source: str = Field(min_length=2, max_length=300)
    visibility: Visibility = Visibility.INTERNAL
    structured_data: dict[str, Any] | None = None
    effective_date: datetime | None = None
    review_date: datetime | None = None
    expiration_date: datetime | None = None


class DocumentPatch(StrictModel):
    title: str | None = Field(default=None, min_length=3, max_length=300)
    content: str | None = Field(default=None, min_length=10, max_length=200_000)
    source: str | None = Field(default=None, max_length=300)
    visibility: Visibility | None = None
    structured_data: dict[str, Any] | None = None
    effective_date: datetime | None = None
    review_date: datetime | None = None
    expiration_date: datetime | None = None


class DocumentOut(BaseModel):
    id: uuid.UUID
    lineage_id: uuid.UUID
    title: str
    content: str
    category: str
    source: str
    visibility: str
    version: int
    status: str
    structured_data: dict | None
    injection_flags: list
    created_by: uuid.UUID | None
    approved_by: uuid.UUID | None
    approved_at: datetime | None
    effective_date: datetime | None
    review_date: datetime | None
    expiration_date: datetime | None
    created_at: datetime
    updated_at: datetime


def _validate_structured(category: str, data: dict | None) -> dict | None:
    if category == KnowledgeCategory.PRICING:
        if data is None:
            raise ValidationFailed("pricing documents require structured pricing data")
        try:
            return PricingData.model_validate(data).model_dump(mode="json")
        except ValidationError as exc:
            raise ValidationFailed("invalid pricing data",
                                   details={"errors": exc.errors(include_input=False)[:10]}) from exc
    return data


def _dates_ok(eff: datetime | None, review: datetime | None, exp: datetime | None) -> None:
    if eff and exp and exp <= eff:
        raise ValidationFailed("expiration_date must be after effective_date")
    if review and exp and review > exp:
        raise ValidationFailed("review_date must not be after expiration_date")


class KnowledgeService:
    def __init__(self, embedder: Embedder, *, min_relevance: float, chunk_size: int,
                 chunk_overlap: int, require_distinct_approver: bool) -> None:
        self.embedder = embedder
        self.min_relevance = min_relevance
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap
        self.require_distinct_approver = require_distinct_approver

    # ------------------------------------------------------------------ authoring
    async def create(self, s: AsyncSession, tenant_id: uuid.UUID, body: DocumentIn,
                     author: uuid.UUID | None) -> KnowledgeDocument:
        _dates_ok(body.effective_date, body.review_date, body.expiration_date)
        content = normalize_text(body.content, max_len=200_000)
        doc = KnowledgeDocument(
            tenant_id=tenant_id, lineage_id=uuid.uuid4(), title=body.title, content=content,
            category=body.category.value, source=body.source, visibility=body.visibility.value,
            version=1, status=KnowledgeStatus.DRAFT.value,
            structured_data=_validate_structured(body.category, body.structured_data),
            content_hash=sha256_hex(content), injection_flags=list(assess_injection(content).signals),
            created_by=author, effective_date=body.effective_date, review_date=body.review_date,
            expiration_date=body.expiration_date,
        )
        s.add(doc)
        await s.flush()
        return doc

    async def get(self, s: AsyncSession, doc_id: uuid.UUID) -> KnowledgeDocument:
        doc = await s.get(KnowledgeDocument, doc_id)
        if doc is None or doc.deleted_at is not None:
            raise NotFound()
        return doc

    async def edit(self, s: AsyncSession, doc_id: uuid.UUID, patch: DocumentPatch,
                   author: uuid.UUID | None) -> KnowledgeDocument:
        doc = await self.get(s, doc_id)
        changes = patch.model_dump(exclude_unset=True)
        if doc.status in (KnowledgeStatus.APPROVED, KnowledgeStatus.ARCHIVED):
            # Approved content is immutable: edits create the next version as a new draft.
            latest = await s.scalar(select(func.max(KnowledgeDocument.version)).where(
                KnowledgeDocument.lineage_id == doc.lineage_id))
            doc = KnowledgeDocument(
                tenant_id=doc.tenant_id, lineage_id=doc.lineage_id, title=doc.title,
                content=doc.content, category=doc.category, source=doc.source,
                visibility=doc.visibility, version=(latest or doc.version) + 1,
                status=KnowledgeStatus.DRAFT.value, structured_data=doc.structured_data,
                content_hash=doc.content_hash, injection_flags=doc.injection_flags,
                created_by=author, effective_date=doc.effective_date,
                review_date=doc.review_date, expiration_date=doc.expiration_date)
            s.add(doc)
        elif doc.status == KnowledgeStatus.PENDING_APPROVAL:
            doc.status = KnowledgeStatus.DRAFT.value
        for key, value in changes.items():
            if key == "visibility" and value is not None:
                value = value.value if hasattr(value, "value") else value
            setattr(doc, key, value)
        if "content" in changes:
            doc.content = normalize_text(doc.content, max_len=200_000)
            doc.content_hash = sha256_hex(doc.content)
            doc.injection_flags = list(assess_injection(doc.content).signals)
        doc.structured_data = _validate_structured(doc.category, doc.structured_data)
        _dates_ok(doc.effective_date, doc.review_date, doc.expiration_date)
        await s.flush()
        return doc

    async def submit(self, s: AsyncSession, doc_id: uuid.UUID) -> KnowledgeDocument:
        doc = await self.get(s, doc_id)
        if doc.status != KnowledgeStatus.DRAFT:
            raise Conflict("only drafts can be submitted")
        doc.status = KnowledgeStatus.PENDING_APPROVAL.value
        return doc

    async def approve(self, s: AsyncSession, doc_id: uuid.UUID, approver: uuid.UUID,
                      acknowledge_flags: bool) -> KnowledgeDocument:
        doc = await self.get(s, doc_id)
        if doc.status != KnowledgeStatus.PENDING_APPROVAL:
            raise Conflict("document is not pending approval")
        if self.require_distinct_approver and doc.created_by == approver:
            raise Forbidden("the author cannot approve their own document")
        if doc.injection_flags and not acknowledge_flags:
            raise Conflict("document contains instruction-like content; review and acknowledge",
                           details={"flags": doc.injection_flags})
        chunks = chunk_text(doc.content, self.chunk_size, self.chunk_overlap)
        vectors = await self.embedder.embed([f"{doc.title}\n{c}" for c in chunks])
        await s.execute(update(KnowledgeDocument).where(
            KnowledgeDocument.lineage_id == doc.lineage_id,
            KnowledgeDocument.status == KnowledgeStatus.APPROVED.value,
        ).values(status=KnowledgeStatus.ARCHIVED.value))
        doc.status = KnowledgeStatus.APPROVED.value
        doc.approved_by = approver
        doc.approved_at = datetime.now(UTC)
        await s.execute(text("DELETE FROM knowledge_chunks WHERE document_id = :d"), {"d": doc.id})
        for i, (chunk, vec) in enumerate(zip(chunks, vectors, strict=True)):
            s.add(KnowledgeChunk(tenant_id=doc.tenant_id, document_id=doc.id, chunk_index=i,
                                 content=chunk, embedding=vec,
                                 embedding_model=self.embedder.model_name))
        await s.flush()
        return doc

    async def archive(self, s: AsyncSession, doc_id: uuid.UUID) -> KnowledgeDocument:
        doc = await self.get(s, doc_id)
        doc.status = KnowledgeStatus.ARCHIVED.value
        return doc

    async def list(self, s: AsyncSession, *, status: str | None, category: str | None,
                   q: str | None, limit: int, offset: int) -> tuple[list[KnowledgeDocument], int]:
        stmt = select(KnowledgeDocument).where(KnowledgeDocument.deleted_at.is_(None))
        if status:
            stmt = stmt.where(KnowledgeDocument.status == status)
        if category:
            stmt = stmt.where(KnowledgeDocument.category == category)
        if q:
            stmt = stmt.where(KnowledgeDocument.title.ilike(f"%{q.replace('%', '')}%"))
        total = await s.scalar(select(func.count()).select_from(stmt.subquery()))
        rows = (await s.scalars(stmt.order_by(KnowledgeDocument.updated_at.desc())
                                .limit(limit).offset(offset))).all()
        return list(rows), int(total or 0)

    async def versions(self, s: AsyncSession, doc_id: uuid.UUID) -> list[KnowledgeDocument]:
        doc = await self.get(s, doc_id)
        return list((await s.scalars(select(KnowledgeDocument).where(
            KnowledgeDocument.lineage_id == doc.lineage_id).order_by(
            KnowledgeDocument.version.desc()))).all())

    # ------------------------------------------------------------------- retrieval
    async def search(self, s: AsyncSession, req: SearchRequest) -> SearchResponse:
        """Only APPROVED + public + currently-effective knowledge is ever returned."""
        query = normalize_text(req.query, max_len=500)
        [qvec] = await self.embedder.embed([query])
        cats = [c.value for c in req.categories] if req.categories else None
        rows = (await s.execute(text("""
            SELECT c.id, c.document_id, d.title, d.category, d.version, c.content,
                   (1 - (c.embedding <=> CAST(:qvec AS vector))) AS vscore,
                   ts_rank(c.tsv, plainto_tsquery('simple', :q)) AS tscore
            FROM knowledge_chunks c
            JOIN knowledge_documents d ON d.id = c.document_id
            WHERE d.status = 'APPROVED' AND d.visibility = 'public' AND d.deleted_at IS NULL
              AND (d.effective_date IS NULL OR d.effective_date <= now())
              AND (d.expiration_date IS NULL OR d.expiration_date > now())
              AND c.embedding_model = :model
              AND (CAST(:cats AS text[]) IS NULL OR d.category = ANY(CAST(:cats AS text[])))
            ORDER BY (0.75 * (1 - (c.embedding <=> CAST(:qvec AS vector)))
                      + 0.25 * least(ts_rank(c.tsv, plainto_tsquery('simple', :q)) * 10, 1)) DESC
            LIMIT :k
        """), {"qvec": str(qvec), "q": query, "model": self.embedder.model_name, "cats": cats,
               "k": req.limit})).all()
        results = []
        for r in rows:
            score = 0.75 * float(r.vscore) + 0.25 * min(float(r.tscore) * 10, 1.0)
            if score >= self.min_relevance:
                results.append(RetrievedChunk(chunk_id=r.id, document_id=r.document_id,
                                              title=r.title, category=r.category,
                                              version=r.version, content=r.content,
                                              score=round(score, 4)))
        return SearchResponse(results=results, sufficient=bool(results))

    async def pricing(self, s: AsyncSession, service_query: str | None) -> list[PricingAnswer]:
        docs = (await s.scalars(select(KnowledgeDocument).where(
            KnowledgeDocument.status == KnowledgeStatus.APPROVED.value,
            KnowledgeDocument.visibility == Visibility.PUBLIC.value,
            KnowledgeDocument.category == KnowledgeCategory.PRICING.value,
            KnowledgeDocument.deleted_at.is_(None),
            (KnowledgeDocument.effective_date.is_(None))
            | (KnowledgeDocument.effective_date <= func.now()),
            (KnowledgeDocument.expiration_date.is_(None))
            | (KnowledgeDocument.expiration_date > func.now()),
        ))).all()
        answers = []
        needle = (service_query or "").lower().strip()
        for d in docs:
            data = PricingData.model_validate(d.structured_data)
            if data.valid_until and data.valid_until <= datetime.now(UTC):
                continue
            items = [i for i in data.items if not needle or needle in i.service.lower()
                     or any(w in i.service.lower() for w in needle.split() if len(w) > 3)]
            if items:
                answers.append(PricingAnswer(currency=data.currency, items=items,
                                             document_id=d.id, version=d.version,
                                             effective_date=d.effective_date))
        return answers
