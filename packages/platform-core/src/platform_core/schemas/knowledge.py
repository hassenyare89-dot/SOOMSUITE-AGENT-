from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from uuid import UUID

from pydantic import BaseModel, Field

from platform_core.schemas.common import StrictModel
from platform_core.schemas.enums import KnowledgeCategory


class SearchRequest(StrictModel):
    query: str = Field(min_length=2, max_length=500)
    categories: list[KnowledgeCategory] | None = Field(default=None, max_length=10)
    limit: int = Field(5, ge=1, le=10)


class RetrievedChunk(BaseModel):
    chunk_id: UUID
    document_id: UUID
    title: str
    category: str
    version: int
    content: str
    score: float


class SearchResponse(BaseModel):
    results: list[RetrievedChunk]
    sufficient: bool


class PriceItem(StrictModel):
    service: str = Field(min_length=1, max_length=200)
    price: Decimal | None = Field(default=None, ge=0)
    price_from: Decimal | None = Field(default=None, ge=0)
    price_to: Decimal | None = Field(default=None, ge=0)
    unit: str = Field("one-time", max_length=60)
    notes: str = Field("", max_length=500)


class PricingData(StrictModel):
    currency: str = Field(pattern="^[A-Z]{3}$")
    items: list[PriceItem] = Field(min_length=1, max_length=200)
    valid_until: datetime | None = None


class PricingAnswer(BaseModel):
    currency: str
    items: list[PriceItem]
    document_id: UUID
    version: int
    effective_date: datetime | None
