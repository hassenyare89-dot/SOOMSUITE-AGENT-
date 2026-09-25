from __future__ import annotations

from fastapi import FastAPI

from knowledge_service.api import router
from knowledge_service.config import Settings
from knowledge_service.embeddings import HashingEmbedder, OpenAIEmbedder
from knowledge_service.service import KnowledgeService
from platform_core.app import ServiceRuntime, build_runtime, create_app


def create(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()

    async def startup(rt: ServiceRuntime) -> None:
        if "knowledge" in rt.extras:
            return
        embedder = (OpenAIEmbedder(settings.openai_api_key.get_secret_value(),
                                   settings.embedding_model, settings.openai_base_url)
                    if settings.openai_api_key else HashingEmbedder())
        rt.extras["knowledge"] = KnowledgeService(
            embedder, min_relevance=settings.min_relevance, chunk_size=settings.chunk_size,
            chunk_overlap=settings.chunk_overlap,
            require_distinct_approver=settings.require_distinct_approver)

    return create_app(settings=settings, runtime_factory=lambda: build_runtime(settings, {}),
                      routers=[router], on_startup=startup, title="SAMIIR Knowledge Service")
