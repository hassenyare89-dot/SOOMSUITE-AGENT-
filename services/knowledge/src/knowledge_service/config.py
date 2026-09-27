from pydantic import SecretStr

from platform_core.config import BaseServiceSettings


class Settings(BaseServiceSettings):
    service_name: str = "knowledge"
    # Optional: without a key a deterministic local embedder is used (development/testing).
    openai_api_key: SecretStr | None = None
    openai_base_url: str = "https://api.openai.com/v1"
    embedding_model: str = "text-embedding-3-small"
    min_relevance: float = 0.28
    chunk_size: int = 900
    chunk_overlap: int = 150
    require_distinct_approver: bool = True
