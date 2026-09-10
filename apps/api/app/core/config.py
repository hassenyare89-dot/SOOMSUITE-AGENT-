from functools import lru_cache

from pydantic import AnyHttpUrl, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    environment: str = "development"
    database_url: str = "postgresql+asyncpg://platform:change-me@localhost:5432/platform"
    redis_url: str = "redis://localhost:6379/0"
    jwt_issuer: str = "https://identity.example.com/"
    jwt_audience: str = "samiir-fatma-api"
    jwt_jwks_url: AnyHttpUrl = "https://identity.example.com/.well-known/jwks.json"
    allowed_origins: str = "http://localhost:3000"
    meta_app_secret: str = ""
    meta_verify_token: str = ""
    max_request_bytes: int = Field(1_048_576, ge=1024)


@lru_cache
def get_settings() -> Settings:
    return Settings()
