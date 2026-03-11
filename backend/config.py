"""
config.py — Application settings via Pydantic BaseSettings.
Reads from environment variables / .env file.
Fails fast on startup if required vars are missing.
"""
from functools import lru_cache
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Required ──────────────────────────────────────────────────────────────
    openai_api_key: str
    postgres_password: str
    jwt_secret: str

    # ── Database ──────────────────────────────────────────────────────────────
    database_url: str = "postgresql+asyncpg://accc:accc_secret_password@postgres:5432/accc_db"
    postgres_user: str = "accc"
    postgres_db: str = "accc_db"

    # ── Redis ─────────────────────────────────────────────────────────────────
    redis_url: str = "redis://redis:6379"

    # ── ChromaDB ──────────────────────────────────────────────────────────────
    chromadb_host: str = "chromadb"
    chromadb_port: int = 8000

    # ── Auth ──────────────────────────────────────────────────────────────────
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7

    # ── Optional APIs ─────────────────────────────────────────────────────────
    abuseipdb_api_key: Optional[str] = None

    # ── App Behaviour ─────────────────────────────────────────────────────────
    environment: str = "production"
    log_level: str = "INFO"
    log_generator_rate: int = 30
    enable_audio_alerts: bool = True

    # ── OpenAI Models ─────────────────────────────────────────────────────────
    openai_model_primary: str = "gpt-4o"
    openai_model_fast: str = "gpt-4o-mini"
    openai_embedding_model: str = "text-embedding-3-small"

    # ── Derived helpers ───────────────────────────────────────────────────────
    @property
    def is_development(self) -> bool:
        return self.environment.lower() == "development"

    @property
    def cors_origins(self) -> list[str]:
        if self.is_development:
            return ["*"]
        return ["http://localhost:3000"]

    @property
    def chromadb_url(self) -> str:
        return f"http://{self.chromadb_host}:{self.chromadb_port}"


@lru_cache()
def get_settings() -> Settings:
    """Cached settings — validates all required fields on first call."""
    return Settings()
