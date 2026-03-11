"""
ACCC Backend Configuration
Phase 2.1 Update: Added JWT settings (G-07, G-16)
Reads all environment variables via pydantic BaseSettings.
Fails loudly if required vars are missing.
"""

import os
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    """Application settings read from environment variables."""

    # --- Required ---
    OPENAI_API_KEY: str = Field(..., description="OpenAI API key for chat + embeddings")   
    POSTGRES_PASSWORD: str = Field(..., description="PostgreSQL password")
    JWT_SECRET: str = Field(..., description="Secret key for JWT signing")


    # --- OpenAI Models ---
    OPENAI_PRIMARY_MODEL: str = Field(default="gpt-4.1")
    OPENAI_FAST_MODEL: str = Field(default="gpt-4.1")
    OPENAI_EMBEDDING_MODEL: str = Field(default="text-embedding-3-small")

    
    # --- PostgreSQL ---
    POSTGRES_USER: str = Field(default="accc")
    POSTGRES_DB: str = Field(default="accc_db")
    POSTGRES_HOST: str = Field(default="postgres")
    POSTGRES_PORT: int = Field(default=5432)

    # --- Redis ---
    REDIS_URL: str = Field(default="redis://redis:6379")

    # --- ChromaDB ---
    CHROMADB_HOST: str = Field(default="chromadb")
    CHROMADB_PORT: int = Field(default=8000)

    # --- AbuseIPDB (stub - graceful fallback if missing) ---
    ABUSEIPDB_API_KEY: str = Field(default="")

    # --- Log Generator ---
    LOG_GENERATOR_RATE: int = Field(default=30)
    GENERATOR_URL: str = Field(default="http://log_generator:8080")

    # --- Application ---
    ENVIRONMENT: str = Field(default="production")
    LOG_LEVEL: str = Field(default="INFO")
    ENABLE_AUDIO_ALERTS: bool = Field(default=True)

    # --- JWT Configuration (G-16) ---
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(
        default=15,
        description="Access token lifetime in minutes (short - limits exposure)"
    )
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = Field(
        default=7,
        description="Refresh token lifetime in days (long - analyst doesn't re-login daily)"
    )
    JWT_ALGORITHM: str = Field(default="HS256")

    @property
    def DATABASE_URL(self) -> str:
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    @property
    def CHROMADB_URL(self) -> str:
        return f"http://{self.CHROMADB_HOST}:{self.CHROMADB_PORT}"

    @property
    def is_development(self) -> bool:
        return self.ENVIRONMENT.lower() == "development"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True


# Singleton settings instance
settings = Settings()