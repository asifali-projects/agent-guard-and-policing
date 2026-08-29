"""Runtime configuration, loaded from environment / `.env`."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="",
        env_file=(".env", "../../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- core ---
    environment: Literal["development", "staging", "production", "test"] = Field(
        default="development", alias="AGENTGUARD_ENV"
    )
    log_level: str = Field(default="INFO", alias="AGENTGUARD_LOG_LEVEL")
    secret_key: str = Field(default="dev-only-insecure-change-me", alias="AGENTGUARD_SECRET_KEY")

    # --- datastores ---
    database_url: str = Field(
        default="postgresql+asyncpg://agentguard:agentguard@localhost:5432/agentguard",
        alias="DATABASE_URL",
    )
    redis_url: str = Field(default="redis://localhost:6379/0", alias="REDIS_URL")
    kafka_bootstrap_servers: str = Field(
        default="localhost:19092", alias="KAFKA_BOOTSTRAP_SERVERS"
    )
    clickhouse_host: str = Field(default="localhost", alias="CLICKHOUSE_HOST")
    clickhouse_port: int = Field(default=8123, alias="CLICKHOUSE_PORT")
    qdrant_url: str = Field(default="http://localhost:6333", alias="QDRANT_URL")

    # --- object storage ---
    s3_endpoint_url: str = Field(default="http://localhost:9000", alias="S3_ENDPOINT_URL")
    s3_bucket: str = Field(default="agentguard-artifacts", alias="S3_BUCKET")

    @property
    def is_production(self) -> bool:
        return self.environment == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()
