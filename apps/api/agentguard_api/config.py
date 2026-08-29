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
    secret_key: str = Field(
        default="dev-only-insecure-change-me-0000000000000000",
        alias="AGENTGUARD_SECRET_KEY",
    )

    # --- datastores ---
    database_url: str = Field(
        default="postgresql+asyncpg://agentguard:agentguard@localhost:5442/agentguard",
        alias="DATABASE_URL",
    )
    redis_url: str = Field(default="redis://localhost:6389/0", alias="REDIS_URL")
    kafka_bootstrap_servers: str = Field(default="localhost:19092", alias="KAFKA_BOOTSTRAP_SERVERS")
    clickhouse_host: str = Field(default="localhost", alias="CLICKHOUSE_HOST")
    clickhouse_port: int = Field(default=8124, alias="CLICKHOUSE_PORT")
    qdrant_url: str = Field(default="http://localhost:6343", alias="QDRANT_URL")

    # --- object storage ---
    s3_endpoint_url: str = Field(default="http://localhost:9002", alias="S3_ENDPOINT_URL")
    s3_bucket: str = Field(default="agentguard-artifacts", alias="S3_BUCKET")

    # --- auth / sessions (PRD §51) ---
    jwt_algorithm: str = Field(default="HS256", alias="AGENTGUARD_JWT_ALG")
    access_token_ttl_seconds: int = Field(default=900, alias="AGENTGUARD_ACCESS_TTL")  # 15 min
    refresh_token_ttl_seconds: int = Field(
        default=60 * 60 * 24 * 30, alias="AGENTGUARD_REFRESH_TTL"
    )  # 30 days
    mfa_issuer: str = Field(default="AgentGuard", alias="AGENTGUARD_MFA_ISSUER")
    allow_open_registration: bool = Field(default=True, alias="AGENTGUARD_OPEN_REGISTRATION")

    # Comma-separated origins allowed to call the API from a browser (the web app).
    cors_allow_origins_raw: str = Field(
        default="http://localhost:3010,http://127.0.0.1:3010", alias="AGENTGUARD_CORS_ORIGINS"
    )

    @property
    def cors_allow_origins(self) -> list[str]:
        return [o.strip() for o in self.cors_allow_origins_raw.split(",") if o.strip()]

    # --- OAuth (PRD §9). Each provider is enabled only when its pair is set. ---
    oauth_redirect_base_url: str = Field(
        default="http://localhost:8010", alias="AGENTGUARD_OAUTH_REDIRECT_BASE"
    )
    # Where the browser lands after an SSO round-trip (the web app reads the
    # tokens from the URL fragment). PRD §9, §51.
    web_base_url: str = Field(default="http://localhost:3010", alias="AGENTGUARD_WEB_BASE_URL")
    google_client_id: str | None = Field(default=None, alias="GOOGLE_CLIENT_ID")
    google_client_secret: str | None = Field(default=None, alias="GOOGLE_CLIENT_SECRET")
    microsoft_client_id: str | None = Field(default=None, alias="MICROSOFT_CLIENT_ID")
    microsoft_client_secret: str | None = Field(default=None, alias="MICROSOFT_CLIENT_SECRET")
    microsoft_tenant: str = Field(default="common", alias="MICROSOFT_TENANT")

    @property
    def is_production(self) -> bool:
        return self.environment == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()
