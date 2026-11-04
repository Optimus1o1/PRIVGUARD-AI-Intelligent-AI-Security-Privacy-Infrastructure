"""Core configuration settings for PRIVGUARD AI."""

from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings and environment configuration."""

    PROJECT_NAME: str = "PRIVGUARD AI"
    VERSION: str = "0.1.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = False
    HOST: str = "127.0.0.1"
    PORT: int = 8000

    # Security & Execution Boundaries
    PRIVGUARD_MASTER_KEY: str = "change-me-in-production-min-32-chars-long-secret"
    FAIL_CLOSED_MODE: bool = True
    MAX_REQUEST_SIZE_BYTES: int = 10 * 1024 * 1024  # 10 MB

    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./privguard.db"

    # Upstream LLM Proxy
    UPSTREAM_LLM_BASE_URL: str = "https://api.openai.com/v1"
    UPSTREAM_LLM_API_KEY: Optional[str] = None
    UPSTREAM_TIMEOUT_SECONDS: float = 60.0

    # Privacy Engine Defaults
    DEFAULT_POLICY_ACTION_PUBLIC: str = "ALLOW"
    DEFAULT_POLICY_ACTION_INTERNAL: str = "ALLOW"
    DEFAULT_POLICY_ACTION_PERSONAL: str = "REDACT"
    DEFAULT_POLICY_ACTION_CONFIDENTIAL: str = "REQUIRE_APPROVAL"
    DEFAULT_POLICY_ACTION_CRITICAL: str = "BLOCK"

    # Audit & Monitoring
    AUDIT_CONTENT_STORAGE_ENABLED: bool = False  # NEVER store prompt/response text by default
    AUDIT_RETENTION_DAYS: int = 90

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()

