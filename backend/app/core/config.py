"""Core configuration settings for PRIVGUARD AI."""

import os
from typing import Any, List, Optional
from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _read_secret_file(file_path: Optional[str]) -> Optional[str]:
    """Reads a secret string from a file if the path exists."""
    if file_path and os.path.isfile(file_path):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if content:
                    return content
        except Exception:
            pass
    return None


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
    PRIVGUARD_MASTER_KEY_FILE: Optional[str] = None
    FAIL_CLOSED_MODE: bool = True
    MAX_REQUEST_SIZE_BYTES: int = 10 * 1024 * 1024  # 10 MB

    # CORS Whitelist (Defaults to local Next.js frontend)
    CORS_ALLOWED_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./privguard.db"
    DATABASE_PASSWORD: Optional[str] = None
    DATABASE_PASSWORD_FILE: Optional[str] = None
    MIGRATION_PASSWORD_FILE: Optional[str] = None

    # Redis
    REDIS_URL: Optional[str] = None
    REDIS_PASSWORD: Optional[str] = None
    REDIS_PASSWORD_FILE: Optional[str] = None

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

    # Key Management Service (KMS) & Cryptography (Stage 10.5)
    KMS_PROVIDER: str = "local"
    KMS_KEY_ID: Optional[str] = None
    KMS_REGION: str = "us-east-1"
    KMS_ENDPOINT: Optional[str] = None
    APPROVAL_HMAC_KEY: Optional[str] = None
    APPROVAL_HMAC_KEY_FILE: Optional[str] = None

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @model_validator(mode="before")
    @classmethod
    def load_secret_files(cls, data: Any) -> Any:
        """Populates credential fields from secret file paths if provided."""
        if not isinstance(data, dict):
            return data

        # Check for master key file
        master_key_file = data.get("PRIVGUARD_MASTER_KEY_FILE") or os.getenv("PRIVGUARD_MASTER_KEY_FILE")
        secret_content = _read_secret_file(master_key_file)
        if secret_content:
            data["PRIVGUARD_MASTER_KEY"] = secret_content

        # Check for database password file
        db_pw_file = data.get("DATABASE_PASSWORD_FILE") or os.getenv("DATABASE_PASSWORD_FILE")
        db_pw = _read_secret_file(db_pw_file)
        if db_pw:
            data["DATABASE_PASSWORD"] = db_pw

        # Check for redis password file
        redis_pw_file = data.get("REDIS_PASSWORD_FILE") or os.getenv("REDIS_PASSWORD_FILE")
        redis_pw = _read_secret_file(redis_pw_file)
        if redis_pw:
            data["REDIS_PASSWORD"] = redis_pw

        # Check for approval HMAC key file
        hmac_key_file = data.get("APPROVAL_HMAC_KEY_FILE") or os.getenv("APPROVAL_HMAC_KEY_FILE")
        hmac_pw = _read_secret_file(hmac_key_file)
        if hmac_pw:
            data["APPROVAL_HMAC_KEY"] = hmac_pw

        return data

    @model_validator(mode="after")
    def validate_production_invariants(self) -> "Settings":
        """Enforces fail-closed security invariants when running in production."""
        is_production = self.ENVIRONMENT.lower() in ("production", "prod")

        if is_production:
            if self.DEBUG:
                raise ValueError("Security violation: DEBUG mode must be disabled in production.")

            if (
                self.PRIVGUARD_MASTER_KEY == "change-me-in-production-min-32-chars-long-secret"
                or len(self.PRIVGUARD_MASTER_KEY.strip()) < 32
            ):
                raise ValueError(
                    "Security violation: Production PRIVGUARD_MASTER_KEY must be a cryptographically "
                    "secure key of at least 32 characters, not the default placeholder."
                )

            if "*" in self.CORS_ALLOWED_ORIGINS:
                raise ValueError(
                    "Security violation: CORS wildcard '*' origin is strictly prohibited in production."
                )

            if self.KMS_PROVIDER.lower() in ("local", "dev", "development"):
                raise ValueError(
                    "Security violation: Local KMS provider is strictly prohibited in production. "
                    "A production KMS (AWS KMS, GCP KMS, Azure Key Vault, or Vault Transit) must be configured."
                )

            if not self.KMS_KEY_ID or not self.KMS_KEY_ID.strip():
                raise ValueError(
                    "Security violation: KMS_KEY_ID must be configured with a valid KMS key reference in production."
                )

        return self


settings = Settings()
