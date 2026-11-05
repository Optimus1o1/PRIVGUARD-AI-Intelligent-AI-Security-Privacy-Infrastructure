"""Base classes and enums for Application Secret Management."""

from enum import Enum
from typing import NamedTuple, Optional


class SecretType(str, Enum):
    """Classification of application credentials and secrets."""
    DATABASE_CREDENTIAL = "DATABASE_CREDENTIAL"
    REDIS_CREDENTIAL = "REDIS_CREDENTIAL"
    LLM_API_KEY = "LLM_API_KEY"
    MCP_CREDENTIAL = "MCP_CREDENTIAL"
    OAUTH_SECRET = "OAUTH_SECRET"
    SIEM_TOKEN = "SIEM_TOKEN"


class SecretStatus(str, Enum):
    """Lifecycle states for operational credentials."""
    CREATED = "CREATED"
    ACTIVE = "ACTIVE"
    ROTATION_PENDING = "ROTATION_PENDING"
    ROTATING = "ROTATING"
    VERIFIED = "VERIFIED"
    REVOKED = "REVOKED"


class SecretMetadata(NamedTuple):
    """Metadata representation of an application secret (zero plaintext)."""
    id: str
    tenant_id: str
    name: str
    secret_type: SecretType
    version: int
    status: SecretStatus
    expires_at: Optional[str]
    created_at: str
    last_rotated_at: str
