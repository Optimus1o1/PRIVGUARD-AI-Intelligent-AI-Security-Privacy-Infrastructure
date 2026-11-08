"""Personal AI Memory Vault models for PRIVGUARD SDK."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from privguard_sdk.types import MemoryCategory, ProposalStatus, RiskLevel


class ProposalCreateRequest(BaseModel):
    """Payload to stage a memory proposal for human consent."""

    proposed_key: str = Field(..., min_length=1, max_length=128)
    proposed_value: str = Field(..., min_length=1, max_length=10000)
    category: MemoryCategory = Field(default=MemoryCategory.USER_PREFERENCES)
    agent_id: str
    task_id: str
    ttl_seconds: int | None = Field(default=86400, ge=60, le=2592000)


class ProposalResponse(BaseModel):
    """Staged memory proposal details."""

    id: str
    app_id: str
    owner_id: str
    agent_id: str | None = None
    task_id: str | None = None
    proposed_key: str
    proposed_value: str
    category: str
    status: ProposalStatus
    threat_assessment: dict[str, Any] = Field(default_factory=dict)
    risk_level: RiskLevel
    created_at: datetime
    expires_at: datetime | None = None


class MemoryItemStoreRequest(BaseModel):
    """Direct memory storage payload (by user or application)."""

    key: str = Field(..., min_length=1, max_length=128)
    value: str = Field(..., min_length=1, max_length=10000)
    category: MemoryCategory = Field(default=MemoryCategory.USER_PREFERENCES)
    ttl_seconds: int | None = Field(None, ge=60, le=31536000)


class MemoryItemResponse(BaseModel):
    """Decrypted memory item returned to authorized caller."""

    key: str
    value: str
    category: str
    version: int
    created_at: datetime
    updated_at: datetime
    expires_at: datetime | None = None


class MemorySearchRequest(BaseModel):
    """Search request within caller's memory vault."""

    query: str = Field(..., min_length=1)
    category: MemoryCategory | None = None
    limit: int = Field(10, ge=1, le=100)


class MemorySearchResult(BaseModel):
    """Search results with match metrics."""

    items: list[MemoryItemResponse] = Field(default_factory=list)
    count: int = 0


class MemoryErasureRequest(BaseModel):
    """Request to irreversibly cryptographically erase memory DEKs."""

    key: str | None = Field(None, description="Specific memory key to erase (if None, purges all keys for user)")
    purge_all: bool = Field(False, description="Explicit confirmation flag for full vault purge")


class MemoryErasureResponse(BaseModel):
    """Result of cryptographic erasure."""

    status: str
    erased_count: int
    message: str
