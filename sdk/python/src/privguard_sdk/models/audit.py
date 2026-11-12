"""Audit and monitoring models for PRIVGUARD SDK."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class AuditEventResponse(BaseModel):
    """Tamper-evident, zero-content security audit event."""

    id: str
    request_id: str
    app_id: str | None = None
    event_type: str = Field(
        ..., description="Classification of security event (e.g. 'SECRET_BLOCKED', 'APPROVAL_GRANTED')"
    )
    data_category: str | None = None
    action_taken: str = Field(..., description="Action taken ('ALLOW', 'REDACT', 'HOLD', 'BLOCK')")
    risk_level: str
    entity_counts: dict[str, Any] = Field(default_factory=dict, description="Metadata counts of scrubbed entities")
    content_fingerprint: str | None = Field(None, description="SHA-256 digest of input without raw text")
    status: str
    timestamp: datetime
