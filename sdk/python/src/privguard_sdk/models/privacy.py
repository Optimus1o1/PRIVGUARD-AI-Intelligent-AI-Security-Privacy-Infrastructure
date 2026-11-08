"""Privacy inspection and redaction models for PRIVGUARD SDK."""

from typing import Any

from pydantic import BaseModel, Field


class InspectRequest(BaseModel):
    """Payload to inspect for sensitive information (secrets and PII)."""

    text: str = Field(..., min_length=1, description="Raw input text to inspect")
    request_id: str | None = Field(None, description="Optional caller correlation ID")


class InspectResponse(BaseModel):
    """Inspection result metadata."""

    category: str = Field(..., description="Detected sensitivity category (e.g. 'SECRET', 'PII', 'SAFE')")
    risk_level: str = Field(..., description="Assessed risk level ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')")
    action: str = Field(..., description="Action taken ('ALLOW', 'REDACT', 'HOLD', 'BLOCK')")
    is_blocked: bool = Field(..., description="Whether the payload was fail-closed blocked")
    blocking_reason: str | None = Field(None, description="Detailed explanation if blocked")
    detected_secrets: list[dict[str, Any]] = Field(default_factory=list)
    detected_pii: list[dict[str, Any]] = Field(default_factory=list)
    entity_counts: dict[str, int] = Field(default_factory=dict)
    content_fingerprint: str = Field(..., description="SHA-256 fingerprint of the input text")


class RedactRequest(BaseModel):
    """Payload to sanitize via reversible PII token substitution."""

    text: str = Field(..., min_length=1, description="Raw text containing PII")
    reversible: bool = Field(True, description="Whether to generate format-preserving substitution tokens")


class RedactResponse(BaseModel):
    """Sanitized payload and token mapping."""

    sanitized_text: str = Field(..., description="Text with PII replaced by tokens (e.g. <EMAIL_1>)")
    mapping: dict[str, str] = Field(default_factory=dict, description="Reversible token to plaintext mapping")
    entity_counts: dict[str, int] = Field(default_factory=dict)
