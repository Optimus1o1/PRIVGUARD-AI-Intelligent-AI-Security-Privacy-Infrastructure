"""Threat detection and defense models for PRIVGUARD SDK."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from privguard_sdk.types import SourceType, TrustLevel


class InspectContentRequest(BaseModel):
    """Request payload to scan content for prompt injection and untrusted directives."""

    text: str = Field(..., min_length=1, description="Raw input text to inspect")
    source_type: SourceType = Field(default=SourceType.USER_INPUT, description="Origin source type")


class InspectContentResponse(BaseModel):
    """Result of prompt injection and untrusted content analysis."""

    assessment: dict[str, Any] = Field(..., description="Threat assessment scores and indicators")
    trust_level: TrustLevel = Field(..., description="Assessed trust level ('UNTRUSTED', 'SEMI_TRUSTED', 'TRUSTED')")
    sanitized_content: str = Field(..., description="Content sanitized of dangerous prompt overrides")
    is_quarantined: bool = Field(..., description="Whether content is quarantined due to high injection confidence")


class ThreatEventResponse(BaseModel):
    """Audit record of a detected threat event."""

    id: str
    application_id: str
    task_id: str | None = None
    agent_id: str | None = None
    threat_type: str = Field(..., description="Threat taxonomy identifier (e.g. 'PROMPT_INJECTION', 'EXFILTRATION')")
    severity: str
    details: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
