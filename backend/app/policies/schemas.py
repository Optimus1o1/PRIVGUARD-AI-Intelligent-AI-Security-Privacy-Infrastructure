"""Schemas for policy configuration and evaluation."""

from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class PolicyAction(str, Enum):
    """Enforceable actions."""
    ALLOW = "ALLOW"
    REDACT = "REDACT"
    BLOCK = "BLOCK"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class PolicyRuleConfig(BaseModel):
    """Configuration for an individual policy rule."""
    category: str
    action: PolicyAction
    risk_level: str
    description: Optional[str] = None
    is_enabled: bool = True


class PolicyEvaluationRequest(BaseModel):
    """Input payload to evaluate against active policies."""
    text: str
    detected_entities: List[str] = Field(default_factory=list)
    detected_secrets: List[str] = Field(default_factory=list)
    metadata: Dict[str, str] = Field(default_factory=dict)


class PolicyDecision(BaseModel):
    """Outcome of policy evaluation."""
    action: PolicyAction
    risk_level: str
    reason: str
    matched_rule: Optional[str] = None
    allow_execution: bool = True
