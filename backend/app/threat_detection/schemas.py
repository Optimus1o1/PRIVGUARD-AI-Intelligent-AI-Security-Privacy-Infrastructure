"""Pydantic schemas and enums for Threat Detection & Defense."""

from datetime import datetime, timezone
from enum import Enum
import hashlib
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class TrustLevel(str, Enum):
    """Trust classification levels for inbound data and context."""

    TRUSTED = "TRUSTED"
    UNTRUSTED = "UNTRUSTED"
    QUARANTINED = "QUARANTINED"


class SourceType(str, Enum):
    """Origin type of content evaluated by PRIVGUARD."""

    USER_INPUT = "USER_INPUT"
    SYSTEM_PROMPT = "SYSTEM_PROMPT"
    EXTERNAL_DOCUMENT = "EXTERNAL_DOCUMENT"
    WEB_SCRAPE = "WEB_SCRAPE"
    TOOL_OUTPUT = "TOOL_OUTPUT"
    RETRIEVED_CHUNK = "RETRIEVED_CHUNK"
    MEMORY_RECALL = "MEMORY_RECALL"


class ThreatType(str, Enum):
    """Recognized AI security and agent threats."""

    DIRECT_PROMPT_INJECTION = "DIRECT_PROMPT_INJECTION"
    INDIRECT_PROMPT_INJECTION = "INDIRECT_PROMPT_INJECTION"
    SYSTEM_PROMPT_EXTRACTION = "SYSTEM_PROMPT_EXTRACTION"
    JAILBREAK_ATTEMPT = "JAILBREAK_ATTEMPT"
    OBFUSCATED_PAYLOAD = "OBFUSCATED_PAYLOAD"
    MEMORY_POISONING = "MEMORY_POISONING"
    SUSPICIOUS_TOOL_SEQUENCE = "SUSPICIOUS_TOOL_SEQUENCE"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    CROSS_TENANT_ACCESS = "CROSS_TENANT_ACCESS"
    RUNAWAY_LOOP = "RUNAWAY_LOOP"
    RETRIEVAL_TAMPERING = "RETRIEVAL_TAMPERING"


class ThreatSeverity(str, Enum):
    """Threat severity levels."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatAction(str, Enum):
    """Explainable defensive response actions."""

    ALLOW = "ALLOW"
    FLAG = "FLAG"
    QUARANTINE = "QUARANTINE"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    BLOCK = "BLOCK"
    REVOKE_CAPABILITIES = "REVOKE_CAPABILITIES"
    TERMINATE_TASK = "TERMINATE_TASK"


class ContentEnvelope(BaseModel):
    """Envelopes incoming data with provenance, tenant attribution, and trust classification."""

    content: str
    source_type: SourceType = SourceType.USER_INPUT
    trust_level: TrustLevel = TrustLevel.UNTRUSTED
    tenant_id: str
    source_id: Optional[str] = None
    content_hash: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def model_post_init(self, __context: Any) -> None:
        if not self.content_hash and self.content is not None:
            self.content_hash = hashlib.sha256(self.content.encode("utf-8")).hexdigest()


class ThreatSignal(BaseModel):
    """Individual signal raised by a detection rule or analyzer."""

    threat_type: ThreatType
    severity: ThreatSeverity
    confidence: float = Field(ge=0.0, le=1.0)
    rule_id: str
    description: str
    indicators: List[str] = Field(default_factory=list)
    recommended_action: ThreatAction = ThreatAction.FLAG


class ThreatAssessment(BaseModel):
    """Unified threat evaluation output across all detectors."""

    is_threat: bool = False
    max_severity: ThreatSeverity = ThreatSeverity.LOW
    overall_risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    signals: List[ThreatSignal] = Field(default_factory=list)
    action: ThreatAction = ThreatAction.ALLOW
    reason: Optional[str] = None


class BehavioralEvent(BaseModel):
    """Chronological event representing an agent action or tool invocation."""

    agent_id: str
    task_id: str
    tool_name: str
    target_resource: Optional[str] = None
    status: str = "ATTEMPTED"  # ATTEMPTED, SUCCESS, FAILED, DENIED
    timestamp: datetime = Field(default_factory=utcnow)
    parameters_fingerprint: Optional[str] = None


class TaintRecord(BaseModel):
    """Taint status associated with a task context."""

    task_id: str
    resource: str
    taint_level: str = "CONFIDENTIAL"
    created_at: datetime = Field(default_factory=utcnow)


class MemoryUpdateProposal(BaseModel):
    """Proposed long-term memory update submitted for inspection."""

    agent_id: str
    user_id: str
    app_id: str
    key: str
    value: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class RetrievedDocumentChunk(BaseModel):
    """RAG document chunk submitted for integrity and poisoning validation."""

    chunk_id: str
    app_id: str
    collection_id: str
    content: str
    expected_hash: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
