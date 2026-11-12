"""Common type aliases and enums for the PRIVGUARD Python SDK.

Moon Sanctum Labs - Decode. Build. Evolve.
"""

from enum import Enum
from typing import Any

# Generic JSON Dict Type
JSONDict = dict[str, Any]


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ActionType(str, Enum):
    ALLOW = "ALLOW"
    REDACT = "REDACT"
    HOLD = "HOLD"
    BLOCK = "BLOCK"


class AgentStatus(str, Enum):
    ACTIVE = "ACTIVE"
    PAUSED = "PAUSED"
    REVOKED = "REVOKED"


class TaskStatus(str, Enum):
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class ApprovalStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


class MemoryCategory(str, Enum):
    USER_PREFERENCES = "USER_PREFERENCES"
    PROJECT_CONTEXT = "PROJECT_CONTEXT"
    CONVERSATION_HISTORY = "CONVERSATION_HISTORY"
    FACTUAL_KNOWLEDGE = "FACTUAL_KNOWLEDGE"
    SYSTEM_DIRECTIVE = "SYSTEM_DIRECTIVE"


class ProposalStatus(str, Enum):
    PENDING = "PENDING"
    CONSENTED = "CONSENTED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


class ExportFormat(str, Enum):
    ZIP = "ZIP"
    JSON = "JSON"
    CSV = "CSV"


class CommencementStatus(str, Enum):
    COMMENCED = "COMMENCED"
    PENDING_COMMENCEMENT = "PENDING_COMMENCEMENT"
    NOT_COMMENCED = "NOT_COMMENCED"


class MappingType(str, Enum):
    DIRECT = "DIRECT"
    PARTIAL = "PARTIAL"
    SUPPORTING = "SUPPORTING"


class AssuranceLevel(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INSUFFICIENT = "INSUFFICIENT"


class SourceType(str, Enum):
    USER_INPUT = "USER_INPUT"
    RETRIEVED_CONTEXT = "RETRIEVED_CONTEXT"
    TOOL_OUTPUT = "TOOL_OUTPUT"
    SYSTEM = "SYSTEM"


class TrustLevel(str, Enum):
    UNTRUSTED = "UNTRUSTED"
    SEMI_TRUSTED = "SEMI_TRUSTED"
    TRUSTED = "TRUSTED"
