"""SQLAlchemy ORM models for PRIVGUARD AI."""

import uuid
from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String, Text, ForeignKey, Index
from app.database.connection import Base


def utcnow() -> datetime:
    """Returns current UTC timestamp."""
    return datetime.now(timezone.utc)


def ensure_utc(dt: datetime) -> datetime:
    """Ensures datetime object is timezone-aware in UTC (fixes SQLite naive datetime returns)."""
    if dt is None:
        return datetime.now(timezone.utc)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class Application(Base):
    """Registered client applications utilizing PRIVGUARD AI."""

    __tablename__ = "applications"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(100), nullable=False)
    api_key_hash = Column(String(64), nullable=False, unique=True, index=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class Agent(Base):
    """Registered AI Agents operating under an Application."""

    __tablename__ = "agents"

    id = Column(String(64), primary_key=True, default=lambda: f"agent_{uuid.uuid4().hex[:12]}")
    app_id = Column(String(36), ForeignKey("applications.id"), nullable=False, index=True)
    name = Column(String(100), nullable=False)
    description = Column(String(255), nullable=True)
    status = Column(String(20), default="ACTIVE", nullable=False)  # ACTIVE, DISABLED, REVOKED
    allowed_tools = Column(Text, default="[]", nullable=False)    # JSON string list of tool names
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_activity_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class AgentTask(Base):
    """Task sessions with strict lifecycle and authorization boundaries."""

    __tablename__ = "agent_tasks"

    id = Column(String(64), primary_key=True, default=lambda: f"task_{uuid.uuid4().hex[:12]}")
    agent_id = Column(String(64), ForeignKey("agents.id"), nullable=False, index=True)
    app_id = Column(String(36), ForeignKey("applications.id"), nullable=False, index=True)
    status = Column(String(30), default="CREATED", nullable=False)
    # Statuses: CREATED, RUNNING, WAITING_FOR_APPROVAL, COMPLETED, FAILED, CANCELLED, EXPIRED
    description = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)


class PolicyRule(Base):
    """Enforceable privacy and security rules."""

    __tablename__ = "policy_rules"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    app_id = Column(String(36), ForeignKey("applications.id"), nullable=True, index=True)
    category = Column(String(50), nullable=False)  # PUBLIC, INTERNAL, PERSONAL, CONFIDENTIAL, CRITICAL
    action = Column(String(30), nullable=False)    # ALLOW, REDACT, BLOCK, REQUIRE_APPROVAL
    risk_level = Column(String(20), nullable=False) # LOW, MEDIUM, HIGH, CRITICAL
    is_enabled = Column(Boolean, default=True, nullable=False)
    description = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class CapabilityGrant(Base):
    """Task-scoped, time-limited, revocable capability token for agent tools."""

    __tablename__ = "capability_grants"

    id = Column(String(64), primary_key=True, default=lambda: f"cap_{uuid.uuid4().hex[:12]}")
    secret_hash = Column(String(64), nullable=False, unique=True, index=True)  # SHA-256 of opaque token
    agent_id = Column(String(64), ForeignKey("agents.id"), nullable=False, index=True)
    task_id = Column(String(64), ForeignKey("agent_tasks.id"), nullable=False, index=True)
    app_id = Column(String(36), ForeignKey("applications.id"), nullable=False, index=True)
    tool_name = Column(String(100), nullable=False)
    resource = Column(String(255), nullable=True)
    permissions = Column(Text, nullable=False, default="[]")  # JSON array string
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    max_uses = Column(Integer, default=1, nullable=False)
    uses_count = Column(Integer, default=0, nullable=False)
    is_revoked = Column(Boolean, default=False, nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class ApprovalRequest(Base):
    """Human approval queue record for high-risk operations."""

    __tablename__ = "approval_requests"

    id = Column(String(64), primary_key=True, default=lambda: f"appr_{uuid.uuid4().hex[:12]}")
    task_id = Column(String(64), ForeignKey("agent_tasks.id"), nullable=False, index=True)
    agent_id = Column(String(64), ForeignKey("agents.id"), nullable=False, index=True)
    app_id = Column(String(36), ForeignKey("applications.id"), nullable=False, index=True)
    tool_name = Column(String(100), nullable=False)
    target_resource = Column(String(255), nullable=True)
    action_parameters = Column(Text, nullable=False)  # Canonical JSON parameters
    action_hash = Column(String(64), nullable=False, index=True)  # SHA-256 cryptographic binding
    risk_level = Column(String(20), default="HIGH", nullable=False)
    status = Column(String(20), default="PENDING", nullable=False, index=True)
    # PENDING, APPROVED, REJECTED, EXPIRED, CONSUMED
    approver_id = Column(String(100), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    consumed_at = Column(DateTime(timezone=True), nullable=True)


class ToolExecutionRecord(Base):
    """Audit log of mediated tool executions."""

    __tablename__ = "tool_executions"

    id = Column(String(64), primary_key=True, default=lambda: f"exec_{uuid.uuid4().hex[:12]}")
    task_id = Column(String(64), nullable=False, index=True)
    agent_id = Column(String(64), nullable=False, index=True)
    app_id = Column(String(36), nullable=False, index=True)
    tool_name = Column(String(100), nullable=False)
    target_resource = Column(String(255), nullable=True)
    status = Column(String(20), nullable=False)  # SUCCESS, FAILED, DENIED, TIMEOUT
    execution_duration_ms = Column(Float, nullable=False, default=0.0)
    output_fingerprint = Column(String(64), nullable=True)  # SHA-256 of tool output
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class AuditEvent(Base):
    """Content-free security and privacy audit trail records."""

    __tablename__ = "audit_events"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    request_id = Column(String(64), nullable=False, index=True)
    app_id = Column(String(36), nullable=True, index=True)
    event_type = Column(String(50), nullable=False)
    data_category = Column(String(50), nullable=True)
    action_taken = Column(String(30), nullable=False)
    risk_level = Column(String(20), nullable=False)
    entity_counts = Column(Text, nullable=True)       # Serialized JSON
    content_fingerprint = Column(String(64), nullable=True) # SHA-256 hash (no raw text!)
    status = Column(String(20), nullable=False, default="SUCCESS")
    timestamp = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)

    __table_args__ = (
        Index("idx_audit_app_timestamp", "app_id", "timestamp"),
    )


class ThreatEvent(Base):
    """Content-free record of detected threats and defense interventions."""

    __tablename__ = "threat_events"

    id = Column(String(64), primary_key=True, default=lambda: f"threat_{uuid.uuid4().hex[:12]}")
    application_id = Column(String(36), ForeignKey("applications.id"), nullable=False, index=True)
    task_id = Column(String(64), nullable=True, index=True)
    agent_id = Column(String(64), nullable=True, index=True)
    threat_type = Column(String(64), nullable=False, index=True)
    severity = Column(String(20), nullable=False, index=True)  # LOW, MEDIUM, HIGH, CRITICAL
    confidence = Column(Float, nullable=False, default=1.0)
    rule_id = Column(String(100), nullable=False)
    action_taken = Column(String(30), nullable=False)  # ALLOW, FLAG, QUARANTINE, REQUIRE_APPROVAL, BLOCK, REVOKE, TERMINATE
    content_hash = Column(String(64), nullable=False)  # SHA-256 fingerprint (strictly no raw text)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)


class ActiveTaint(Base):
    """Active data taint tracked on a running task (MITRE T1700 defense)."""

    __tablename__ = "active_taints"

    id = Column(String(64), primary_key=True, default=lambda: f"taint_{uuid.uuid4().hex[:12]}")
    task_id = Column(String(64), ForeignKey("agent_tasks.id"), nullable=False, index=True)
    resource = Column(String(255), nullable=False)
    taint_level = Column(String(50), default="CONFIDENTIAL", nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

