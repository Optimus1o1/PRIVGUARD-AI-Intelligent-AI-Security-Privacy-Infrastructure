"""SQLAlchemy ORM models for PRIVGUARD AI."""

import uuid
from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text, ForeignKey, Index
from app.database.connection import Base


def utcnow() -> datetime:
    """Returns current UTC timestamp."""
    return datetime.now(timezone.utc)


class Application(Base):
    """Registered client applications utilizing PRIVGUARD AI."""

    __tablename__ = "applications"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(100), nullable=False)
    api_key_hash = Column(String(64), nullable=False, unique=True, index=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


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


class AuditEvent(Base):
    """Content-free security and privacy audit trail records."""

    __tablename__ = "audit_events"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    request_id = Column(String(64), nullable=False, index=True)
    app_id = Column(String(36), nullable=True, index=True)
    event_type = Column(String(50), nullable=False)  # DATA_INSPECTED, SECRET_BLOCKED, DATA_REDACTED, TOOL_EXECUTED
    data_category = Column(String(50), nullable=True)
    action_taken = Column(String(30), nullable=False)
    risk_level = Column(String(20), nullable=False)
    entity_counts = Column(Text, nullable=True)       # Serialized JSON e.g. {"EMAIL": 1, "PHONE": 2}
    content_fingerprint = Column(String(64), nullable=True) # SHA-256 hash of content (no raw text!)
    status = Column(String(20), nullable=False, default="SUCCESS")
    timestamp = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)

    __table_args__ = (
        Index("idx_audit_app_timestamp", "app_id", "timestamp"),
    )


class CapabilityGrant(Base):
    """Task-scoped, time-limited, revocable capability token for agent tools."""

    __tablename__ = "capability_grants"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String(100), nullable=False, index=True)
    task_id = Column(String(100), nullable=False, index=True)
    tool_name = Column(String(100), nullable=False)
    resource = Column(String(255), nullable=True)
    permissions = Column(Text, nullable=False, default="[]")  # JSON array string
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    max_uses = Column(Integer, default=1, nullable=False)
    uses_count = Column(Integer, default=0, nullable=False)
    is_revoked = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class ApprovalRequest(Base):
    """Human approval queue record for high-risk operations."""

    __tablename__ = "approval_requests"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    task_id = Column(String(100), nullable=False, index=True)
    agent_id = Column(String(100), nullable=False)
    tool_name = Column(String(100), nullable=False)
    action_description = Column(Text, nullable=False)
    status = Column(String(20), default="PENDING", nullable=False) # PENDING, APPROVED, REJECTED, EXPIRED
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
