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
    tenant_id = Column(String(64), nullable=False, default="default_tenant", index=True)
    workspace_id = Column(String(64), nullable=True, index=True)

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(100), nullable=False)
    api_key_hash = Column(String(64), nullable=False, unique=True, index=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class Agent(Base):
    """Registered AI Agents operating under an Application."""

    __tablename__ = "agents"
    tenant_id = Column(String(64), nullable=False, default="default_tenant", index=True)
    workspace_id = Column(String(64), nullable=True, index=True)

    id = Column(String(64), primary_key=True, default=lambda: f"agent_{uuid.uuid4().hex[:12]}")
    app_id = Column(String(36), ForeignKey("applications.id"), nullable=False, index=True)
    name = Column(String(100), nullable=False)
    description = Column(String(255), nullable=True)
    status = Column(String(20), default="ACTIVE", nullable=False)  # ACTIVE, DISABLED, REVOKED
    allowed_tools = Column(Text, default="[]", nullable=False)    # JSON string list of tool names
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_activity_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


# Alias for Agent Identity
AgentIdentity = Agent


class AgentTask(Base):
    """Task sessions with strict lifecycle and authorization boundaries."""

    __tablename__ = "agent_tasks"
    tenant_id = Column(String(64), nullable=False, default="default_tenant", index=True)
    workspace_id = Column(String(64), nullable=True, index=True)

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
    tenant_id = Column(String(64), nullable=False, default="default_tenant", index=True)
    workspace_id = Column(String(64), nullable=True, index=True)

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
    tenant_id = Column(String(64), nullable=False, default="default_tenant", index=True)
    workspace_id = Column(String(64), nullable=True, index=True)

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
    tenant_id = Column(String(64), nullable=False, default="default_tenant", index=True)
    workspace_id = Column(String(64), nullable=True, index=True)

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
    tenant_id = Column(String(64), nullable=False, default="default_tenant", index=True)
    workspace_id = Column(String(64), nullable=True, index=True)

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
    tenant_id = Column(String(64), nullable=False, default="default_tenant", index=True)
    workspace_id = Column(String(64), nullable=True, index=True)

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
    tenant_id = Column(String(64), nullable=False, default="default_tenant", index=True)
    workspace_id = Column(String(64), nullable=True, index=True)

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
    tenant_id = Column(String(64), nullable=False, default="default_tenant", index=True)
    workspace_id = Column(String(64), nullable=True, index=True)

    id = Column(String(64), primary_key=True, default=lambda: f"taint_{uuid.uuid4().hex[:12]}")
    task_id = Column(String(64), ForeignKey("agent_tasks.id"), nullable=False, index=True)
    resource = Column(String(255), nullable=False)
    taint_level = Column(String(50), default="CONFIDENTIAL", nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class MemoryRecord(Base):
    """Encrypted personal memory record (AES-256-GCM envelope encryption)."""

    __tablename__ = "memory_records"
    tenant_id = Column(String(64), nullable=False, default="default_tenant", index=True)
    workspace_id = Column(String(64), nullable=True, index=True)

    id = Column(String(64), primary_key=True, default=lambda: f"mem_{uuid.uuid4().hex[:12]}")
    app_id = Column(String(36), ForeignKey("applications.id"), nullable=False, index=True)
    owner_id = Column(String(100), nullable=False, index=True)
    agent_id = Column(String(64), nullable=True, index=True)
    category = Column(String(50), nullable=False, index=True)
    status = Column(String(30), default="ACTIVE", nullable=False, index=True)
    # ACTIVE, REVOKED, EXPIRED, DELETED, QUARANTINED
    provenance = Column(String(30), default="USER_CONFIRMED", nullable=False)
    # USER_CONFIRMED, AI_PROPOSED, EXTERNALLY_SOURCED, SYSTEM_GENERATED
    encrypted_content = Column(Text, nullable=False)
    nonce = Column(String(64), nullable=False)
    wrapped_dek = Column(Text, nullable=False)
    dek_nonce = Column(String(64), nullable=False)
    key_version = Column(Integer, default=1, nullable=False)
    content_fingerprint = Column(String(64), nullable=False, index=True)
    summary = Column(String(255), nullable=True)
    version = Column(Integer, default=1, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=True, index=True)
    retention_days = Column(Integer, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    consumed_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("idx_mem_app_owner", "app_id", "owner_id"),
        Index("idx_mem_owner_status", "owner_id", "status"),
    )


class MemoryProposal(Base):
    """Staged memory creation proposal awaiting user consent."""

    __tablename__ = "memory_proposals"
    tenant_id = Column(String(64), nullable=False, default="default_tenant", index=True)
    workspace_id = Column(String(64), nullable=True, index=True)

    id = Column(String(64), primary_key=True, default=lambda: f"prop_{uuid.uuid4().hex[:12]}")
    app_id = Column(String(36), ForeignKey("applications.id"), nullable=False, index=True)
    owner_id = Column(String(100), nullable=False, index=True)
    agent_id = Column(String(64), nullable=False, index=True)
    task_id = Column(String(64), nullable=False, index=True)
    proposed_key = Column(String(100), nullable=False)
    proposed_value = Column(Text, nullable=False)
    category = Column(String(50), default="USER_PREFERENCES", nullable=False)
    status = Column(String(30), default="PROPOSED", nullable=False, index=True)
    # PROPOSED, PENDING_APPROVAL, APPROVED, REJECTED, EXPIRED
    threat_assessment = Column(Text, nullable=True)
    risk_level = Column(String(20), default="LOW", nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    resolved_at = Column(DateTime(timezone=True), nullable=True)


class MemoryPermission(Base):
    """Granular access permission granting an agent authority over memory records."""

    __tablename__ = "memory_permissions"
    tenant_id = Column(String(64), nullable=False, default="default_tenant", index=True)
    workspace_id = Column(String(64), nullable=True, index=True)

    id = Column(String(64), primary_key=True, default=lambda: f"mperm_{uuid.uuid4().hex[:12]}")
    app_id = Column(String(36), ForeignKey("applications.id"), nullable=False, index=True)
    owner_id = Column(String(100), nullable=False, index=True)
    agent_id = Column(String(64), nullable=False, index=True)
    memory_id = Column(String(64), nullable=True, index=True)
    category = Column(String(50), nullable=True, index=True)
    operation = Column(String(30), nullable=False)
    # memory.read, memory.propose_write, memory.update, memory.delete
    is_granted = Column(Boolean, default=True, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=True, index=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class MemoryVersion(Base):
    """Historical encrypted version archive for rollback and audit."""

    __tablename__ = "memory_versions"
    tenant_id = Column(String(64), nullable=False, default="default_tenant", index=True)
    workspace_id = Column(String(64), nullable=True, index=True)

    id = Column(String(64), primary_key=True, default=lambda: f"mver_{uuid.uuid4().hex[:12]}")
    memory_id = Column(String(64), ForeignKey("memory_records.id"), nullable=False, index=True)
    version_num = Column(Integer, nullable=False)
    encrypted_content = Column(Text, nullable=False)
    nonce = Column(String(64), nullable=False)
    wrapped_dek = Column(Text, nullable=False)
    dek_nonce = Column(String(64), nullable=False)
    key_version = Column(Integer, default=1, nullable=False)
    content_fingerprint = Column(String(64), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class MemoryDeletionJob(Base):
    """Asynchronous deletion job tracking cryptographic erasure of memories."""

    __tablename__ = "memory_deletion_jobs"
    tenant_id = Column(String(64), nullable=False, default="default_tenant", index=True)
    workspace_id = Column(String(64), nullable=True, index=True)

    id = Column(String(64), primary_key=True, default=lambda: f"mdel_{uuid.uuid4().hex[:12]}")
    app_id = Column(String(36), ForeignKey("applications.id"), nullable=False, index=True)
    owner_id = Column(String(100), nullable=False, index=True)
    target_ids = Column(Text, nullable=False)  # JSON array string
    deletion_type = Column(String(30), default="INDIVIDUAL", nullable=False)
    # INDIVIDUAL, BULK, PURGE, EXPIRATION
    status = Column(String(30), default="PENDING", nullable=False, index=True)
    # PENDING, PROCESSING, COMPLETED, FAILED
    items_deleted = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)


class MemoryAuditEvent(Base):
    """Content-free audit logging for memory vault actions."""

    __tablename__ = "memory_audit_events"
    tenant_id = Column(String(64), nullable=False, default="default_tenant", index=True)
    workspace_id = Column(String(64), nullable=True, index=True)

    id = Column(String(64), primary_key=True, default=lambda: f"maudit_{uuid.uuid4().hex[:12]}")
    app_id = Column(String(36), nullable=False, index=True)
    owner_id = Column(String(100), nullable=False, index=True)
    agent_id = Column(String(64), nullable=True, index=True)
    memory_id = Column(String(64), nullable=True, index=True)
    operation = Column(String(50), nullable=False)
    # PROPOSE, APPROVE, REJECT, RETRIEVE, UPDATE, DELETE, PURGE, ROTATE_KEY
    category = Column(String(50), nullable=True)
    action_taken = Column(String(30), nullable=False)  # ALLOW, BLOCK, REDACT
    status = Column(String(30), nullable=False, default="SUCCESS")
    content_fingerprint = Column(String(64), nullable=True)
    timestamp = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)


# ==============================================================================
# STAGE 8: MCP SECURITY GATEWAY MODELS
# ==============================================================================

class MCPServer(Base):
    """Registered upstream Model Context Protocol (MCP) server configuration."""

    __tablename__ = "mcp_servers"
    tenant_id = Column(String(64), nullable=False, default="default_tenant", index=True)
    workspace_id = Column(String(64), nullable=True, index=True)

    id = Column(String(64), primary_key=True, default=lambda: f"mcp_srv_{uuid.uuid4().hex[:12]}")
    app_id = Column(String(36), ForeignKey("applications.id"), nullable=False, index=True)
    name = Column(String(100), nullable=False)
    description = Column(String(255), nullable=True)
    transport_type = Column(String(30), default="streamable_http", nullable=False)
    # streamable_http, stdio
    endpoint_url = Column(String(512), nullable=True)

    @property
    def url(self) -> str:
        return self.endpoint_url or ""

    @url.setter
    def url(self, value: str):
        self.endpoint_url = value
    command = Column(String(255), nullable=True)
    args = Column(Text, default="[]", nullable=False)  # JSON list
    env_vars = Column(Text, default="{}", nullable=False)  # JSON dict with encrypted or secret references
    status = Column(String(30), default="ACTIVE", nullable=False, index=True)
    # ACTIVE, DISABLED, DISCONNECTED, QUARANTINED, REQUIRES_REAPPROVAL
    trust_level = Column(String(30), default="UNTRUSTED", nullable=False)
    # TRUSTED, UNTRUSTED, PROBATION
    catalog_fingerprint = Column(String(64), nullable=True)
    auth_type = Column(String(30), default="NONE", nullable=False)
    # NONE, API_KEY, BEARER_TOKEN, OAUTH2
    auth_credential_ref = Column(String(255), nullable=True)
    last_connected_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class MCPToolDefinition(Base):
    """Tool definitions discovered from an upstream MCP server or exposed by PRIVGUARD."""

    __tablename__ = "mcp_tool_definitions"
    tenant_id = Column(String(64), nullable=False, default="default_tenant", index=True)
    workspace_id = Column(String(64), nullable=True, index=True)

    id = Column(String(64), primary_key=True, default=lambda: f"mcpt_{uuid.uuid4().hex[:12]}")
    server_id = Column(String(64), ForeignKey("mcp_servers.id"), nullable=False, index=True)
    app_id = Column(String(36), ForeignKey("applications.id"), nullable=False, index=True)
    name = Column(String(100), nullable=False, index=True)
    description = Column(Text, nullable=True)
    input_schema = Column(Text, default="{}", nullable=False)  # JSON schema string
    risk_level = Column(String(20), default="MEDIUM", nullable=False)
    # LOW, MEDIUM, HIGH, CRITICAL
    requires_approval = Column(Boolean, default=False, nullable=False)
    is_approved = Column(Boolean, default=True, nullable=False)
    version = Column(Integer, default=1, nullable=False)
    definition_hash = Column(String(64), nullable=False)  # SHA-256 of canonical definition
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class MCPResourceDefinition(Base):
    """Resource representations discovered from an upstream MCP server."""

    __tablename__ = "mcp_resource_definitions"
    tenant_id = Column(String(64), nullable=False, default="default_tenant", index=True)
    workspace_id = Column(String(64), nullable=True, index=True)

    id = Column(String(64), primary_key=True, default=lambda: f"mcpr_{uuid.uuid4().hex[:12]}")
    server_id = Column(String(64), ForeignKey("mcp_servers.id"), nullable=False, index=True)
    app_id = Column(String(36), ForeignKey("applications.id"), nullable=False, index=True)
    uri = Column(String(512), nullable=False, index=True)
    name = Column(String(100), nullable=False)
    description = Column(String(255), nullable=True)
    mime_type = Column(String(100), default="text/plain", nullable=False)
    risk_level = Column(String(20), default="LOW", nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class MCPAuditEvent(Base):
    """Audit events specifically tracking MCP gateway operations and security interventions."""

    __tablename__ = "mcp_audit_events"
    tenant_id = Column(String(64), nullable=False, default="default_tenant", index=True)
    workspace_id = Column(String(64), nullable=True, index=True)

    id = Column(String(64), primary_key=True, default=lambda: f"mcpaudit_{uuid.uuid4().hex[:12]}")
    app_id = Column(String(36), ForeignKey("applications.id"), nullable=False, index=True)
    server_id = Column(String(64), nullable=True, index=True)
    agent_id = Column(String(64), nullable=True)
    tool_name = Column(String(100), nullable=True)
    action = Column(String(50), nullable=False)
    # REGISTER_SERVER, SYNC_CATALOG, CALL_TOOL, READ_RESOURCE, CATALOG_DRIFT_DETECTED, SSRF_BLOCKED, POISONING_BLOCKED
    status = Column(String(30), default="SUCCESS", nullable=False)
    # SUCCESS, BLOCKED, ERROR, QUARANTINED
    details = Column(Text, default="{}", nullable=False)  # JSON string
    timestamp = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)



# ==========================================
# ENTERPRISE GOVERNANCE & MULTI-TENANCY (STAGE 9)
# ==========================================

class Organization(Base):
    """Enterprise tenant boundary defining security, SSO, and compliance policies."""

    __tablename__ = "organizations"

    id = Column(String(64), primary_key=True, default=lambda: f"org_{uuid.uuid4().hex[:12]}")
    slug = Column(String(64), unique=True, nullable=False, index=True)
    name = Column(String(128), nullable=False)
    domain = Column(String(128), nullable=True, index=True)
    domain_verified = Column(Boolean, default=False, nullable=False)
    status = Column(String(32), default="ACTIVE", nullable=False)  # ACTIVE, SUSPENDED, PENDING_VERIFICATION
    security_profile = Column(Text, default="{}", nullable=False)  # JSON settings
    retention_days = Column(Integer, default=90, nullable=False)
    sso_config = Column(Text, default="{}", nullable=False)  # OIDC/SAML JSON config
    signing_public_key = Column(Text, nullable=True)  # Ed25519 public key hex
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


class OrganizationMembership(Base):
    """User membership within an organization with assigned enterprise RBAC role."""

    __tablename__ = "organization_memberships"

    id = Column(String(64), primary_key=True, default=lambda: f"mem_{uuid.uuid4().hex[:12]}")
    organization_id = Column(String(64), ForeignKey("organizations.id"), nullable=False, index=True)
    user_id = Column(String(64), nullable=False, index=True)
    email = Column(String(128), nullable=False, index=True)
    role = Column(String(32), default="VIEWER", nullable=False)
    # Roles: ORGANIZATION_OWNER, SECURITY_ADMIN, POLICY_ADMIN, FLEET_ADMIN, DEVELOPER, AGENT_OPERATOR, AUDITOR, VIEWER
    status = Column(String(32), default="ACTIVE", nullable=False)  # ACTIVE, INVITED, SUSPENDED, DEPROVISIONED
    mfa_enabled = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


class OrganizationInvitation(Base):
    """Pending user invitations to join an enterprise organization."""

    __tablename__ = "organization_invitations"

    id = Column(String(64), primary_key=True, default=lambda: f"inv_{uuid.uuid4().hex[:12]}")
    organization_id = Column(String(64), ForeignKey("organizations.id"), nullable=False, index=True)
    email = Column(String(128), nullable=False)
    role = Column(String(32), default="VIEWER", nullable=False)
    token_hash = Column(String(64), unique=True, nullable=False)
    invited_by_user_id = Column(String(64), nullable=False)
    status = Column(String(32), default="PENDING", nullable=False)  # PENDING, ACCEPTED, EXPIRED, REVOKED
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class Workspace(Base):
    """Departmental workspace boundary within an organization."""

    __tablename__ = "workspaces"

    id = Column(String(64), primary_key=True, default=lambda: f"ws_{uuid.uuid4().hex[:12]}")
    tenant_id = Column(String(64), nullable=False, default="default_tenant", index=True)
    organization_id = Column(String(64), ForeignKey("organizations.id"), nullable=False, index=True)
    name = Column(String(100), nullable=False)
    slug = Column(String(64), nullable=False)
    description = Column(String(255), nullable=True)
    is_default = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class WorkspaceMembership(Base):
    """User membership within a specific workspace."""

    __tablename__ = "workspace_memberships"

    id = Column(String(64), primary_key=True, default=lambda: f"wsm_{uuid.uuid4().hex[:12]}")
    workspace_id = Column(String(64), ForeignKey("workspaces.id"), nullable=False, index=True)
    user_id = Column(String(64), nullable=False, index=True)
    role = Column(String(32), default="MEMBER", nullable=False)  # ADMIN, MEMBER, VIEWER
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class PolicyBundle(Base):
    """Cryptographically signed policy bundles deployed across an organization or workspace."""

    __tablename__ = "policy_bundles"

    id = Column(String(64), primary_key=True, default=lambda: f"pol_{uuid.uuid4().hex[:12]}")
    tenant_id = Column(String(64), nullable=False, default="default_tenant", index=True)
    organization_id = Column(String(64), ForeignKey("organizations.id"), nullable=False, index=True)
    workspace_id = Column(String(64), nullable=True, index=True)
    version = Column(Integer, nullable=False)
    status = Column(String(32), default="DRAFT", nullable=False)  # DRAFT, VALIDATED, APPROVED, STAGED, ACTIVE, ROLLED_BACK, REPLACED
    policy_hash = Column(String(64), nullable=False)  # SHA-256 of canonical JSON
    bundle_json = Column(Text, nullable=False)
    signature_ed25519 = Column(Text, nullable=False)
    signing_key_id = Column(String(64), nullable=False)
    created_by = Column(String(64), nullable=False)
    approved_by = Column(String(64), nullable=True)
    deployed_by = Column(String(64), nullable=True)
    rollout_stage = Column(String(32), default="NONE", nullable=False)  # NONE, CANARY, WORKSPACE, ORG_WIDE
    previous_bundle_id = Column(String(64), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    activated_at = Column(DateTime(timezone=True), nullable=True)


class FleetResource(Base):
    """Central inventory record for AI agents, MCP servers, gateways, and SDK clients."""

    __tablename__ = "fleet_resources"

    id = Column(String(64), primary_key=True, default=lambda: f"res_{uuid.uuid4().hex[:12]}")
    tenant_id = Column(String(64), nullable=False, default="default_tenant", index=True)
    workspace_id = Column(String(64), nullable=True, index=True)
    resource_type = Column(String(32), nullable=False)  # AGENT, MCP_SERVER, GATEWAY_INSTANCE, SDK_CLIENT
    resource_id = Column(String(64), nullable=False, index=True)
    name = Column(String(128), nullable=False)
    environment = Column(String(32), default="production", nullable=False)  # production, staging, development
    status = Column(String(32), default="ACTIVE", nullable=False)  # ACTIVE, DISABLED, QUARANTINED, REVOKED
    active_policy_version = Column(Integer, nullable=True)
    active_policy_hash = Column(String(64), nullable=True)
    drift_status = Column(String(32), default="SYNCED", nullable=False)  # SYNCED, DRIFTED, DISCONNECTED, UNKNOWN
    last_heartbeat_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    registered_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    metadata_json = Column(Text, default="{}", nullable=False)


class FleetRegistrationToken(Base):
    """One-time or bounded tokens for fleet agents and MCP servers to register."""

    __tablename__ = "fleet_registration_tokens"

    id = Column(String(64), primary_key=True, default=lambda: f"ftok_{uuid.uuid4().hex[:12]}")
    tenant_id = Column(String(64), nullable=False, default="default_tenant", index=True)
    workspace_id = Column(String(64), nullable=True, index=True)
    token_hash = Column(String(64), unique=True, nullable=False)
    max_uses = Column(Integer, default=1, nullable=False)
    uses_count = Column(Integer, default=0, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class IntegrationCredential(Base):
    """Encrypted secrets strictly scoped to integrations (MCP servers, SIEM endpoints)."""

    __tablename__ = "integration_credentials"

    id = Column(String(64), primary_key=True, default=lambda: f"cred_{uuid.uuid4().hex[:12]}")
    tenant_id = Column(String(64), nullable=False, default="default_tenant", index=True)
    workspace_id = Column(String(64), nullable=True, index=True)
    integration_type = Column(String(32), nullable=False)  # MCP_SERVER, SIEM_WEBHOOK, PROVIDER_API
    target_id = Column(String(64), nullable=False, index=True)
    encrypted_secret = Column(Text, nullable=False)
    key_version = Column(String(32), default="v1", nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    last_rotated_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class EnterpriseAuditEvent(Base):
    """Tamper-evident, hash-chained security audit events for enterprise governance."""

    __tablename__ = "enterprise_audit_events"

    id = Column(String(64), primary_key=True, default=lambda: f"eaudit_{uuid.uuid4().hex[:12]}")
    tenant_id = Column(String(64), nullable=False, default="default_tenant", index=True)
    workspace_id = Column(String(64), nullable=True, index=True)
    sequence_number = Column(Integer, nullable=False, index=True)
    action = Column(String(64), nullable=False, index=True)
    actor_type = Column(String(32), nullable=False)  # USER, AGENT, SYSTEM, SCIM
    actor_id = Column(String(64), nullable=False)
    resource_type = Column(String(64), nullable=False)
    resource_id = Column(String(64), nullable=False)
    details_json = Column(Text, default="{}", nullable=False)  # Redacted metadata
    previous_event_hash = Column(String(64), nullable=False)
    event_hash = Column(String(64), nullable=False, index=True)  # SHA-256(prev_hash + canonical_event)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class AuditExportJob(Base):
    """Asynchronous SIEM export jobs pushing audit records to external telemetry systems."""

    __tablename__ = "audit_export_jobs"

    id = Column(String(64), primary_key=True, default=lambda: f"exp_{uuid.uuid4().hex[:12]}")
    tenant_id = Column(String(64), nullable=False, default="default_tenant", index=True)
    destination_type = Column(String(32), nullable=False)  # SIEM_WEBHOOK, S3_EXPORT, DATADOG
    destination_url = Column(String(255), nullable=False)
    status = Column(String(32), default="PENDING", nullable=False)  # PENDING, IN_PROGRESS, COMPLETED, FAILED
    from_sequence = Column(Integer, default=0, nullable=False)
    to_sequence = Column(Integer, default=0, nullable=False)
    records_count = Column(Integer, default=0, nullable=False)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)
