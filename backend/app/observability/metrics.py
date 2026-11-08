"""PRIVGUARD AI - Low-Cardinality Prometheus Metrics Registry.
Enforces strictly bounded labels and zero-high-cardinality values across all counters,
gauges, and duration histograms.
"""

from typing import Optional
from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    REGISTRY,
    generate_latest,
    CONTENT_TYPE_LATEST,
)

# Custom Registry for PRIVGUARD to prevent collisions in test runners
privguard_registry = CollectorRegistry(auto_describe=True)

# Standard Latency Buckets (in seconds)
LATENCY_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)

# ==============================================================================
# 1. HTTP Metrics (Strictly Bounded Labels: method, route, status_class)
# ==============================================================================
HTTP_REQUESTS_TOTAL = Counter(
    "privguard_http_requests_total",
    "Total HTTP requests received by the gateway",
    ["method", "route", "status_class"],
    registry=privguard_registry,
)

HTTP_REQUEST_DURATION_SECONDS = Histogram(
    "privguard_http_request_duration_seconds",
    "HTTP request latency distribution in seconds",
    ["method", "route", "status_class"],
    buckets=LATENCY_BUCKETS,
    registry=privguard_registry,
)

HTTP_REQUESTS_IN_FLIGHT = Gauge(
    "privguard_http_requests_in_flight",
    "Current number of in-flight HTTP requests",
    ["method"],
    registry=privguard_registry,
)

HTTP_ERRORS_TOTAL = Counter(
    "privguard_http_errors_total",
    "Total HTTP server and client errors returned",
    ["method", "route", "error_type"],
    registry=privguard_registry,
)

# ==============================================================================
# 2. AI Gateway Metrics
# ==============================================================================
GATEWAY_REQUESTS_TOTAL = Counter(
    "privguard_gateway_requests_total",
    "Total upstream model gateway requests",
    ["provider", "model", "status"],
    registry=privguard_registry,
)

GATEWAY_REQUEST_DURATION_SECONDS = Histogram(
    "privguard_gateway_request_duration_seconds",
    "AI Gateway roundtrip latency in seconds",
    ["provider", "model", "phase"],
    buckets=LATENCY_BUCKETS,
    registry=privguard_registry,
)

GATEWAY_BLOCKED_REQUESTS_TOTAL = Counter(
    "privguard_gateway_blocked_requests_total",
    "Total gateway requests blocked by pre-flight or post-flight security policies",
    ["reason"],
    registry=privguard_registry,
)

GATEWAY_UPSTREAM_ERRORS_TOTAL = Counter(
    "privguard_gateway_upstream_errors_total",
    "Total upstream model provider failures",
    ["provider", "error_code"],
    registry=privguard_registry,
)

GATEWAY_RESPONSE_INSPECTION_TOTAL = Counter(
    "privguard_gateway_response_inspection_total",
    "Total model responses inspected for leaked secrets or policy violations",
    ["decision"],
    registry=privguard_registry,
)

# ==============================================================================
# 3. Privacy Metrics
# ==============================================================================
PII_DETECTION_TOTAL = Counter(
    "privguard_pii_detection_total",
    "Total PII entities detected in incoming context",
    ["entity_type"],
    registry=privguard_registry,
)

REDACTION_TOTAL = Counter(
    "privguard_redaction_total",
    "Total PII entities successfully redacted with safe surrogate tokens",
    ["entity_type"],
    registry=privguard_registry,
)

SECRET_BLOCK_TOTAL = Counter(
    "privguard_secret_block_total",
    "Total high-entropy secrets and credentials blocked from entering model context",
    ["secret_type"],
    registry=privguard_registry,
)

PRIVACY_POLICY_DECISIONS_TOTAL = Counter(
    "privguard_privacy_policy_decisions_total",
    "Total automated privacy policy enforcement decisions",
    ["action"],
    registry=privguard_registry,
)

# ==============================================================================
# 4. Agent Security Metrics
# ==============================================================================
AGENT_TOOL_EXECUTIONS_TOTAL = Counter(
    "privguard_agent_tool_executions_total",
    "Total agent tool executions processed by the broker",
    ["tool_name", "status"],
    registry=privguard_registry,
)

AGENT_TOOL_EXECUTION_DURATION_SECONDS = Histogram(
    "privguard_agent_tool_execution_duration_seconds",
    "Agent tool execution duration in seconds",
    ["tool_name"],
    buckets=LATENCY_BUCKETS,
    registry=privguard_registry,
)

AGENT_AUTHORIZATION_DENIALS_TOTAL = Counter(
    "privguard_agent_authorization_denials_total",
    "Total agent tool calls denied due to missing or expired capabilities",
    ["reason"],
    registry=privguard_registry,
)

AGENT_CAPABILITY_REVOCATIONS_TOTAL = Counter(
    "privguard_agent_capability_revocations_total",
    "Total capability tokens actively revoked across the cluster",
    ["reason"],
    registry=privguard_registry,
)

AGENT_APPROVAL_REQUESTS_TOTAL = Counter(
    "privguard_agent_approval_requests_total",
    "Total high-risk tool operations held for human approval",
    ["status"],
    registry=privguard_registry,
)

AGENT_EXECUTION_FAILURES_TOTAL = Counter(
    "privguard_agent_execution_failures_total",
    "Total agent execution failures",
    ["tool_name", "failure_type"],
    registry=privguard_registry,
)

# ==============================================================================
# 5. Threat Detection Metrics
# ==============================================================================
THREAT_DETECTIONS_TOTAL = Counter(
    "privguard_threat_detections_total",
    "Total security threats detected across all analyzers",
    ["threat_category", "severity"],
    registry=privguard_registry,
)

THREAT_BLOCKS_TOTAL = Counter(
    "privguard_threat_blocks_total",
    "Total threats actively blocked from execution",
    ["threat_category"],
    registry=privguard_registry,
)

THREAT_QUARANTINE_TOTAL = Counter(
    "privguard_threat_quarantine_total",
    "Total entities placed in security quarantine",
    ["quarantine_type"],
    registry=privguard_registry,
)

EXFILTRATION_ATTEMPTS_TOTAL = Counter(
    "privguard_exfiltration_attempts_total",
    "Total unauthorized data transmission attempts intercepted by taint tracking",
    ["sink_type"],
    registry=privguard_registry,
)

PROMPT_INJECTION_DETECTIONS_TOTAL = Counter(
    "privguard_prompt_injection_detections_total",
    "Total prompt injection attacks detected",
    ["pattern_category"],
    registry=privguard_registry,
)

# ==============================================================================
# 6. MCP Gateway Metrics
# ==============================================================================
MCP_REQUESTS_TOTAL = Counter(
    "privguard_mcp_requests_total",
    "Total Model Context Protocol gateway requests",
    ["server_type", "status"],
    registry=privguard_registry,
)

MCP_TOOL_CALLS_TOTAL = Counter(
    "privguard_mcp_tool_calls_total",
    "Total MCP tool invocations mediated by the gateway",
    ["server_type", "status"],
    registry=privguard_registry,
)

MCP_SERVER_CONNECTION_ERRORS_TOTAL = Counter(
    "privguard_mcp_server_connection_errors_total",
    "Total upstream MCP server transport or connection errors",
    ["server_type", "error_code"],
    registry=privguard_registry,
)

MCP_TOOL_CATALOG_CHANGES_TOTAL = Counter(
    "privguard_mcp_tool_catalog_changes_total",
    "Total MCP tool catalog drift or update events detected",
    ["action"],
    registry=privguard_registry,
)

# ==============================================================================
# 7. Memory Vault & KMS Cryptographic Metrics
# ==============================================================================
MEMORY_OPERATIONS_TOTAL = Counter(
    "privguard_memory_operations_total",
    "Total personal AI memory vault operations",
    ["operation", "status"],
    registry=privguard_registry,
)

MEMORY_ENCRYPTION_DURATION_SECONDS = Histogram(
    "privguard_memory_encryption_duration_seconds",
    "Memory envelope encryption duration in seconds",
    ["format"],
    buckets=LATENCY_BUCKETS,
    registry=privguard_registry,
)

MEMORY_DECRYPTION_DURATION_SECONDS = Histogram(
    "privguard_memory_decryption_duration_seconds",
    "Memory envelope decryption duration in seconds",
    ["format"],
    buckets=LATENCY_BUCKETS,
    registry=privguard_registry,
)

MEMORY_MIGRATION_PROGRESS = Gauge(
    "privguard_memory_migration_progress",
    "Count of unmigrated V1 records remaining in active storage",
    ["status"],
    registry=privguard_registry,
)

KMS_OPERATIONS_TOTAL = Counter(
    "privguard_kms_operations_total",
    "Total cryptographic key management operations executed",
    ["provider", "operation"],
    registry=privguard_registry,
)

KMS_OPERATION_DURATION_SECONDS = Histogram(
    "privguard_kms_operation_duration_seconds",
    "KMS key wrap/unwrap latency in seconds",
    ["provider", "operation"],
    buckets=LATENCY_BUCKETS,
    registry=privguard_registry,
)

KMS_FAILURES_TOTAL = Counter(
    "privguard_kms_failures_total",
    "Total KMS operational failures or network timeouts",
    ["provider", "error_type"],
    registry=privguard_registry,
)

KEY_ROTATION_STATUS = Gauge(
    "privguard_key_rotation_status",
    "Current status of managed cryptographic key versions (1=active, 0=non-active)",
    ["purpose", "status"],
    registry=privguard_registry,
)

# ==============================================================================
# 8. Distributed Infrastructure & Database Pool Metrics
# ==============================================================================
OUTBOX_PENDING_EVENTS = Gauge(
    "privguard_outbox_pending_events",
    "Current count of unpublished transactional outbox events",
    registry=privguard_registry,
)

STREAM_CONSUMER_LAG = Gauge(
    "privguard_stream_consumer_lag",
    "Pending messages in Redis Stream consumer groups",
    ["stream_name", "consumer_group"],
    registry=privguard_registry,
)

EVENT_PROCESSING_FAILURES_TOTAL = Counter(
    "privguard_event_processing_failures_total",
    "Total asynchronous event processing failures in the worker tier",
    ["event_type"],
    registry=privguard_registry,
)

DISTRIBUTED_RATE_LIMIT_DENIALS_TOTAL = Counter(
    "privguard_distributed_rate_limit_denials_total",
    "Total requests denied by cluster-wide Redis sliding-window rate limiters",
    ["limiter_tier"],
    registry=privguard_registry,
)

POLICY_SYNC_FAILURES_TOTAL = Counter(
    "privguard_policy_sync_failures_total",
    "Total cross-replica policy synchronization failures",
    ["reason"],
    registry=privguard_registry,
)

DATABASE_POOL_CONNECTIONS = Gauge(
    "privguard_database_pool_connections",
    "Current status of PostgreSQL async database connection pool",
    ["state"],  # checked_in, checked_out, overflow
    registry=privguard_registry,
)

DATABASE_POOL_WAIT_SECONDS = Histogram(
    "privguard_database_pool_wait_seconds",
    "Time waiting to acquire a connection from the database pool",
    buckets=LATENCY_BUCKETS,
    registry=privguard_registry,
)

REDIS_CONNECTION_ERRORS_TOTAL = Counter(
    "privguard_redis_connection_errors_total",
    "Total Redis connection failures, timeouts, or command errors",
    ["operation"],
    registry=privguard_registry,
)


def get_metrics_snapshot() -> bytes:
    """Renders the current metrics snapshot formatted for Prometheus scraping."""
    return generate_latest(privguard_registry)


# ==============================================================================
# 9. Synthetic Security Canary Metrics
# ==============================================================================
CANARY_STATUS = Gauge(
    "privguard_canary_status",
    "Status of synthetic security canary execution (1 = pass/verified, 0 = fail/unverified)",
    ["canary_name"],
    registry=privguard_registry,
)

CANARY_EXECUTION_DURATION_SECONDS = Histogram(
    "privguard_canary_execution_duration_seconds",
    "Canary scenario execution duration in seconds",
    ["canary_name"],
    buckets=LATENCY_BUCKETS,
    registry=privguard_registry,
)

CANARY_LAST_RUN_TIMESTAMP = Gauge(
    "privguard_canary_last_run_timestamp",
    "Unix timestamp of the most recent canary scenario execution",
    ["canary_name"],
    registry=privguard_registry,
)

OUTBOX_EVENTS_PUBLISHED_TOTAL = Counter(
    "privguard_outbox_events_published_total",
    "Total outbox events published to Redis stream",
    registry=privguard_registry,
)


# ==============================================================================
# 10. Operational Convenience Helper Functions
# ==============================================================================
def record_http_request(method: str, route: str, status_class: str, duration: Optional[float] = None) -> None:
    HTTP_REQUESTS_TOTAL.labels(method=method, route=route, status_class=status_class).inc()
    if duration is not None:
        HTTP_REQUEST_DURATION_SECONDS.labels(method=method, route=route, status_class=status_class).observe(duration)


def record_gateway_request(
    provider: str, model: str, status: str, duration: Optional[float] = None, phase: str = "total"
) -> None:
    GATEWAY_REQUESTS_TOTAL.labels(provider=provider, model=model, status=status).inc()
    if duration is not None:
        GATEWAY_REQUEST_DURATION_SECONDS.labels(provider=provider, model=model, phase=phase).observe(duration)


def record_pii_detection(entity_type: str) -> None:
    PII_DETECTION_TOTAL.labels(entity_type=entity_type).inc()


def record_redaction(entity_type: str) -> None:
    REDACTION_TOTAL.labels(entity_type=entity_type).inc()


def record_secret_block(secret_type: str) -> None:
    SECRET_BLOCK_TOTAL.labels(secret_type=secret_type).inc()


def record_policy_decision(action: str) -> None:
    PRIVACY_POLICY_DECISIONS_TOTAL.labels(action=action).inc()


def record_tool_execution(tool_name: str, status: str, duration: Optional[float] = None) -> None:
    AGENT_TOOL_EXECUTIONS_TOTAL.labels(tool_name=tool_name, status=status).inc()
    if duration is not None:
        AGENT_TOOL_EXECUTION_DURATION_SECONDS.labels(tool_name=tool_name).observe(duration)


def record_authorization_denial(reason: str) -> None:
    AGENT_AUTHORIZATION_DENIALS_TOTAL.labels(reason=reason).inc()


def record_capability_revocation() -> None:
    AGENT_CAPABILITY_REVOCATIONS_TOTAL.inc()


def record_approval_request(status: str) -> None:
    AGENT_APPROVAL_REQUESTS_TOTAL.labels(status=status).inc()


def record_threat_detection(threat_category: str, severity: str) -> None:
    THREAT_DETECTIONS_TOTAL.labels(threat_category=threat_category, severity=severity).inc()


def record_threat_block() -> None:
    THREAT_BLOCKS_TOTAL.inc()


def record_exfiltration_attempt(sink_type: str) -> None:
    EXFILTRATION_ATTEMPTS_TOTAL.labels(sink_type=sink_type).inc()


def record_prompt_injection(pattern_category: str) -> None:
    PROMPT_INJECTION_DETECTIONS_TOTAL.labels(pattern_category=pattern_category).inc()


def record_mcp_request(server_type: str, status: str) -> None:
    MCP_REQUESTS_TOTAL.labels(server_type=server_type, status=status).inc()


def record_mcp_tool_call() -> None:
    MCP_TOOL_CALLS_TOTAL.inc()


def record_mcp_connection_error() -> None:
    MCP_SERVER_CONNECTION_ERRORS_TOTAL.inc()


def record_mcp_catalog_change(action: str) -> None:
    MCP_TOOL_CATALOG_CHANGES_TOTAL.labels(action=action).inc()


def record_memory_operation(operation: str, status: str) -> None:
    MEMORY_OPERATIONS_TOTAL.labels(operation=operation, status=status).inc()


def record_memory_encryption_duration(duration: float) -> None:
    MEMORY_ENCRYPTION_DURATION_SECONDS.observe(duration)


def record_kms_operation(provider: str, operation: str) -> None:
    KMS_OPERATIONS_TOTAL.labels(provider=provider, operation=operation).inc()


def record_kms_failure() -> None:
    KMS_FAILURES_TOTAL.inc()


def record_key_rotation_status(purpose: str, status: int = 1) -> None:
    KEY_ROTATION_STATUS.labels(purpose=purpose).set(status)


def record_outbox_published() -> None:
    OUTBOX_EVENTS_PUBLISHED_TOTAL.inc()


def record_event_failure(event_type: str) -> None:
    EVENT_PROCESSING_FAILURES_TOTAL.labels(event_type=event_type).inc()


def record_rate_limit_denial(limiter_tier: str) -> None:
    DISTRIBUTED_RATE_LIMIT_DENIALS_TOTAL.labels(limiter_tier=limiter_tier).inc()


def record_redis_error(operation: str) -> None:
    REDIS_CONNECTION_ERRORS_TOTAL.labels(operation=operation).inc()


def set_outbox_pending(count: int) -> None:
    OUTBOX_PENDING_EVENTS.set(count)


def set_stream_lag(stream_name: str, consumer_group: str, lag: int) -> None:
    STREAM_CONSUMER_LAG.labels(stream_name=stream_name, consumer_group=consumer_group).set(lag)


def set_db_pool_connections(state: str, count: int) -> None:
    DATABASE_POOL_CONNECTIONS.labels(state=state).set(count)


# ==============================================================================
# Compliance Evidence Engine Metrics (Stage 10.9)
# ==============================================================================
COMPLIANCE_EVIDENCE_COLLECTED_TOTAL = Counter(
    "privguard_compliance_evidence_collected_total",
    "Total compliance evidence records collected",
    ["collector_name", "status"],
    registry=privguard_registry,
)

COMPLIANCE_EXPORTS_GENERATED_TOTAL = Counter(
    "privguard_compliance_exports_generated_total",
    "Total signed compliance evidence export packages generated",
    ["export_format"],
    registry=privguard_registry,
)

COMPLIANCE_GAPS_DETECTED = Gauge(
    "privguard_compliance_gaps_detected",
    "Current count of active compliance gaps by severity",
    ["severity"],
    registry=privguard_registry,
)


def record_evidence_collected(collector_name: str, status: str = "VERIFIED") -> None:
    COMPLIANCE_EVIDENCE_COLLECTED_TOTAL.labels(collector_name=collector_name, status=status).inc()


def record_compliance_export(export_format: str = "ZIP") -> None:
    COMPLIANCE_EXPORTS_GENERATED_TOTAL.labels(export_format=export_format).inc()


def set_compliance_gaps(severity: str, count: int) -> None:
    COMPLIANCE_GAPS_DETECTED.labels(severity=severity).set(count)


# ==============================================================================
# Disaster Recovery & Production Validation Metrics (Stage 10.11)
# ==============================================================================
DR_BASE_BACKUP_AGE_SECONDS = Gauge(
    "privguard_dr_base_backup_age_seconds",
    "Age of most recent verified PostgreSQL physical base backup in seconds",
    registry=privguard_registry,
)

DR_WAL_ARCHIVE_LAG_SECONDS = Gauge(
    "privguard_dr_wal_archive_lag_seconds",
    "Lag between primary WAL write and secondary archival persistence in seconds",
    registry=privguard_registry,
)

DR_BACKUP_VERIFICATION_STATUS = Gauge(
    "privguard_dr_backup_verification_status",
    "Signature and integrity verification status of latest backup (1=verified, 0=failed)",
    ["backup_type"],
    registry=privguard_registry,
)

DR_SECURITY_EPOCH = Gauge(
    "privguard_dr_security_epoch",
    "Current active monotonic security recovery epoch",
    registry=privguard_registry,
)

DR_ERASURE_TOMBSTONES_TOTAL = Gauge(
    "privguard_dr_erasure_tombstones_total",
    "Total active memory erasure tombstones tracked in independent ledger",
    registry=privguard_registry,
)

DR_RECONCILED_ERASURES_TOTAL = Counter(
    "privguard_dr_reconciled_erasures_total",
    "Total resurrected ciphertexts scrubbed during post-recovery reconciliation",
    registry=privguard_registry,
)

DR_RECONCILED_REVOCATIONS_TOTAL = Counter(
    "privguard_dr_reconciled_revocations_total",
    "Total resurrected capabilities re-revoked during post-recovery reconciliation",
    registry=privguard_registry,
)

DR_DRILL_DURATION_SECONDS = Gauge(
    "privguard_dr_drill_duration_seconds",
    "Duration of most recent automated disaster recovery drill execution in seconds",
    ["status"],
    registry=privguard_registry,
)

DR_SAFE_RESTRICTION_MODE_ACTIVE = Gauge(
    "privguard_dr_safe_restriction_mode_active",
    "Indicates if cold-start Safe Restriction Mode is active (1=active, 0=normal)",
    registry=privguard_registry,
)


def set_dr_backup_age(seconds: float) -> None:
    DR_BASE_BACKUP_AGE_SECONDS.set(seconds)


def set_dr_wal_lag(seconds: float) -> None:
    DR_WAL_ARCHIVE_LAG_SECONDS.set(seconds)


def set_dr_backup_verification_status(backup_type: str, verified: bool) -> None:
    DR_BACKUP_VERIFICATION_STATUS.labels(backup_type=backup_type).set(1.0 if verified else 0.0)


def set_dr_security_epoch(epoch: int) -> None:
    DR_SECURITY_EPOCH.set(epoch)


def set_dr_erasure_tombstones(count: int) -> None:
    DR_ERASURE_TOMBSTONES_TOTAL.set(count)


def record_dr_reconciled_erasure() -> None:
    DR_RECONCILED_ERASURES_TOTAL.inc()


def record_dr_reconciled_revocation() -> None:
    DR_RECONCILED_REVOCATIONS_TOTAL.inc()


def record_dr_drill_result(duration_seconds: float, status: str = "passed") -> None:
    DR_DRILL_DURATION_SECONDS.labels(status=status).set(duration_seconds)


def set_dr_safe_restriction_mode(active: bool) -> None:
    DR_SAFE_RESTRICTION_MODE_ACTIVE.set(1.0 if active else 0.0)


