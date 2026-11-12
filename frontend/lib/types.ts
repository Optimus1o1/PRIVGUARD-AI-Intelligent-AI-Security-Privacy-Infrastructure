/** TypeScript interfaces for PRIVGUARD Control Center */

export type SecurityStatus = "PROTECTED" | "ATTENTION_REQUIRED" | "CRITICAL_ALERT" | "SYSTEM_UNAVAILABLE";

export interface DashboardSummary {
  security_status: SecurityStatus;
  protection_score: number;
  total_requests: number;
  blocked_requests: number;
  pii_redactions: number;
  threats_detected: number;
  critical_threats: number;
  active_agents: number;
  running_tasks: number;
  pending_approvals: number;
  last_updated: string;
}

export interface ThreatStatistics {
  by_severity: {
    CRITICAL: number;
    HIGH: number;
    MEDIUM: number;
    LOW: number;
  };
  by_type: Record<string, number>;
  recent_timeline: Array<{
    date: string;
    requests: number;
    threats: number;
  }>;
}

export interface ComponentHealth {
  name: string;
  status: "OPERATIONAL" | "DEGRADED" | "DOWN" | string;
  latency_ms: number;
  description: string;
}

export interface SystemHealth {
  overall_status: string;
  overall_latency_ms: number;
  components: ComponentHealth[];
  last_check: string;
  // Dynamic status mappings for UI cards
  gateway_status?: string;
  privacy_engine_status?: string;
  agent_broker_status?: string;
  threat_detector_status?: string;
  database_status?: string;
  latencies_ms?: Record<string, number>;
  status?: string;
}

export interface Agent {
  id: string;
  name: string;
  description?: string;
  status: "ACTIVE" | "DISABLED" | "REVOKED";
  allowed_tools: string[];
  created_at: string;
  last_activity_at: string;
}

export interface Task {
  id: string;
  agent_id: string;
  status: "CREATED" | "RUNNING" | "WAITING_FOR_APPROVAL" | "COMPLETED" | "FAILED" | "CANCELLED" | "EXPIRED";
  description?: string;
  created_at: string;
  expires_at: string;
  completed_at?: string;
  is_tainted?: boolean;
  taint_reasons?: string[];
  context_summary?: Record<string, any>;
}

export interface ApprovalRequest {
  id: string;
  task_id: string;
  agent_id: string;
  tool_name: string;
  target_resource?: string;
  action_parameters: Record<string, any>;
  action_hash: string;
  risk_level: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  status: "PENDING" | "APPROVED" | "REJECTED" | "EXPIRED" | "CONSUMED";
  created_at: string;
  expires_at: string;
}

export interface ThreatEvent {
  id: string;
  application_id: string;
  task_id?: string;
  agent_id?: string;
  threat_type: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | string;
  confidence: number;
  rule_id: string;
  action_taken: string;
  content_hash: string;
  created_at: string;
  content_fingerprint?: string;
  source_type?: string;
  indicators?: Record<string, any>;
}

export interface AuditEvent {
  id: string;
  request_id: string;
  event_type: string;
  data_category?: string;
  action_taken: string;
  risk_level: string;
  entity_counts?: string | Record<string, any>;
  content_fingerprint?: string;
  status: string;
  timestamp: string;
  created_at?: string;
  processing_time_ms?: number;
  metadata?: Record<string, any>;
}

export interface PolicyRule {
  id: string;
  name?: string;
  category: string;
  action: string;
  severity?: string;
  risk_level?: string;
  description?: string;
  is_baseline?: boolean;
  is_enabled?: boolean;
  enabled?: boolean;
}

export interface MemoryRecord {
  id: string;
  category: string;
  status: "ACTIVE" | "REVOKED" | "EXPIRED" | "DELETED" | "QUARANTINED";
  provenance: "USER_CONFIRMED" | "AI_PROPOSED" | "EXTERNALLY_SOURCED" | "SYSTEM_GENERATED";
  summary?: string;
  version: number;
  created_at: string;
  updated_at: string;
  expires_at?: string;
  retention_days?: number;
  content_fingerprint: string;
  value?: string;
}

export interface MemoryProposal {
  id: string;
  app_id: string;
  owner_id: string;
  agent_id?: string;
  task_id?: string;
  proposed_key: string;
  proposed_value: string;
  category: string;
  status: "PROPOSED" | "PENDING_APPROVAL" | "APPROVED" | "REJECTED" | "EXPIRED";
  threat_assessment: Record<string, any>;
  risk_level: string;
  created_at: string;
  expires_at?: string;
}

export interface MemoryPermission {
  id: string;
  agent_id: string;
  operation: string;
  category?: string;
  memory_id?: string;
  is_granted: boolean;
  created_at: string;
  expires_at?: string;
}

export interface MemoryAuditEvent {
  id: string;
  memory_id?: string;
  agent_id?: string;
  operation: string;
  action_taken: string;
  status: string;
  timestamp: string;
}

export interface MemoryRetentionSummary {
  active_count: number;
  expired_count: number;
  revoked_count: number;
  quarantined_count: number;
  pending_proposals: number;
  categories_breakdown: Record<string, number>;
}

export interface MCPServer {
  id: string;
  name: string;
  description?: string;
  transport_type: "streamable_http" | "stdio";
  endpoint_url?: string;
  command?: string;
  args?: string[];
  status: "ACTIVE" | "DISABLED" | "DISCONNECTED" | "QUARANTINED" | "REQUIRES_REAPPROVAL";
  trust_level: "VERIFIED" | "SANDBOXED" | "UNTRUSTED" | string;
  catalog_fingerprint?: string;
  auth_type: string;
  last_connected_at?: string;
  created_at: string;
  updated_at: string;
}

export interface MCPToolDefinition {
  id: string;
  server_id: string;
  name: string;
  description?: string;
  input_schema: Record<string, any>;
  risk_level: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  requires_approval: boolean;
  is_approved: boolean;
  version: number;
  definition_hash: string;
  created_at: string;
}

export interface MCPResourceDefinition {
  id: string;
  server_id: string;
  uri: string;
  name: string;
  description?: string;
  mime_type?: string;
  risk_level: string;
  created_at: string;
}

export interface MCPAuditEvent {
  id: string;
  server_id?: string;
  agent_id?: string;
  tool_name?: string;
  action: string;
  status: string;
  details: Record<string, any>;
  timestamp: string;
}

export interface CatalogSyncResult {
  server_id: string;
  server_status: string;
  new_tools: number;
  updated_tools: number;
  drift_detected: boolean;
  catalog_fingerprint?: string;
}


// ==============================================================================
// Stage 10.5 — Key Management & Secrets Lifecycle Types
// ==============================================================================

export interface ManagedKey {
  id: string;
  tenant_id: string;
  name: string;
  purpose: string;
  provider: string;
  algorithm: string;
  status: string;
  active_version_id?: string;
  last_rotated_at: string;
  created_at: string;
}

export interface KeyVersion {
  id: string;
  version_num: number;
  provider_version_id?: string;
  status: string;
  has_public_key: boolean;
  created_at: string;
}

export interface KeyDetails {
  key: ManagedKey;
  versions: KeyVersion[];
}

export interface MigrationStatus {
  unmigrated_records: number;
  can_retire_legacy_key: boolean;
  retirement_check_reason: string;
  latest_job: {
    id: string;
    status: string;
    records_total: number;
    records_migrated: number;
  } | null;
}

export interface SecretMetadata {
  id: string;
  tenant_id: string;
  name: string;
  secret_type: string;
  version: number;
  status: string;
  expires_at?: string;
  created_at: string;
  last_rotated_at: string;
}

export interface KeyCompromiseResult {
  status: string;
  incident_type: string;
  action?: string;
  key_id?: string;
  memory_id?: string;
  rotation_job_id?: string;
  records_to_rewrap?: number;
  timestamp: string;
  notes?: string;
}


// ==============================================================================
// Observability & Telemetry Types (Stage 10.6)
// ==============================================================================

export interface CanaryResult {
  canary_name: string;
  passed: boolean;
  latency_ms: number;
  message: string;
  timestamp: string;
  severity: "critical" | "high" | "medium" | "low";
  details?: Record<string, any>;
}

export interface CanarySummary {
  total_canaries: number;
  executed: number;
  passed: number;
  failed: number;
  healthy: boolean;
  last_run_timestamp: string | null;
}

export interface CanaryResponse {
  summary: CanarySummary;
  canaries: CanaryResult[];
}

export interface SLOStatus {
  name: string;
  target: number;
  current_ratio: number;
  error_budget_remaining: number;
  burn_rate: number;
  healthy: boolean;
  total_events: number;
  bad_events: number;
}

export interface MonitoringOverview {
  status: "nominal" | "degraded";
  service: string;
  version: string;
  environment: string;
  canary_summary: CanarySummary;
  slos: Record<string, SLOStatus>;
  active_alerts_count: number;
}

export interface GatewayTelemetry {
  p95_latency_ms: number;
  p99_latency_ms: number;
  requests_24h: number;
  blocked_requests_24h: number;
  provider_breakdown: Record<string, { requests: number; error_rate: number }>;
}

export interface SecurityTelemetry {
  threat_detections_total: number;
  prompt_injections_blocked: number;
  secrets_blocked: number;
  pii_entities_redacted: number;
  unauthorized_tool_calls_blocked: number;
  quarantined_agents_count: number;
}

export interface AlertItem {
  alertname: string;
  severity: string;
  description: string;
  status: string;
}

export interface AlertsResponse {
  firing_alerts: AlertItem[];
  total_firing: number;
}

// =============================================================================
// Compliance Evidence Engine (Stage 10.9)
// =============================================================================

export interface ComplianceRequirement {
  id: string;
  framework_id: string;
  identifier: string;
  title: string;
  description: string;
  domain: string;
  commencement_status: "COMMENCED" | "PENDING_COMMENCEMENT" | "EXEMPTED";
  commencement_date?: string;
  phase_category?: string;
  mandatory: boolean;
}

export interface ComplianceFramework {
  id: string;
  name: string;
  version: string;
  jurisdiction: string;
  authority: string;
  description: string;
  official_reference: string;
  status: string;
  commenced_at?: string;
  total_requirements: number;
  commenced_requirements: number;
  mapped_requirements: number;
  requirements?: ComplianceRequirement[];
}

export interface ComplianceControlMapping {
  id: string;
  control_id: string;
  requirement_id: string;
  mapping_type: "DIRECT" | "PARTIAL" | "SUPPORTING" | "NOT_MAPPED";
  rationale: string;
  coverage_score: number;
}

export interface ComplianceControl {
  id: string;
  title: string;
  domain: string;
  description: string;
  owner_role: string;
  verification_method: string;
  review_frequency_days: number;
  criticality: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  version: string;
  implementation_status: "IMPLEMENTED" | "PARTIALLY_IMPLEMENTED" | "NOT_IMPLEMENTED" | "NOT_ASSESSED" | "NOT_APPLICABLE";
  active: boolean;
  mappings?: ComplianceControlMapping[];
  latest_evidence?: {
    id: string;
    collector_name: string;
    artifact_hash_sha256: string;
    verification_status: string;
    freshness_status: string;
    assurance_status: string;
    collected_at: string;
    expires_at: string;
    details: Record<string, any>;
  };
  current_assurance?: "HIGH" | "MEDIUM" | "LOW" | "INSUFFICIENT";
}

export interface ComplianceEvidenceRecord {
  id: string;
  tenant_id: string;
  control_id: string;
  collector_name: string;
  artifact_type: string;
  artifact_hash_sha256: string;
  artifact_payload: Record<string, any>;
  verification_status: "VERIFIED" | "FAILED" | "UNKNOWN" | "REQUIRES_REVIEW";
  freshness_status: "CURRENT" | "STALE" | "EXPIRED";
  assurance_status: "HIGH" | "MEDIUM" | "LOW" | "INSUFFICIENT";
  collected_at: string;
  expires_at: string;
  signing_kid?: string;
  signature_hex?: string;
}

export interface ComplianceGapItem {
  gap_type: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  requirement_id?: string;
  control_id?: string;
  title: string;
  description: string;
  remediation_action: string;
}

export interface ComplianceGapAnalysis {
  tenant_id: string;
  evaluated_at: string;
  total_gaps: number;
  critical_gaps: number;
  high_gaps: number;
  medium_gaps: number;
  low_gaps: number;
  items: ComplianceGapItem[];
}

export interface ComplianceApplicabilityRecord {
  id: string;
  tenant_id: string;
  framework_id: string;
  requirement_id?: string;
  decision: "APPLICABLE" | "NOT_APPLICABLE" | "REQUIRES_REVIEW";
  role: "DATA_FIDUCIARY" | "DATA_PROCESSOR" | "AI_DEPLOYER" | "AI_PROVIDER" | "CONTROLLER";
  justification: string;
  reviewed_by: string;
  reviewed_at: string;
}

export interface CompliancePublicKey {
  kid: string;
  algorithm: string;
  purpose: string;
  public_key_hex: string;
  public_key_pem: string;
  fingerprint_sha256: string;
  status: string;
}

export interface ComplianceExportResponse {
  export_id: string;
  tenant_id: string;
  framework_id?: string;
  export_format: "ZIP" | "JSON" | "CSV";
  manifest_hash_sha256: string;
  signing_kid: string;
  signature_hex: string;
  artifact_count: number;
  package_size_bytes: number;
  download_url: string;
  created_at: string;
}
