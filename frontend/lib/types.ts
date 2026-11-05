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
