import {
  Agent,
  ApprovalRequest,
  AuditEvent,
  CatalogSyncResult,
  DashboardSummary,
  MCPAuditEvent,
  MCPResourceDefinition,
  MCPServer,
  MCPToolDefinition,
  MemoryAuditEvent,
  MemoryPermission,
  MemoryProposal,
  MemoryRecord,
  MemoryRetentionSummary,
  PolicyRule,
  SystemHealth,
  Task,
  ThreatEvent,
  ThreatStatistics,
  KeyDetails,
  ManagedKey,
  MigrationStatus,
  SecretMetadata,
  KeyCompromiseResult,
  MonitoringOverview,
  CanaryResponse,
  SLOStatus,
  GatewayTelemetry,
  SecurityTelemetry,
  AlertsResponse,
} from "./types";

const BASE_URL = "/api/backend";

async function fetchJson<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE_URL}${endpoint}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options?.headers || {}),
    },
    cache: "no-store",
  });

  if (!res.ok) {
    let errorMsg = `API Error: ${res.status} ${res.statusText}`;
    try {
      const errData = await res.json();
      if (errData?.error?.message) {
        errorMsg = errData.error.message;
      }
    } catch {}
    throw new Error(errorMsg);
  }

  return res.json();
}

export const api = {
  // Dashboard Aggregates
  getSummary: () => fetchJson<DashboardSummary>("/dashboard/summary"),
  getThreatStatistics: () => fetchJson<ThreatStatistics>("/dashboard/threat-statistics"),
  getSystemHealth: () => fetchJson<SystemHealth>("/dashboard/system-health"),

  // Agents
  getAgents: () => fetchJson<Agent[]>("/agents"),
  getAgent: (id: string) => fetchJson<Agent>(`/agents/${id}`),
  disableAgent: (id: string) => fetchJson<Agent>(`/agents/${id}/disable`, { method: "POST" }),
  revokeAgent: (id: string) => fetchJson<Agent>(`/agents/${id}/revoke`, { method: "POST" }),

  // Tasks
  getTasks: (status?: string) => {
    const q = status ? `?status=${encodeURIComponent(status)}` : "";
    return fetchJson<Task[]>(`/tasks${q}`);
  },
  cancelTask: (id: string) => fetchJson<Task>(`/tasks/${id}/cancel`, { method: "POST" }),

  // Approvals
  getPendingApprovals: () => fetchJson<ApprovalRequest[]>("/approvals/pending"),
  approveAction: (id: string) => fetchJson<any>(`/approvals/${id}/approve`, { method: "POST" }),
  rejectAction: (id: string) => fetchJson<any>(`/approvals/${id}/reject`, { method: "POST" }),

  // Threats
  getThreatEvents: (params?: { severity?: string; threat_type?: string; limit?: number }) => {
    const sp = new URLSearchParams();
    if (params?.severity) sp.set("severity", params.severity);
    if (params?.threat_type) sp.set("threat_type", params.threat_type);
    if (params?.limit) sp.set("limit", params.limit.toString());
    const queryStr = sp.toString();
    return fetchJson<ThreatEvent[]>(`/threats/events${queryStr ? `?${queryStr}` : ""}`);
  },
  inspectThreat: (text: string) =>
    fetchJson<any>("/threats/inspect", {
      method: "POST",
      body: JSON.stringify({ text, source_type: "USER_INPUT" }),
    }),

  // Audit
  getAuditEvents: (limit = 50) => fetchJson<AuditEvent[]>(`/audit/events?limit=${limit}`),

  // Policies
  getPolicies: () => fetchJson<{ baseline_policies: PolicyRule[]; custom_rules: PolicyRule[] }>("/policies"),
  createPolicyRule: (rule: Partial<PolicyRule>) =>
    fetchJson<PolicyRule>("/policies", { method: "POST", body: JSON.stringify(rule) }),
  updatePolicyRule: (id: string, rule: Partial<PolicyRule>) =>
    fetchJson<PolicyRule>(`/policies/${id}`, { method: "PUT", body: JSON.stringify(rule) }),
  deletePolicyRule: (id: string) => fetchJson<any>(`/policies/${id}`, { method: "DELETE" }),
  evaluatePolicy: (entities: string[]) =>
    fetchJson<any>("/policies/evaluate", {
      method: "POST",
      body: JSON.stringify({ detected_entities: entities, detected_secrets: [] }),
    }),

  // Privacy Inspection & Redaction
  inspectPrivacy: (text: string) =>
    fetchJson<any>("/privacy/inspect", {
      method: "POST",
      body: JSON.stringify({ text }),
    }),
  redactPrivacy: (text: string) =>
    fetchJson<any>("/privacy/redact", {
      method: "POST",
      body: JSON.stringify({ text, reversible: true }),
    }),

  // Memory Vault
  getMemoryRecords: (params?: { category?: string; status?: string; limit?: number }) => {
    const sp = new URLSearchParams();
    if (params?.category) sp.set("category", params.category);
    if (params?.status) sp.set("status", params.status);
    if (params?.limit) sp.set("limit", params.limit.toString());
    const q = sp.toString();
    return fetchJson<MemoryRecord[]>(`/memory${q ? `?${q}` : ""}`);
  },
  getMemoryDetail: (id: string) => fetchJson<MemoryRecord>(`/memory/${id}`),
  createMemory: (key: string, value: string, category = "USER_PREFERENCES", retention_days?: number) =>
    fetchJson<MemoryRecord>("/memory", {
      method: "POST",
      body: JSON.stringify({ key, value, category, retention_days }),
    }),
  updateMemory: (id: string, new_value: string, expected_version?: number) =>
    fetchJson<MemoryRecord>(`/memory/${id}`, {
      method: "PATCH",
      body: JSON.stringify({ new_value, expected_version }),
    }),
  deleteMemory: (id: string) => fetchJson<void>(`/memory/${id}`, { method: "DELETE" }),
  revokeMemory: (id: string) => fetchJson<{ status: string }>(`/memory/${id}/revoke`, { method: "POST" }),
  getMemoryProposals: (status = "PROPOSED") =>
    fetchJson<MemoryProposal[]>(`/memory/proposals?status=${encodeURIComponent(status)}`),
  approveMemoryProposal: (id: string, retention_days?: number) =>
    fetchJson<MemoryRecord>(`/memory/proposals/${id}/approve`, {
      method: "POST",
      body: JSON.stringify({ retention_days }),
    }),
  rejectMemoryProposal: (id: string, reason = "User rejected") =>
    fetchJson<MemoryProposal>(`/memory/proposals/${id}/reject`, {
      method: "POST",
      body: JSON.stringify({ reason }),
    }),
  getMemoryPermissions: (agent_id?: string) => {
    const q = agent_id ? `?agent_id=${encodeURIComponent(agent_id)}` : "";
    return fetchJson<MemoryPermission[]>(`/memory/permissions${q}`);
  },
  grantMemoryPermission: (perm: { agent_id: string; operation: string; category?: string; memory_id?: string; ttl_seconds?: number }) =>
    fetchJson<MemoryPermission>("/memory/permissions", {
      method: "POST",
      body: JSON.stringify(perm),
    }),
  revokeMemoryPermission: (id: string) =>
    fetchJson<void>(`/memory/permissions/${id}`, { method: "DELETE" }),
  getMemoryRetention: () => fetchJson<MemoryRetentionSummary>("/memory/retention"),
  rotateMemoryKey: () => fetchJson<any>("/memory/key/rotate", { method: "POST" }),
  purgeMemoryVault: () => fetchJson<any>("/memory/purge", { method: "POST" }),
  getMemoryAudit: (limit = 50) => fetchJson<MemoryAuditEvent[]>(`/memory/audit?limit=${limit}`),

  // MCP Security Gateway
  getMCPServers: () => fetchJson<MCPServer[]>("/mcp/servers"),
  getMCPServer: (id: string) => fetchJson<MCPServer>(`/mcp/servers/${id}`),
  registerMCPServer: (server: {
    name: string;
    description?: string;
    transport_type: "streamable_http" | "stdio";
    endpoint_url?: string;
    command?: string;
    args?: string[];
    auth_type?: string;
    auth_credential_ref?: string;
  }) => fetchJson<MCPServer>("/mcp/servers", { method: "POST", body: JSON.stringify(server) }),
  syncMCPCatalog: (id: string) =>
    fetchJson<CatalogSyncResult>(`/mcp/servers/${id}/sync`, { method: "POST" }),
  approveMCPCatalog: (id: string) =>
    fetchJson<{ status: string; approved_tools_count: number }>(`/mcp/servers/${id}/approve`, {
      method: "POST",
    }),
  disableMCPServer: (id: string) =>
    fetchJson<MCPServer>(`/mcp/servers/${id}/disable`, { method: "POST" }),
  deleteMCPServer: (id: string) =>
    fetchJson<void>(`/mcp/servers/${id}`, { method: "DELETE" }),
  getMCPTools: (params?: { server_id?: string; risk_level?: string }) => {
    const sp = new URLSearchParams();
    if (params?.server_id) sp.set("server_id", params.server_id);
    if (params?.risk_level) sp.set("risk_level", params.risk_level);
    const q = sp.toString();
    return fetchJson<MCPToolDefinition[]>(`/mcp/tools${q ? `?${q}` : ""}`);
  },
  callMCPTool: (
    serverId: string,
    toolName: string,
    payload: {
      parameters?: Record<string, any>;
      agent_id?: string;
      task_id?: string;
      capability_token?: string;
      approval_id?: string;
    }
  ) =>
    fetchJson<any>(`/mcp/servers/${serverId}/tools/${encodeURIComponent(toolName)}/call`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  getMCPActivity: (params?: { server_id?: string; limit?: number }) => {
    const sp = new URLSearchParams();
    if (params?.server_id) sp.set("server_id", params.server_id);
    if (params?.limit) sp.set("limit", params.limit.toString());
    const q = sp.toString();
    return fetchJson<MCPAuditEvent[]>(`/mcp/activity${q ? `?${q}` : ""}`);
  },

  // Enterprise Governance & Fleet APIs
  getOrganizations: () =>
    fetchJson<any[]>("/organizations"),
  getOrganization: (id: string) =>
    fetchJson<any>(`/organizations/${id}`),
  getGovernanceSummary: (id: string) =>
    fetchJson<any>(`/organizations/${id}/governance-summary`),
  getOrganizationMembers: (id: string) =>
    fetchJson<any[]>(`/organizations/${id}/members`),
  inviteMember: (id: string, payload: { email: string; role: string }) =>
    fetchJson<any>(`/organizations/${id}/members/invite`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  getWorkspaces: (orgId: string) =>
    fetchJson<any[]>(`/organizations/${orgId}/workspaces`),
  createWorkspace: (orgId: string, payload: { name: string; slug?: string; description?: string }) =>
    fetchJson<any>(`/organizations/${orgId}/workspaces`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  getOrganizationPolicies: (orgId: string) =>
    fetchJson<any[]>(`/organizations/${orgId}/policies`),
  createPolicyBundle: (orgId: string, payload: { rules: any[]; workspace_id?: string }) =>
    fetchJson<any>(`/organizations/${orgId}/policies`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  deployPolicyBundle: (orgId: string, bundleId: string, rolloutStage: string = "ORG_WIDE") =>
    fetchJson<any>(`/organizations/${orgId}/policies/${bundleId}/deploy`, {
      method: "POST",
      body: JSON.stringify({ rollout_stage: rolloutStage }),
    }),
  rollbackPolicyBundle: (orgId: string, bundleId: string) =>
    fetchJson<any>(`/organizations/${orgId}/policies/${bundleId}/rollback`, {
      method: "POST",
    }),
  getFleet: (orgId: string) =>
    fetchJson<any[]>(`/organizations/${orgId}/fleet`),
  revokeFleetResource: (orgId: string, resourceId: string, reason: string = "Administrative revocation") =>
    fetchJson<any>(`/organizations/${orgId}/fleet/${resourceId}/revoke`, {
      method: "POST",
      body: JSON.stringify({ reason }),
    }),
  getPolicySyncStatus: (orgId: string) =>
    fetchJson<any>(`/organizations/${orgId}/policy-sync`),
  getEnterpriseAuditTrail: (orgId: string, limit: number = 50) =>
    fetchJson<any[]>(`/organizations/${orgId}/audit?limit=${limit}`),
  verifyAuditIntegrity: (orgId: string) =>
    fetchJson<{ is_valid: boolean; violations_detected: number; details: string[] }>(
      `/organizations/${orgId}/audit/verify-integrity`
    ),
  exportAuditToSIEM: (orgId: string, destinationUrl: string) =>
    fetchJson<any>(`/organizations/${orgId}/audit/export`, {
      method: "POST",
      body: JSON.stringify({ destination_url: destinationUrl, destination_type: "SIEM_WEBHOOK" }),
    }),

  // Stage 10.5 — Key & Secret Lifecycle Management
  getKeys: () => fetchJson<ManagedKey[]>("/keys"),
  getKey: (keyId: string) => fetchJson<KeyDetails>(`/keys/${keyId}`),
  registerKey: (data: any) =>
    fetchJson<ManagedKey>("/keys", {
      method: "POST",
      body: JSON.stringify(data),
    }),
  rotateKey: (keyId: string) =>
    fetchJson<any>(`/keys/${keyId}/rotate`, {
      method: "POST",
    }),
  verifyKey: (keyId: string) =>
    fetchJson<any>(`/keys/${keyId}/verify`, {
      method: "POST",
    }),
  getMigrationStatus: () => fetchJson<MigrationStatus>("/keys/migration/status"),
  startMigration: (batchSize: number = 50) =>
    fetchJson<any>("/keys/migration/start", {
      method: "POST",
      body: JSON.stringify({ batch_size: batchSize }),
    }),
  getSecrets: () => fetchJson<SecretMetadata[]>("/secrets"),
  registerSecret: (data: any) =>
    fetchJson<SecretMetadata>("/secrets", {
      method: "POST",
      body: JSON.stringify(data),
    }),
  rotateSecret: (secretId: string) =>
    fetchJson<any>(`/secrets/${secretId}/rotate`, {
      method: "POST",
    }),
  revokeSecret: (secretId: string) =>
    fetchJson<any>(`/secrets/${secretId}/revoke`, {
      method: "POST",
    }),
  reportCompromise: (data: any) =>
    fetchJson<KeyCompromiseResult>("/incidents/compromise", {
      method: "POST",
      body: JSON.stringify(data),
    }),

  // Observability & Telemetry APIs (Stage 10.6)
  getMonitoringOverview: () => fetchJson<MonitoringOverview>("/monitoring/overview"),
  getCanaries: (autoRun: boolean = false) => fetchJson<CanaryResponse>(`/monitoring/canaries?auto_run=${autoRun}`),
  runCanaries: () =>
    fetchJson<CanaryResponse>("/monitoring/canaries/run", {
      method: "POST",
    }),
  getSLOs: () => fetchJson<Record<string, SLOStatus>>("/monitoring/slos"),
  getGatewayTelemetry: () => fetchJson<GatewayTelemetry>("/monitoring/gateway"),
  getSecurityTelemetry: () => fetchJson<SecurityTelemetry>("/monitoring/security"),
  getActiveAlerts: () => fetchJson<AlertsResponse>("/monitoring/alerts"),
};

