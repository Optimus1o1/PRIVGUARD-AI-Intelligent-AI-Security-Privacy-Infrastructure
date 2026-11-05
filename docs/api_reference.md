# PRIVGUARD AI — API Reference (v0.1)

**Moon Sanctum Labs** — *Decode. Build. Evolve.*

## Base URL
Default local endpoint: `http://127.0.0.1:8000`

## Authentication
All protected endpoints require an Application API key supplied in one of two formats:
- Header: `X-API-Key: <YOUR_API_KEY>`
- Header: `Authorization: Bearer <YOUR_API_KEY>`

---

## Endpoints

### 1. Health & Liveness
- `GET /health`
  Returns service health and version.
- `GET /ready`
  Returns operational status and fail-closed flags.

### 2. OpenAI-Compatible Chat Gateway
- `POST /v1/chat/completions`
  Drop-in replacement for OpenAI `/v1/chat/completions`.
  **Request:** Standard OpenAI payload (`model`, `messages`, `temperature`, `max_tokens`, `stream: bool`).
  **Behavior:**
  - **Prompt Inspection:** Blocks with HTTP 403 `CRITICAL_SECRET_DETECTED` if credentials are in messages.
  - **PII Minimization:** Redacts PII (emails, phone numbers, SSNs, credit cards) into tokens (`<EMAIL_1>`).
  - **Live Upstream Routing:** Forwards sanitized messages to server-configured model provider.
  - **Response Security Inspection:** Inspects model output before transmission. If model leaks credentials, blocks with HTTP 502 `RESPONSE_SECURITY_VIOLATION`.
  - **PII Restoration:** Restores authorized placeholders (`<EMAIL_1>`) for authorized clients.
  - **Streaming Mode (`stream: true`):**
    - Enforces Buffer-Before-Stream: Buffers upstream SSE events, inspects entire response, and emits compliant OpenAI SSE chunks (`data: {...}`, `finish_reason: "stop"`, `data: [DONE]`).
    - Media Type: `text/event-stream`.
  - **Non-Streaming Mode (`stream: false`):**
    - Returns JSON `ChatCompletionResponse` with `privguard_meta` (audit ID, tokens restored, latency).

**Error Responses:**
- `400 Bad Request`: `MODEL_NOT_CONFIGURED` (SSRF prevention)
- `401 Unauthorized`: `AUTHENTICATION_FAILED` (missing or invalid client key)
- `403 Forbidden`: `CRITICAL_SECRET_DETECTED` (secret in input prompt)
- `429 Too Many Requests`: `UPSTREAM_RATE_LIMITED`
- `502 Bad Gateway`: `RESPONSE_SECURITY_VIOLATION` (model generated secrets) or `UPSTREAM_PROVIDER_ERROR`
- `504 Gateway Timeout`: `UPSTREAM_TIMEOUT` (upstream provider exceeded timeout)

### 3. Privacy Inspection
- `POST /v1/privacy/inspect`
  Inspects raw text for sensitive credentials and PII.
  **Response:**
  ```json
  {
    "category": "PERSONAL",
    "risk_level": "MEDIUM",
    "action": "REDACT",
    "is_blocked": false,
    "blocking_reason": null,
    "detected_secrets": [],
    "detected_pii": [{"type": "EMAIL", "start": 18, "end": 36}],
    "entity_counts": {"EMAIL": 1},
    "content_fingerprint": "a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447"
  }
  ```

- `POST /v1/privacy/redact`
  Redacts text directly and returns pseudonymization mapping.

### 4. Policies
- `GET /v1/policies`
  Lists active baseline and custom application rules.
- `POST /v1/policies/evaluate`
  Simulates policy engine evaluation for a given entity set.

### 5. Audit & Monitoring
- `GET /v1/audit/events`
  Retrieves content-free audit trail events.
  **Query Parameters:** `event_type`, `limit` (1-200), `offset`.

### 6. Agent Identity & Registration
- `POST /v1/agents/register`
  Registers a new agent bound to the authenticated application.
  Body: `{"name": "...", "description": "...", "allowed_tools": ["read_file", "search_web"]}`
- `GET /v1/agents`
  Lists all registered agents belonging to caller application.
- `GET /v1/agents/{agent_id}`
  Retrieves agent details.
- `POST /v1/agents/{agent_id}/disable`
  Disables agent, blocking all further tool executions.
- `POST /v1/agents/{agent_id}/revoke`
  Permanently revokes agent.

### 7. Task Management
- `POST /v1/tasks`
  Initializes a task session. Body: `{"agent_id": "...", "description": "...", "ttl_seconds": 600}`
- `GET /v1/tasks/{task_id}`
  Retrieves task session status.
- `POST /v1/tasks/{task_id}/cancel`
  Cancels task and auto-revokes all associated capability grants.

### 8. Temporary Capabilities
- `POST /v1/capabilities/request`
  Requests a task-scoped capability token.
  Body: `{"agent_id": "...", "task_id": "...", "tool_name": "...", "resource": "...", "max_uses": 1, "ttl_seconds": 300}`
  Returns: One-time opaque `capability_token` (`pg_cap_...`).
- `POST /v1/capabilities/{capability_id}/revoke`
  Instantly revokes capability.

### 9. Human-in-the-Loop Approvals
- `GET /v1/approvals/pending`
  Lists pending approval requests.
- `POST /v1/approvals/{approval_id}/approve`
  Grants human authorization for the exact proposed action.
- `POST /v1/approvals/{approval_id}/reject`
  Rejects proposed action.

### 10. Controlled Tool Execution Broker
- `GET /v1/tools`
  Lists registered tools with schemas and risk classifications.
- `POST /v1/tools/{tool_name}/execute`
  Executes a registered tool through the broker.
  Body: `{"agent_id": "...", "task_id": "...", "capability_token": "...", "parameters": {...}, "approval_id": "..."}`
  Enforces identity, tool allowlist, schema, sandboxing, capability consumption, behavioral monitoring, taint tracking, and human approvals.

### 11. Threat Detection & Defense
- `POST /v1/threats/inspect`
  Inspects arbitrary text or untrusted documents for prompt injection, hidden CSS directives, and active scripts.
  Body: `{"text": "...", "source_type": "USER_INPUT"}`
  Returns: `{"assessment": {...}, "trust_level": "UNTRUSTED", "sanitized_content": "...", "is_quarantined": false}`
- `POST /v1/threats/evaluate-behavior`
  Evaluates the sliding-window tool invocation sequence for an active task.
  Body: `{"task_id": "..."}`
  Returns: `ThreatAssessment` with anomalies, risk score, and recommended action.
- `GET /v1/threats/taints/{task_id}`
  Queries active data taint propagation status on an autonomous task.
  Returns: `{"task_id": "...", "is_tainted": true, "tainted_resources": ["..."]}`
- `GET /v1/threats/events`
  Retrieves content-free audit records of threat signals and defense interventions.
  Query params: `limit`, `offset`, `severity`, `threat_type`.

### 12. Dashboard & Telemetry Aggregation
- `GET /v1/dashboard/summary`
  Aggregates real-time security posture KPIs directly from the SQLite database:
  Returns: `{"security_status": "PROTECTED", "protection_score": 98.5, "total_requests": 1420, "blocked_requests": 18, "pii_redactions": 112, "threats_detected": 14, "critical_threats": 2, "active_agents": 4, "running_tasks": 3, "pending_approvals": 1, "last_updated": "..."}`
- `GET /v1/dashboard/threat-statistics`
  Returns aggregated threat distribution by severity, by threat type, and historical 7-day request/threat volume buckets.
- `GET /v1/dashboard/system-health`
  Returns sub-millisecond execution probe latencies and operational statuses for AI Gateway, Privacy Engine, Agent Broker, Threat Detector, and SQLite WAL database.
- `GET /v1/tasks`
  Lists task sessions with optional filtering by status (`RUNNING`, `WAITING_FOR_APPROVAL`, `COMPLETED`, `CANCELLED`) and agent ID.
- `POST /v1/policies`, `PUT /v1/policies/{rule_id}`, `DELETE /v1/policies/{rule_id}`
  Manage custom policy rules with audit logging and protection against invariant violations (e.g. blocking attempts to set `CRITICAL` severity to `ALLOW`).

### 13. Personal AI Memory Vault
- `POST /v1/memory/proposals`
  Agent submits a candidate memory proposal awaiting human consent.
  Body: `{"proposed_key": "...", "proposed_value": "...", "category": "...", "agent_id": "...", "task_id": "...", "ttl_seconds": 86400}`
- `GET /v1/memory/proposals`
  Lists pending candidate proposals for user review and consent (`status=PROPOSED`).
- `POST /v1/memory/proposals/{proposal_id}/approve`
  User approves proposal, triggering AES-256-GCM envelope encryption into active memory.
  Body: `{"retention_days": 30}` (optional)
- `POST /v1/memory/proposals/{proposal_id}/reject`
  User permanently rejects proposal.
  Body: `{"reason": "User rejected"}`
- `POST /v1/memory`
  User directly creates and encrypts a verified memory entry.
  Body: `{"key": "...", "value": "...", "category": "USER_PREFERENCES", "retention_days": 90}`
- `GET /v1/memory`
  Lists memory records in vault (metadata only, zero plaintext).
  Query params: `category`, `status`, `limit`, `offset`.
- `GET /v1/memory/{memory_id}`
  Retrieves and decrypts a specific personal memory entry using user KEK and record DEK.
- `PATCH /v1/memory/{memory_id}`
  Updates memory content with optimistic concurrency control (CAS).
  Body: `{"new_value": "...", "expected_version": 1}`
- `DELETE /v1/memory/{memory_id}`
  Cryptographically erases memory (overwrites DEK and ciphertext with erasure markers).
- `POST /v1/memory/{memory_id}/revoke`
  Soft-revokes memory, immediately excluding it from active query retrieval.
- `POST /v1/memory/retrieve`
  Privacy-preserving bounded retrieval for active agent tasks or user queries.
  Body: `{"agent_id": "...", "task_id": "...", "capability_token": "...", "query": "...", "categories": [...], "limit": 5}`
- `POST /v1/memory/permissions`
  Grants granular memory operation permission to an agent.
  Body: `{"agent_id": "...", "operation": "memory.read", "category": "...", "ttl_seconds": 86400}`
- `GET /v1/memory/permissions`
  Lists active agent memory permissions.
- `DELETE /v1/memory/permissions/{permission_id}`
  Revokes an agent memory permission.
- `POST /v1/memory/key/rotate`
  Rotates user Key Encryption Key (KEK) and re-wraps active DEKs in $O(1)$ time.
- `POST /v1/memory/purge`
  Executes permanent cryptographic purge of all user personal memories (Right to be Forgotten).
- `GET /v1/memory/retention`
  Returns retention metrics, status breakdown, and category counts.
- `GET /v1/memory/audit`
  Returns content-free memory vault audit trail.

### 14. Model Context Protocol (MCP) Security Gateway
- `POST /v1/mcp/servers`
  Registers an upstream MCP server after strict destination SSRF or stdio command validation.
  Body: `{"name": "...", "transport_type": "streamable_http|stdio", "endpoint_url": "...", "command": "...", "args": [...], "auth_type": "..."}`
- `GET /v1/mcp/servers`
  Lists registered upstream MCP servers and their trust status.
- `GET /v1/mcp/servers/{server_id}`
  Retrieves detailed server status, catalog fingerprint, and connection metadata.
- `POST /v1/mcp/servers/{server_id}/sync`
  Discovers upstream tool catalog, executes prompt injection & imperative smuggling scan, and detects catalog drift.
- `POST /v1/mcp/servers/{server_id}/approve`
  Human administrator approves drifted catalog, lifting quarantine (`REQUIRES_REAPPROVAL`).
- `POST /v1/mcp/servers/{server_id}/disable`
  Disables an MCP server, blocking all subsequent tool execution attempts.
- `DELETE /v1/mcp/servers/{server_id}`
  Removes server registration and purges its tool and resource definitions.
- `GET /v1/mcp/tools`
  Lists discovered tools with optional filters: `server_id`, `risk_level`.
- `POST /v1/mcp/servers/{server_id}/tools/{tool_name}/call`
  Executes a tool through PRIVGUARD's 9-step mediation proxy (validating drift, parameters, capability tokens, human approvals, and output response security).
  Body: `{"parameters": {...}, "agent_id": "...", "task_id": "...", "capability_token": "...", "approval_id": "..."}`
- `GET /v1/mcp/activity`
  Retrieves content-free audit trail of MCP tool calls, catalog syncs, and security blocks.
- `POST /mcp`
  2026-07-28 Protected MCP Server Facade. Standard Streamable HTTP JSON-RPC 2.0 endpoint for AI applications.
  Headers: `mcp-version: 2026-07-28`, `mcp-method: tools/list|tools/call|resources/list|resources/read`, `mcp-name: <tool_name>`.

### 15. Enterprise Multi-Tenancy & Governance
- `POST /v1/organizations`
  Creates a new isolated organization tenant with default workspace and admin role assignment.
  Body: `{"name": "...", "slug": "...", "tier": "ENTERPRISE"}`
- `GET /v1/organizations/{org_id}`
  Retrieves organization metadata, subscription tier, and governance summary.
- `GET /v1/organizations/{org_id}/members`
  Lists organization members with their RBAC role mappings.
- `POST /v1/organizations/{org_id}/members/invite`
  Issues a cryptographically signed email invitation for organization membership.
  Body: `{"email": "...", "role": "DEVELOPER", "workspace_ids": [...]}`
- `POST /v1/organizations/{org_id}/domain/verify`
  Generates or validates DNS TXT verification token for SSO auto-provisioning domain claim.

### 16. Departmental Workspaces
- `POST /v1/organizations/{org_id}/workspaces`
  Creates an isolated departmental workspace within the organization boundary.
  Body: `{"name": "Engineering", "description": "...", "data_boundary_strict": true}`
- `GET /v1/organizations/{org_id}/workspaces`
  Lists departmental workspaces accessible to the authenticated caller.
- `GET /v1/organizations/{org_id}/workspaces/{workspace_id}`
  Retrieves workspace details, assigned members, and active agent count.

### 17. Ed25519 Cryptographic Policy Governance
- `GET /v1/organizations/{org_id}/policies/bundles`
  Lists active and historical policy bundles for the organization.
- `POST /v1/organizations/{org_id}/policies/bundles`
  Authors, validates, canonicalizes, and Ed25519-signs a new monotonically-versioned policy bundle.
  Body: `{"name": "...", "version": 2, "rules": [...], "target_workspaces": [...]}`
- `POST /v1/organizations/{org_id}/policies/bundles/{bundle_id}/rollback`
  Executes an audited, cryptographically verified rollback to a prior valid policy bundle.
  Body: `{"reason": "...", "target_bundle_id": "..."}`
- `GET /v1/organizations/{org_id}/policies/effective`
  Resolves deterministic 5-layer effective policy hierarchy (Platform -> Org -> Workspace -> Agent -> Task).

### 18. Fleet Management & Policy Synchronization
- `GET /v1/organizations/{org_id}/fleet`
  Returns central fleet inventory across registered agents and MCP servers with drift and health metrics.
- `POST /v1/organizations/{org_id}/fleet/register`
  Registers a new fleet agent or MCP host with ephemeral or permanent registration token.
- `POST /v1/organizations/{org_id}/fleet/{resource_id}/heartbeat`
  Processes heartbeat from fleet agent, returning policy bundle hash, sync status, and active killswitch commands.
- `POST /v1/organizations/{org_id}/fleet/{resource_id}/sync`
  Fetches full Ed25519-signed policy bundle for local agent verification and enforcement.
- `POST /v1/organizations/{org_id}/fleet/{resource_id}/revoke`
  Executes central authoritative broker-side revocation, immediately disabling agent/server execution.

### 19. SCIM 2.0 Identity Provisioning
- `GET /v1/scim/v2/Users`
  SCIM 2.0 user directory query endpoint for IdPs (Okta, Entra ID, Ping).
- `POST /v1/scim/v2/Users`
  Provisions a new user from IdP with auto-role mapping based on SCIM groups.
- `PATCH /v1/scim/v2/Users/{user_id}`
  Applies incremental user attribute updates or suspends user access.
- `DELETE /v1/scim/v2/Users/{user_id}`
  Deprovisions user, immediately revoking active sessions, approvals, and capability tokens.

### 20. Tamper-Evident Audit Ledger & SIEM Export
- `GET /v1/organizations/{org_id}/audit/ledger`
  Retrieves sequential SHA-256 hash-chained enterprise audit ledger records.
- `POST /v1/organizations/{org_id}/audit/verify`
  Scans full audit ledger and cryptographically verifies hash-chain integrity from genesis.
- `POST /v1/organizations/{org_id}/audit/export`
  Dispatches tamper-evident audit records to external SIEM destination (Splunk, Datadog, Webhook) with SSRF loopback defense.





