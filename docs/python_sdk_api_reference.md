# PRIVGUARD AI — Python SDK Complete API Reference

**Organization**: Moon Sanctum Labs  
**Motto**: Decode. Build. Evolve.  
**Package**: `privguard-sdk` (import: `privguard_sdk`)  
**Specification Version**: 1.0.0 (SDK Version: 0.1.0)  

---

## 1. Client Classes & Initialization

```python
from privguard_sdk import PrivGuardClient, AsyncPrivGuardClient, PrivGuardConfig
```

### `PrivGuardClient` / `AsyncPrivGuardClient`

```python
PrivGuardClient(
    base_url: str | None = None,
    api_key: str | None = None,
    tenant_id: str | None = None,
    user_id: str | None = None,
    workspace_id: str | None = None,
    timeout: float | httpx.Timeout = 30.0,
    max_retries: int = 3,
    verify_ssl: bool = True,
    config: PrivGuardConfig | None = None,
)
```

Provides context manager support:
- `with PrivGuardClient(...) as client:` (closes underlying HTTP pool on exit)
- `async with AsyncPrivGuardClient(...) as client:` (closes async HTTP pool on exit)

---

## 2. Resource Reference

### 2.1 `health` Namespace

#### `client.health.check() -> HealthCheckResponse`
Performs service health and subsystem readiness check.
- **Returns**: `HealthCheckResponse(status="healthy", version="...", timestamp="...", components={...})`

---

### 2.2 `gateway` Namespace

#### `client.gateway.chat(...) -> ChatCompletionResponse`
Sends a chat completion request through PRIVGUARD AI's privacy and threat analysis gateway.
- **Parameters**:
  - `model: str` — Upstream LLM model identifier (e.g. `"gpt-4o"`).
  - `messages: list[ChatMessage | dict[str, str]]` — List of chat messages with `"role"` and `"content"`.
  - `temperature: float | None` — Sampling temperature (default: `1.0`).
  - `max_tokens: int | None` — Maximum tokens to generate.
  - `stream: bool` — Must be `False` (for streaming, use `stream()`).
- **Returns**: `ChatCompletionResponse(id="...", model="...", choices=[...], usage=...)`

#### `client.gateway.stream(...) -> Iterator[ChatCompletionChunk]` (Sync) / `AsyncIterator[ChatCompletionChunk]` (Async)
Streams chat completion tokens in real-time via Server-Sent Events (SSE).
- **Parameters**: Identical to `chat()` with `stream=True`.
- **Yields**: `ChatCompletionChunk(id="...", choices=[ChatCompletionChunkChoice(...)])`

---

### 2.3 `privacy` Namespace

#### `client.privacy.analyze(text: str, language: str = "en") -> PrivacyAnalyzeResponse`
Scans raw text for sensitive PII/PHI entities (e.g. names, email addresses, credit cards, Aadhaar, SSN).
- **Returns**: `PrivacyAnalyzeResponse(entities=[PIIEntity(...)], risk_score=0.15)`

#### `client.privacy.anonymize(text: str, mask_token: str = "[REDACTED]") -> PrivacyAnonymizeResponse`
Replaces detected sensitive entities with consistent cryptographic pseudonyms or redaction tokens.
- **Returns**: `PrivacyAnonymizeResponse(anonymized_text="...", mapping_id="map_123")`

#### `client.privacy.deanonymize(text: str, mapping_id: str) -> PrivacyDeanonymizeResponse`
Reverses tokenized pseudonyms back to original values using the temporary mapping table.
- **Returns**: `PrivacyDeanonymizeResponse(original_text="...")`

---

### 2.4 `threats` Namespace

#### `client.threats.scan(prompt: str, context: dict[str, Any] | None = None) -> ThreatScanResponse`
Evaluates text for adversarial prompt injections, jailbreaks, data exfiltration attacks, or system prompt overrides.
- **Returns**: `ThreatScanResponse(is_safe=True, threat_score=0.02, detected_threats=[...])`

---

### 2.5 `agents` Namespace

#### `client.agents.register(name: str, framework: str, description: str | None = None, capabilities: list[str] | None = None) -> AgentResponse`
Registers an agentic AI identity within PRIVGUARD's governance registry.
- **Returns**: `AgentResponse(id="ag_...", name="...", status=AgentStatus.ACTIVE, ...)`

#### `client.agents.get(agent_id: str) -> AgentResponse`
Retrieves agent identity, metadata, and status.

#### `client.agents.list() -> list[AgentResponse]`
Lists all registered agents under the active tenant.

#### `client.agents.update_status(agent_id: str, status: AgentStatus | str) -> AgentResponse`
Updates agent operational status (`ACTIVE`, `SUSPENDED`, `REVOKED`, `QUARANTINED`).

---

### 2.6 `tasks` Namespace

#### `client.tasks.create(agent_id: str, title: str, description: str | None = None, input_data: dict[str, Any] | None = None) -> TaskResponse`
Creates an auditable execution task assigned to an agent identity.
- **Returns**: `TaskResponse(id="tsk_...", agent_id="...", status=TaskStatus.PENDING, ...)`

#### `client.tasks.get(task_id: str) -> TaskResponse`
Retrieves status, execution steps, and task outcome.

#### `client.tasks.update_status(task_id: str, status: TaskStatus | str) -> TaskResponse`
Updates task execution status (`PENDING`, `RUNNING`, `COMPLETED`, `FAILED`, `CANCELLED`).

#### `client.tasks.record_step(task_id: str, step_number: int, action: str, details: dict[str, Any] | None = None) -> TaskStepResponse`
Appends an immutable execution step to the task's audit ledger.

---

### 2.7 `capabilities` Namespace

#### `client.capabilities.mint(agent_id: str, allowed_tools: list[str], max_uses: int = 10, ttl_seconds: int = 3600) -> CapabilityTokenResponse`
Mints an Ed25519-signed capability token authorizing specific tools under execution constraints.
- **Returns**: `CapabilityTokenResponse(token="ey...", expires_at="...", allowed_tools=[...])`

#### `client.capabilities.verify(token: str, tool_name: str) -> CapabilityVerifyResponse`
Verifies signature, expiration, remaining usage count, and tool scope.
- **Returns**: `CapabilityVerifyResponse(valid=True, agent_id="...", remaining_uses=9)`

#### `client.capabilities.revoke(token_id: str) -> CapabilityRevokeResponse`
Immediately revokes a capability token before its natural TTL expiration.

---

### 2.8 `approvals` Namespace

#### `client.approvals.request(action_type: ActionType | str, risk_level: RiskLevel | str, requested_by: str, context: dict[str, Any] | None = None) -> ApprovalRequestResponse`
Submits a high-risk action for Human-in-the-Loop (HITL) review.
- **Returns**: `ApprovalRequestResponse(id="appr_...", status=ApprovalStatus.PENDING, ...)`

#### `client.approvals.get(approval_id: str) -> ApprovalRequestResponse`
Checks approval status and reviewer decision.

#### `client.approvals.decide(approval_id: str, status: ApprovalStatus | str, reviewed_by: str, comments: str | None = None) -> ApprovalDecisionResponse`
Grants or denies a pending approval request.

#### `client.approvals.list_pending() -> list[ApprovalRequestResponse]`
Lists all outstanding pending approval requests.

---

### 2.9 `tools` Namespace

#### `client.tools.execute(tool_name: str, arguments: dict[str, Any], capability_token: str, task_id: str | None = None) -> ToolExecutionResponse`
Executes a sandboxed tool call with server-side capability token verification.
- **Returns**: `ToolExecutionResponse(execution_id="...", status="SUCCESS", result={...})`

---

### 2.10 `memory` Namespace

#### `client.memory.propose(agent_id: str, category: MemoryCategory | str, content: str, source_type: SourceType | str = "CONVERSATION", confidence_score: float = 0.9) -> MemoryProposalResponse`
Proposes new memory for agent storage subject to privacy and security scrubbing.
- **Returns**: `MemoryProposalResponse(id="prop_...", status=ProposalStatus.PENDING, ...)`

#### `client.memory.decide(proposal_id: str, action: str, reviewed_by: str) -> MemoryProposalResponse`
Approves or rejects a memory proposal (`action="APPROVE"` or `"REJECT"`).

#### `client.memory.search(agent_id: str, query: str, category: MemoryCategory | str | None = None, limit: int = 10) -> list[MemoryItemResponse]`
Semantic and keyword search over verified agent memory.

#### `client.memory.delete(memory_id: str, reason: str = "USER_REQUEST") -> MemoryDeleteResponse`
Performs hard deletion of memory item to satisfy GDPR / DPDP right-to-erasure.

---

### 2.11 `audit` Namespace

#### `client.audit.query(agent_id: str | None = None, event_type: str | None = None, start_time: str | None = None, end_time: str | None = None, limit: int = 50) -> list[AuditEventResponse]`
Queries the tamper-evident security audit log with hash-chain verification.

---

### 2.12 `compliance` Namespace

#### `client.compliance.get_overview() -> ComplianceOverviewResponse`
Fetches aggregate compliance posture, control activation rates, and coverage percentage.

#### `client.compliance.list_frameworks() -> list[ComplianceFrameworkResponse]`
Lists supported regulatory frameworks (e.g. DPDP 2023/2025, EU AI Act, HIPAA, SOC 2, ISO 27001).

#### `client.compliance.list_controls(domain: str | None = None) -> list[ComplianceControlResponse]`
Lists internal PRIVGUARD technical controls and implementation statuses.

#### `client.compliance.collect_evidence() -> ComplianceEvidenceCollectResponse`
Triggers automated evidence collection across telemetry, audit logs, and configurations.

#### `client.compliance.list_evidence(control_id: str | None = None) -> list[ComplianceEvidenceRecordResponse]`
Lists cryptographic evidence records with SHA-256 fingerprints.

#### `client.compliance.analyze_gaps(framework_id: str) -> ComplianceGapAnalysisResponse`
Produces automated gap analysis against the specified regulatory standard.

#### `client.compliance.request_export(framework_id: str, format: ExportFormat | str = ExportFormat.ZIP) -> ComplianceExportResponse`
Initiates compilation of an exportable, Ed25519-signed compliance evidence package.

#### `client.compliance.download_export(export_id: str, destination_path: str) -> None`
Downloads the compiled compliance ZIP bundle to disk.

