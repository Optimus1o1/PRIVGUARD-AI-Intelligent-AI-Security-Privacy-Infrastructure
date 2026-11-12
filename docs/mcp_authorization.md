# PRIVGUARD AI — Model Context Protocol Authorization
## Capability Tokens, Cryptographic Action Binding, and Human Governance

*Moon Sanctum Labs — Decode. Build. Evolve.*

---

### 1. Unified Authorization Architecture

PRIVGUARD enforces authorization across the MCP boundary without creating redundant access control subsystems. It reuses the core Stage 3 Agent Security Broker, Capability Manager, and Human-in-the-Loop Approval Engine.

```
Agent Tool Request (POST /v1/mcp/servers/{id}/tools/{name}/call)
                   |
                   v
+-------------------------------------------------------------+
| 1. Agent Verification                                       |
|    - Agent must be ACTIVE in AgentIdentity table            |
|    - Associated task must be in RUNNING state               |
+-------------------------------------------------------------+
                   |
                   v
+-------------------------------------------------------------+
| 2. Capability Token Enforcement                             |
|    - Single-use, cryptographically generated token          |
|    - Validated against tool name, agent ID, and task ID     |
|    - Atomically consumed on successful mediation            |
+-------------------------------------------------------------+
                   |
                   v
+-------------------------------------------------------------+
| 3. Risk-Based Human Approval Gate                           |
|    - If risk_level in (HIGH, CRITICAL) or requires_approval |
|    - Requires valid approval_id                             |
|    - Verifies HMAC action hash against exact parameters     |
|    - Replay protection: consumed immediately                |
+-------------------------------------------------------------+
                   |
                   v
       Upstream Execution via Protected Client
```

---

### 2. Single-Use Capability Tokens

To eliminate excessive agency and unconstrained multi-step tool loops:
- PRIVGUARD issues scoped **Capability Tokens** for specific tool invocations.
- Each token encapsulates:
  - `agent_id`: Caller agent identity.
  - `task_id`: Scoped execution task.
  - `tool_name`: Permitted tool name.
  - `expires_at`: Strict time-to-live.
- Upon proxy invocation, `capability_manager.validate_and_consume` validates the token and atomically marks it as consumed in the database, preventing token reuse.

---

### 3. Cryptographic Action Binding & Human Approvals

When an MCP tool has `HIGH` risk (e.g. `send_email`, `delete_records`, `update_settings`):
1. **Creation:** When called without `approval_id`, PRIVGUARD halts execution and creates a pending `ApprovalRequest`.
2. **HMAC Binding:** An action hash is generated using HMAC-SHA-256 over `tool_name`, `target_resource`, and canonical JSON `parameters`:
   $$\text{ActionHash} = \text{HMAC-SHA256}_{K_{\text{master}}}(\text{tool} \parallel \text{resource} \parallel \text{canonical\_json}(\text{params}))$$
3. **HTTP 402 Response:** PRIVGUARD raises `ApprovalRequiredError` (HTTP 402), returning `approval_id`.
4. **Human Review:** The administrator reviews the exact action parameters in the PRIVGUARD Control Center and approves or rejects the request.
5. **Execution:** The agent re-submits the call with `approval_id`. The proxy verifies that current parameters yield the exact stored `ActionHash` before consuming the approval and dispatching upstream.
