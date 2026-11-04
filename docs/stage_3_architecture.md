# Stage 3 Architecture: Agent Security Broker & Temporary Capabilities

**Moon Sanctum Labs** — *Decode. Build. Evolve.*

## 1. Architectural Overview

Stage 3 introduces the **Agent Security Broker** to enforce hard boundaries around autonomous AI agent tool executions, capabilities, and sensitive operations.

```
Agent Execution Request
        |
        v
PRIVGUARD API (/v1/tools/{name}/execute)
        |
   [Identity Check] (app/agent_security/identity.py)
   - Authenticated application context
   - Agent active status verification
        |
        v
   [Tool Allowlist & Parameter Schema] (app/agent_security/tool_registry.py)
   - Checks tool registered and enabled
   - Validates arguments against schema; rejects unexpected parameters
        |
        v
   [Permission & Capability Check] (app/agent_security/capability_manager.py)
   - Validates opaque cryptographic capability token (secret hash lookup)
   - Verifies agent, task, tool, and resource scope bounds
   - Verifies expiration and usage limits
        |
        v
   [Human-in-the-Loop Gatekeeper] (app/approvals/approval_engine.py)
   - High-risk operations (send_email, delete_file) held as PENDING
   - Cryptographic action binding: SHA256(canonical_json(tool, resource, params))
   - Atomic state transition: APPROVED -> CONSUMED
        |
        v
   [Controlled Sandboxed Execution] (app/agent_security/executor.py)
   - Enforces execution timeout
   - Path-jailed filesystem access (./sandbox/)
   - Code execution disabled in v0.1
        |
        v
   [Output Security Inspection] (app/privacy/secret_scanner.py)
   - Scans tool output for leaked credentials
   - Blocks output if secrets detected (HTTP 502)
        |
        v
   [Content-Free Audit Logging] (app/monitoring/audit.py)
   - Records metadata, latency, and SHA-256 fingerprint
        |
        v
   Return Sanitized Tool Result to Agent
```

## 2. Key Modules & Separation of Concerns

* **Agent Identity Manager (`app/agent_security/identity.py`):** Establishes non-forgeable identities anchored in authenticated application credentials (`app_id`). Agents cannot self-assert IDs or cross application boundaries.
* **Task Manager (`app/agent_security/task_manager.py`):** Binds capabilities and approvals to temporary task sessions. Cancelling or completing a task automatically revokes all associated capability grants and expires pending approvals.
* **Temporary Capability Manager (`app/agent_security/capability_manager.py`):** Issues opaque, high-entropy tokens (`pg_cap_...`). Only SHA-256 hashes are persisted in the database. Performs atomic usage count increments.
* **Human Approval Engine (`app/approvals/approval_engine.py`):** Binds approvals to exact action parameters via cryptographic hashing (`action_hash`). Eliminates tampering and replay attacks.
* **Tool Registry & Executor (`app/agent_security/tool_registry.py`, `app/agent_security/executor.py`):** Central allowlist with strict parameter schemas and jailed execution handlers.
* **Tool Broker (`app/agent_security/tool_broker.py`):** Mediates the entire execution lifecycle and scans tool outputs for secret leakage before client return.
