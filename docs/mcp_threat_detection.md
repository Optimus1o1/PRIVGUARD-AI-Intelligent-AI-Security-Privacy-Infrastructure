# PRIVGUARD AI — Model Context Protocol Runtime Threat Detection
## Argument Inspection, Response Poisoning Protection, and Content-Free Audit Logging

*Moon Sanctum Labs — Decode. Build. Evolve.*

---

### 1. Inbound & Outbound Runtime Threats

Threat detection across the MCP boundary covers both sides of every tool execution:

```
AI Agent                     PRIVGUARD Proxy                    Upstream Server
   |                                |                                  |
   | --- Tool Arguments ----------> | (Argument Scan)                  |
   |                                |  - Secret Scanner                |
   |                                |  - Prompt Injection Scanner      |
   |                                |  - Imperative Smuggle            |
   |                                |                                  |
   |                                | --- Mediated Request ----------> |
   |                                |                                  |
   |                                | <--- Upstream Result ----------- |
   |                                | (Response Scan)                  |
   |                                |  - Outbound Secret Leak Scan     |
   |                                |  - Indirect Injection Scan       |
   |                                |                                  |
   | <--- Sanitized Result -------- | (Content-Free Audit Emitted)     |
```

#### 1.1 Inbound Argument Threat Detection
Before parameters are passed to an upstream tool:
1. **Secret Scanning:** Scans for raw API keys (OpenAI, Anthropic, GitHub, AWS, Google Cloud), database connection URIs, private keys, and passwords. Any detected credential raises `SecretDetectedError` (HTTP 403) and terminates execution before network egress.
2. **Prompt Injection Inspection:** Scans tool arguments for instruction override phrases, jailbreak tokens, and encoded payloads (Base64). Malicious arguments raise `MCPToolPoisoningError` (HTTP 403).

#### 1.2 Outbound Response Threat Detection
When the upstream tool returns data (e.g. database query, search results, web scrape):
1. **Response Secret Leakage Defense:** Inspects raw output for leaked credentials (e.g. accidentally dumped `.env` files or database columns containing API tokens). If detected, `ResponseSecurityViolationError` (HTTP 502) is raised, preventing the LLM context from ingesting the secret.
2. **Indirect Prompt Injection Defense:** Inspects returned document contents or text chunks for embedded attacker instructions designed to compromise the host agent. Malicious payloads trigger `TOOL_OUTPUT_INJECTION_DETECTED`.

---

### 2. Content-Free Audit Trail

To preserve auditability without compromising user privacy or persisting sensitive tool inputs:
- Every mediated call generates an immutable `MCPAuditEvent` record.
- **Persisted Fields:**
  - `app_id`, `server_id`, `agent_id`, `tool_name`
  - `action`: `CALL_TOOL`, `READ_RESOURCE`, `REGISTER_SERVER`, `CATALOG_DRIFT_DETECTED`
  - `status`: `SUCCESS`, `BLOCKED`, `ERROR`, `QUARANTINED`
  - `details`: Metadata-only JSON containing risk levels, execution flags, and action hashes. Raw parameter values and response payloads are **never** stored in the audit table.
