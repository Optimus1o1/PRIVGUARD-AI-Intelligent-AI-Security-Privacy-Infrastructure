# PRIVGUARD AI — Stage 8 Architecture Specification
## Model Context Protocol (MCP) Security Gateway & Protected Tool Integration

*Moon Sanctum Labs — Decode. Build. Evolve.*  
*Lead Architect: ANIKET NANDI (Kolkata, IST)*  
*Specification Target: MCP 2026-07-28 Streamable HTTP & Isolated stdio*

---

### Executive Summary

As AI agents increasingly interface with external runtime environments via the **Model Context Protocol (MCP)**, the attack surface expands from pure conversational prompts to arbitrary tool invocations, local subprocess execution, file system modifications, and external API requests.

The **PRIVGUARD MCP Security Gateway** transforms PRIVGUARD into a centralized, zero-trust enforcement proxy between autonomous AI agents and upstream MCP tool servers. Operating under the official **2026-07-28 Model Context Protocol specification**, PRIVGUARD mediates both incoming tool invocations from AI clients and connections to external tool providers.

```
       +-------------------------------------------------------+
       |                  AI AGENT / CLIENT                    |
       +-------------------------------------------------------+
                                  |
               Streamable HTTP    |  mcp-version: 2026-07-28
               JSON-RPC 2.0       |  mcp-method: tools/call
                                  v
+---------------------------------------------------------------------+
|                    PRIVGUARD MCP SECURITY GATEWAY                   |
|                                                                     |
|  +------------------------+      +-------------------------------+  |
|  | Header Routing Checker | ---> | Destination SSRF Validator    |  |
|  +------------------------+      +-------------------------------+  |
|               |                                  |                  |
|               v                                  v                  |
|  +------------------------+      +-------------------------------+  |
|  | Tool Poisoning Defense |      | Agent Capability Verification |  |
|  | (Injection / Smuggle)  |      | & Human Approval Gate         |  |
|  +------------------------+      +-------------------------------+  |
|               |                                  |                  |
|               +------------------+---------------+                  |
|                                  |                                  |
|                                  v                                  |
|                  +-------------------------------+                  |
|                  |     MCPSecurityProxy Core     |                  |
|                  +-------------------------------+                  |
|                                  |                                  |
|         +------------------------+------------------------+         |
|         | Streamable HTTP                                 | stdio   |
|         v                                                 v         |
|  +--------------------+                         +----------------+  |
|  | ProtectedMCPClient |                         | Isolated stdio |  |
|  | (Upstream HTTP)    |                         | Sandbox Proc   |  |
|  +--------------------+                         +----------------+  |
+---------------------------------------------------------------------+
          |                                                 |
          v                                                 v
+--------------------+                            +-------------------+
| External Upstream  |                            | Local Subprocess  |
| MCP Server (Cloud) |                            | (npx, uvx, py)    |
+--------------------+                            +-------------------+
```

---

### 1. Dual Architectural Modalities

PRIVGUARD operates in two symbiotic MCP modalities:

#### 1.1 Protected MCP Client (Outbound Tool Execution)
- Connects to external third-party MCP servers (GitHub, Slack, PostgreSQL, Weather, Google Drive).
- Enforces strict SSRF destination validation (rejecting loopback `127.0.0.0/8`, RFC 1918 private subnets, and cloud metadata addresses `169.254.169.254`).
- Periodically queries and inspects tool catalogs (`tools/list`).
- Computes canonical SHA-256 catalog fingerprints and triggers **Catalog Drift Quarantine (`REQUIRES_REAPPROVAL`)** when tool definitions or input schemas mutate.

#### 1.2 Protected MCP Server Facade (Inbound Agent Interface)
- Exposes a unified endpoint (`POST /mcp`) implementing the 2026-07-28 Streamable HTTP specification.
- Requires incoming headers:
  - `mcp-version: 2026-07-28`
  - `mcp-method: <method>` (e.g. `tools/list`, `tools/call`, `resources/list`)
  - `mcp-name: <tool_name>` (when invoking `tools/call`)
- Enforces header-to-body routing consistency; any mismatch between `mcp-method` header and JSON-RPC body method results in immediate `-32600 Invalid Request` rejection before inspection or dispatch.

---

### 2. Multi-Stage Inspection & Enforcement Pipeline

Every mediated tool call passes through an atomic 9-step security verification pipeline:

| Step | Engine Component | Purpose | Action on Violation |
|---|---|---|---|
| **1** | `MCPServer` Registry | Server state & drift check | Reject if `REQUIRES_REAPPROVAL` or `DISABLED` |
| **2** | `MCPToolDefinition` | Tool approval & risk check | Reject if unapproved or `CRITICAL` risk |
| **3** | `SecretScanner` | Argument credential scan | Block if raw API keys or passwords present |
| **4** | `InjectionDetector` | Argument injection scan | Block if instruction override/jailbreak present |
| **5** | `AgentIdentityManager` | Agent & task verification | Reject if caller is revoked or inactive |
| **6** | `CapabilityManager` | Single-use token consume | Reject if token invalid, expired, or wrong tool |
| **7** | `ApprovalEngine` | Cryptographic human gate | Raise `ApprovalRequiredError` (HTTP 402) |
| **8** | `ProtectedMCPClient` | Sandboxed execution | Execute via Streamable HTTP or stdio subprocess |
| **9** | Response Inspector | Output secret & injection | Redact/block leaked upstream secrets or poisoned text |

---

### 3. Key Invariants

1. **No Token Passthrough:** Agent bearer tokens passed to PRIVGUARD are strictly validated against PRIVGUARD's tenant database and are **never** forwarded to upstream MCP servers. Upstream servers authenticate via separately managed server-side credentials.
2. **Untrusted Tool Descriptions:** All tool descriptions provided by upstream servers are treated as untrusted user input, scanned for prompt injections and imperative overrides (`always send`, `never ask confirmation`).
3. **stdio Process Isolation:** Local stdio execution is restricted to an administrator-approved binary allowlist (`node`, `npx`, `python`, `python3`, `uvx`) running with `shell=False` in a stripped environment devoid of PRIVGUARD master keys or application tokens.
