# PRIVGUARD AI — System Architecture (v0.1)

**Moon Sanctum Labs** — *Decode. Build. Evolve.*

## 1. High-Level Overview

PRIVGUARD AI serves as an independent security and privacy enforcement layer positioned between AI applications, untrusted data sources, external foundation models, and agent execution tools.

```
USER / DEVELOPER
      |
 AI APPLICATION / AGENT
      |
 PRIVGUARD SDK / OpenAI-Compatible Interface
      v
+-------------------------------------------------------+
| PRIVGUARD GATEWAY (app/api/gateway.py)                |
| - Application Authentication (app/core/auth.py)       |
| - Request Inspection Pipeline                         |
| - Fail-Closed Security Perimeter                      |
+---------------------------+---------------------------+
                            |
           +----------------+----------------+
           |                                 |
           v                                 v
+----------------------+           +--------------------+
| PRIVACY ENGINE       |           | THREAT DETECTOR    |
| - Secret Scanner     |           | - Prompt Injection |
| - PII Detector       |           | - Risk Analysis    |
| - Reversible Redactor|           | - Anomaly Signals  |
+----------+-----------+           +---------+----------+
           |                                 |
           +----------------+----------------+
                            |
                            v
+-------------------------------------------------------+
| POLICY ENGINE (app/policies/engine.py)                |
| - Deterministic Rules: ALLOW | REDACT | BLOCK         |
+---------------------------+---------------------------+
                            |
           +----------------+----------------+
           |                                 |
           v                                 v
+----------------------+           +--------------------+
| MODEL GATEWAY        |           | AGENT BROKER       |
| - OpenAI Proxy       |           | - Tool Validation  |
| - Minimized Context  |           | - Task Grants      |
| - De-redaction Return|           | - Human Approval   |
+----------+-----------+           +---------+----------+
           |                                 |
           v                                 v
  EXTERNAL / LOCAL LLM              AUTHORIZED TOOLS
           |                                 |
           +----------------+----------------+
                            |
                            v
+-------------------------------------------------------+
| CONTENT-FREE AUDIT & MONITORING                       |
| - Zero prompt/response storage                        |
| - Cryptographic metadata & entity hashes              |
+-------------------------------------------------------+
```

## 2. Security Boundaries & Invariants

1. **Three Core Security Boundaries:**
   - **Boundary A: Model Ingress/Egress Gateway.** Sanitizes context before upstream delivery; blocks credentials from entering model context; inspects model output for leaked secrets before client delivery.
   - **Boundary B: Agent Broker Tool Execution.** Mediates every tool execution through task-scoped capability tokens. Prompt injection defense is secondary to Broker authorization.
   - **Boundary C: Secure Personal AI Memory Vault.** Isolates personal context behind AES-256-GCM envelope encryption, user consent proposals, and task-bound capability retrieval. Zero training usage.
   - **Boundary D: Model Context Protocol (MCP) Security Gateway.** Mediates upstream MCP tools and incoming agent tool calls. Enforces 2026-07-28 Streamable HTTP header routing, SSRF destination protection, tool description poisoning scans, catalog drift quarantine, and stdio sandboxing.
   - **Boundary E: Enterprise Multi-Tenancy & Fleet Governance.** Enforces PostgreSQL Row-Level Security (`FORCE ROW LEVEL SECURITY`), server-side tenant context resolution, 8-role RBAC, Ed25519-signed policy bundles with anti-downgrade defense, departmental workspace jailing, and tamper-evident SHA-256 hash-chained audit ledgers.
   - **Boundary F: Hardened Deployment & Network Isolation.** Three isolated network tiers (`edge`, `application`, `data`) guarantee that backend ASGI servers, PostgreSQL databases, and Redis caches are unreachable from public internet ingress. Application runtime connects as non-superuser `privguard_app` with `NOBYPASSRLS`. Secrets are mounted via Docker Compose secrets rather than environment strings.
2. **Buffer-Before-Stream Invariant:** In streaming mode, upstream SSE events are completely buffered and reconstructed before response security inspection. Tokens are only emitted to the client after inspection passes, preventing split-chunk token leaks.
3. **SSRF & Provider Isolation:** Upstream endpoints are resolved exclusively through server-side trusted configuration (`app/providers/registry.py`). Clients cannot specify arbitrary remote destinations.
4. **Cryptographic Action-Binding for Approvals:** Approvals compute an HMAC-SHA256 fingerprint (`action_hash = HMAC(master_key, tool|resource|canonical_json(params))`). Any parameter alteration between approval and execution is detected and rejected with `APPROVAL_TAMPERING_DETECTED`.
5. **Opaque Revocable Capabilities & Atomic CAS:** Capability tokens (`pg_cap_...`) are high-entropy opaque secrets whose SHA-256 hashes are verified against the database on every invocation. Consumption uses atomic SQL compare-and-swap (`UPDATE ... WHERE uses_count < max_uses`), eliminating double-spend race conditions under concurrent load. Revoking a capability takes effect instantaneously.
6. **Multi-Tenant Filesystem Jailing:** Sandboxed file operations are scoped to `./sandbox/{app_id}/`. Absolute paths, root paths (`/`, `\\`), Windows drive letters (`C:`), and directory traversals (`..`) are hard-blocked prior to path normalization with HTTP 403 `PATH_TRAVERSAL_DETECTED`.
7. **Fail-Closed Default:** Unrecognized data categories, response security violations, unconfigured model strings, or subsystem failures trigger immediate execution denial.
8. **Zero Content Retention:** Audit logs store entity categories, action codes, risk levels, and SHA-256 content fingerprints. Raw prompts and completions are never written to disk.
9. **Cryptographic Erasure & Envelope Encryption:** Memories are encrypted with unique AES-256-GCM DEKs wrapped under HKDF-SHA256 derived user KEKs. Deletion wipes the DEK and ciphertext on disk, rendering historical decryption mathematically impossible.
10. **MCP Zero-Trust & No Token Passthrough:** Agent bearer tokens are strictly validated for PRIVGUARD audience and never forwarded to upstream MCP servers. Tool descriptions are treated as untrusted input and scanned for instruction smuggling. Local stdio processes run in an isolated environment with zero shell execution.


