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
    - **Boundary G: Distributed State & PostgreSQL Authority.** Enforces consistent cluster-wide security enforcement across multiple backend replicas. PostgreSQL is the authoritative source of truth; state mutations use the Transactional Outbox pattern with secret sanitization. Redis Streams provide durable at-least-once event delivery with consumer group idempotency. Agent and capability revocations propagate instantly, task taint tracking is monotonic across nodes, and sliding-window rate limiting is evaluated atomically via Lua scripts.
    - **Boundary H: Cloud-Neutral Kubernetes Ingress & Micro-Segmentation.** Ingress terminates TLS and exposes exclusively the Next.js frontend on port 3000. Backend (port 8000), worker, and data stores (PostgreSQL, Redis) are strictly unexposed. Default-deny Kubernetes `NetworkPolicy` objects restrict inter-pod and external traffic to explicit least-privilege paths. All workloads comply with Kubernetes Restricted Pod Security Standards (`runAsNonRoot: true`, `readOnlyRootFilesystem: true`, capabilities drop `ALL`, runtime seccomp profile, and memory-backed ephemeral mounts). Dedicated ServiceAccounts disable API server token automounting (`automountServiceAccountToken: false`). Database migrations run as a decoupled, one-shot Pre-Upgrade Hook Job under the DDL-privileged role (`privguard_migrator`), completely isolated from the runtime application role (`privguard_app`).
    - **Boundary I: Enterprise KMS & Cryptographic Key Management.** Provider-independent KMS abstraction supporting AWS KMS (with native server-side `ReEncrypt`), GCP Cloud KMS, Azure Key Vault, HashiCorp Vault Transit, and isolated local development. Ephemeral 256-bit AES-GCM DEKs are wrapped under managed KEKs with Additional Authenticated Data (`{tenant_id}:{owner_id}:{memory_id}:{category}:v2`). Stage 7 legacy HKDF records are migrated non-destructively by rewrapping DEKs without payload re-encryption or ciphertext mutation. Master legacy keys cannot be deleted while unmigrated records exist. Ed25519 asymmetric policy signing keys and versioned HMAC-SHA256 approval action binding secrets are decoupled from data encryption keys to prevent privilege escalation or cross-subsystem compromise. Operational application credentials enforce a zero-plaintext invariant across all database tables and API contracts.
    - **Boundary J: Zero-Content Production Observability & Active Security Canaries.** Production OpenTelemetry tracing, low-cardinality Prometheus metrics, Loki structured logging, and Alertmanager routing hierarchy. Zero raw prompts, completions, memory plaintext, tool arguments, or API tokens appear in telemetry. Metric cardinality is strictly bounded via automatic route path normalization. Eight active synthetic security canaries continuously probe detection, redaction, authorization, revocation, isolation, SSRF prevention, and KMS availability to verify that security controls fail closed. Outbound SIEM exports (Splunk HEC, Elastic ECS, Microsoft Sentinel) are validated by `MCPDestinationValidator` against SSRF threats. Operational telemetry remains strictly decoupled from the Stage 9 tamper-evident audit ledger.
    - **Boundary K: Software Supply-Chain Integrity & Verifiable Distribution.** Enforces SLSA v1.0 Level 3 build provenance, Sigstore Cosign keyless signing tied to GitHub OIDC workflow identities, machine-readable CycloneDX 1.6 SBOMs, automated release integrity verification (`scripts/security/verify_release.py`) operating fail-closed, Gitleaks secret leak prevention with repository allowlists, zero unmitigated High/Critical dependency vulnerabilities (`pip-audit`, `npm audit`), immutable 40-character commit SHA pinning for all GitHub Actions, least-privilege workflow permissions (`permissions: {}`), and manual production deployment gates.
    - **Boundary L: Production Hardening, Edge Resource Bounding & Deterministic Chaos.** Enforces edge request size bounding (`RequestSizeLimitMiddleware`, 10 MB limit) rejecting oversized and unbounded chunked payloads before memory allocation; runaway agent task step limits (`STEP_LIMIT_EXCEEDED`, HTTP 429) auto-revoking assigned capabilities and expiring approvals; per-tool upstream execution timeouts (`asyncio.wait_for`, HTTP 504); SQL-level atomic compare-and-swap (CAS) preventing replay attacks; and 19 deterministic chaos & adversarial resilience tests (`backend/tests/chaos/`) verifying fail-closed security under complete Redis/KMS outages, worker crashes, parameter tampering, and upstream data poisoning.
2. **Buffer-Before-Stream Invariant:** In streaming mode, upstream SSE events are completely buffered and reconstructed before response security inspection. Tokens are only emitted to the client after inspection passes, preventing split-chunk token leaks.
3. **SSRF & Provider Isolation:** Upstream endpoints are resolved exclusively through server-side trusted configuration (`app/providers/registry.py`). Clients cannot specify arbitrary remote destinations.
4. **Cryptographic Action-Binding for Approvals:** Approvals compute an HMAC-SHA256 fingerprint (`action_hash = HMAC(master_key, tool|resource|canonical_json(params))`). Any parameter alteration between approval and execution is detected and rejected with `APPROVAL_TAMPERING_DETECTED`.
5. **Opaque Revocable Capabilities & Atomic CAS:** Capability tokens (`pg_cap_...`) are high-entropy opaque secrets whose SHA-256 hashes are verified against the database on every invocation. Consumption uses atomic SQL compare-and-swap (`UPDATE ... WHERE uses_count < max_uses`), eliminating double-spend race conditions under concurrent load. Revoking a capability takes effect instantaneously.
6. **Multi-Tenant Filesystem Jailing:** Sandboxed file operations are scoped to `./sandbox/{app_id}/`. Absolute paths, root paths (`/`, `\\`), Windows drive letters (`C:`), and directory traversals (`..`) are hard-blocked prior to path normalization with HTTP 403 `PATH_TRAVERSAL_DETECTED`.
7. **Fail-Closed Default:** Unrecognized data categories, response security violations, unconfigured model strings, or subsystem failures trigger immediate execution denial.
8. **Zero Content Retention:** Audit logs store entity categories, action codes, risk levels, and SHA-256 content fingerprints. Raw prompts and completions are never written to disk.
9. **Cryptographic Erasure & Envelope Encryption:** Memories are encrypted with unique AES-256-GCM DEKs wrapped under HKDF-SHA256 derived user KEKs. Deletion wipes the DEK and ciphertext on disk, rendering historical decryption mathematically impossible.
10. **MCP Zero-Trust & No Token Passthrough:** Agent bearer tokens are strictly validated for PRIVGUARD audience and never forwarded to upstream MCP servers. Tool descriptions are treated as untrusted input and scanned for instruction smuggling. Local stdio processes run in an isolated environment with zero shell execution.


