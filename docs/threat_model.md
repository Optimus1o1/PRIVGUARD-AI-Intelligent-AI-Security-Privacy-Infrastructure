# PRIVGUARD AI — Threat Model & Security Controls

**Moon Sanctum Labs** — *Decode. Build. Evolve.*

## Threat Matrix

| Security Threat | PRIVGUARD Component | Initial Protection Mechanism |
|---|---|---|
| **Sensitive Data Leakage** | Privacy Protection Engine | Multi-regex & NLP PII detection; deterministic token substitution (`<EMAIL_1>`, `<PHONE_1>`). |
| **Credential & Key Exposure** | Secret Scanner | High-entropy regex and pattern scanners for API keys (OpenAI, Anthropic, AWS, GitHub, Slack), private keys, and DB credentials; hard fail-closed block. |
| **Prompt Injection & Hijacking** | Threat Analyzer & Agent Broker | Capability grants isolate execution; LLM cannot self-authorize tool calls; injection detected via heuristic signals. |
| **Excessive Agent Permissions** | Agent Broker | Least privilege; task-specific capabilities with strict timeout and invocation limits. |
| **Data Exfiltration via Tools** | Agent Broker | Outbound tools (email, HTTP post) require explicit human approval by default. |
| **Insecure Audit Logging** | Audit Logger | Zero-content storage invariant: logs only contain metadata, category counts, and SHA-256 fingerprints. |
| **Model Output Credential Leaks** | Response Security Inspector | Full secret scanning on model outputs; blocks responses containing generated/reflected keys with HTTP 502. |
| **Split-Chunk Token Exfiltration** | Secure Streaming Handler | Buffer-Before-Stream architecture: buffers entire stream and reconstructs payload before emitting SSE chunks to client. |
| **SSRF / Malicious Upstream Injection** | Provider Registry | Strict server-side registry: client cannot specify upstream base URLs. |
| **Upstream Key Exposure** | Upstream Provider Client | Server-side credential isolation: provider keys never appear in client responses, error traces, or audit logs. |
| **Parameter Tampering after Approval** | Approval Engine | Cryptographic action binding (`action_hash = HMAC(master_key, canonical_params)`); detects parameter changes and returns 403 `APPROVAL_TAMPERING_DETECTED`. |
| **Approval Replay Attacks** | Approval Engine | Atomic CAS state transition `UPDATE ... WHERE status = 'APPROVED'`; replay attempts rejected with 403 `APPROVAL_ALREADY_CONSUMED`. |
| **Capability Double-Spend Race** | Capability Manager | Atomic SQL CAS increments (`UPDATE ... WHERE uses_count < max_uses`); zero race conditions under concurrent client bursts. |
| **Sandbox Path Traversal & Multi-Tenancy** | Tool Executor | Scoped resolution to `./sandbox/{app_id}/`; traversal (`..`), root paths, and Windows drive letters blocked upfront with 403 `PATH_TRAVERSAL_DETECTED`. |
| **Delimiter & Codeblock Hijacking** | Prompt Injection Rules | Deterministic detection of boundary markers (`--- END OF SYSTEM CONTEXT ---`, ````system````, `### End of Prompt ###`). |
| **RAG Poisoning & Tampering** | Retrieval Security Validator | Cross-tenant retrieval isolation, cryptographic chunk hash validation, and HTML/CSS hidden injection scanning. |
| **Covert Data Exfiltration (MITRE T1700)** | Exfiltration Detector | Taint tracking on confidential resources; blocks unauthorized transmission from tainted context to external sinks. |
| **Arbitrary Code Execution** | Tool Registry | Critical risk tool `execute_code` is disabled by default in v0.1. |
| **Long-Term Memory Poisoning** | Memory Validator & Consent Gate | Staged proposals require human consent; injection and hidden directives blocked before staging. |
| **Imperative Agent Behavioral Overrides** | Memory Validator | Scans for persistent control phrases (`always send`, `never ask confirmation`); rejects with HTTP 400. |
| **Credential Harvesting in Memory** | Memory Validator & Secret Scanner | Raw API keys and private tokens blocked prior to encryption or staging. |
| **Cross-User / Cross-Tenant Memory Splicing** | Envelope Encryption Engine | AES-256-GCM with AAD binding (`memory_id:owner_id:category`); ciphertext tampering or splicing fails tag verification with HTTP 403 `MEMORY_INTEGRITY_COMPROMISED`. |
| **Unauthorized Memory Retention** | Memory Lifecycle Manager | Optional expiration TTL; Cryptographic erasure destroys DEK (`[DEK_DESTROYED]`) and overwrites ciphertext (`[CRYPTOGRAPHICALLY_ERASED]`). |
| **AI Model Training on Personal Data** | Architectural Invariant | Memory vault is strictly bounded for real-time context retrieval; zero training usage. |
| **Tool Description Shadow Poisoning** | MCP Tool Registry | Tool descriptions scanned for prompt injections and behavioral overrides (`always send`); poisoned tools blocked. |
| **MCP Catalog Drift / Rug-Pulling** | MCP Tool Registry | Canonical SHA-256 fingerprinting detects schema and semantic modifications, placing server in `REQUIRES_REAPPROVAL` quarantine. |
| **MCP Server-Side Request Forgery (SSRF)** | MCP Destination Validator | Blocks loopback, private IPv4/IPv6, cloud metadata (`169.254.169.254`), and DNS rebinding attacks. |
| **stdio Shell Injection & Privilege Escalation** | MCP stdio Sandbox | Enforces approved binary allowlist (`node`, `npx`, `python`, `uvx`), zero `shell=True`, and stripped environment. |
| **Inbound Token Forwarding Across MCP Boundary** | Protected MCP Client | Inbound agent tokens are audience-checked for PRIVGUARD and never forwarded to upstream servers. |
| **Upstream Tool Response Poisoning & Leakage** | MCP Security Proxy | Response scanning intercepts leaked credentials and prompt injection payloads before returning to agent. |
| **Cross-Tenant Data Exposure** | Database RLS & Tenant Scoper | App-level query filtering combined with PostgreSQL `FORCE ROW LEVEL SECURITY`; queries scoped to `tenant_id` context. |
| **Unauthorized Role Elevation** | RBAC Engine & Separation of Duties | Strict 8-role RBAC enforcement; bounded admin authority prevents lowering platform security invariants. |
| **Policy Downgrade & Replay** | Ed25519 Policy Signer & Bundle Verifier | Monotonically-increasing versions, anti-downgrade enforcement, and canonical RFC 8785 Ed25519 signature checks. |
| **Unverified SSO Domain Hijacking** | Enterprise Identity Service | Requires cryptographic DNS TXT verification token prior to enabling SSO domain auto-join. |
| **Audit Ledger Tampering** | Hash-Chained Audit Ledger | Cryptographic SHA-256 hash chaining (`prev_hash || record_hash`); detects any row mutation, deletion, or insertion. |
| **SIEM Webhook SSRF Exfiltration** | SIEM Exporter | Destination IP validation blocks internal/private subnets and loopback addresses from export destinations. |
| **Stale Fleet Policy Desync** | Fleet Sync & Heartbeat Engine | Central authoritative broker-side revocation immediately terminates access regardless of agent heartbeat status. |
| **Permissive CORS Credential Exposure** | CORS Middleware & Config Validator | Strict origin whitelisting (`CORS_ALLOWED_ORIGINS`); production fails closed if wildcard `*` is configured with credentials. |
| **Accidental DEBUG Admin Bypass** | Authentication Handler & Core Config | Elimination of master key backdoor under `DEBUG`; production startup rejects `DEBUG=True` fail-closed. |
| **Public Database / Cache Direct Probing** | Multi-Tier Network Topology | PostgreSQL and Redis isolated on `internal: true` data network with zero public port publishing. |
| **Container Breakout & Host Filesystem Write** | Multi-Stage Dockerfiles & Compose | Non-root users (`privguard:privguard`, `nextjs:nodejs`), `no-new-privileges:true`, and read-only root filesystems with tmpfs scratch space. |
| **Database Superuser RLS Subversion** | PostgreSQL Role Separation | Runtime application role `privguard_app` runs with `NOBYPASSRLS` and `NOSUPERUSER`; migrations execute under separate role. |
| **Distributed Rate Limit Bypass** | Distributed Rate Limiter | Atomic Redis Lua sliding-window rate limiting evaluates cluster-wide quotas; local fail-safe enforces sensitive quotas on outage. |
| **Dual-Write State Desynchronization** | Transactional Outbox | Atomic SQL transaction bundles state mutations with `OutboxEvent`; outbox relay ensures at-least-once Redis Stream delivery. |
| **Stale Cross-Replica Revocation Window** | Agent Security Broker | Tool execution verifies agent and capability status against PostgreSQL authority at dispatch time; sub-millisecond Redis invalidation. |
| **Cross-Node Covert Exfiltration** | Distributed Taint Store | Monotonic task taint persistence in PostgreSQL `active_taints` and Redis sets prevents exfiltration across multi-replica clusters. |
| **Connection Pool Tenant Contamination** | Database Session Manager | Transaction-scoped `SET LOCAL app.current_tenant_id` combined with deterministic `finally: RESET` prevents cross-tenant RLS leakage across pooled connections. |
| **Master Key Compromise Blast Radius** | KMS Abstraction & Purpose Segregation | Separation of DEKs, KEKs, Ed25519 signing keys, and HMAC approval keys; compromise of one subsystem does not compromise others. |
| **Premature Master Key Destruction** | Legacy Memory Migrator Safeguard | System prevents retirement or deletion of legacy keys while unmigrated records exist in the database or active backup retention window. |
| **Plaintext Credential Leakage in DB** | Secret Metadata Manager | Application credentials maintain zero plaintext in database models or API metadata contracts. |
| **In-Flight Key Rotation Downtime** | Envelope Encryption Engine | Dual-mode V1/V2 reading and non-destructive DEK rewrapping preserving ciphertext and nonces ensures 100% uptime during key rotation. |
| **Approval Forgery via Master Key Exposure** | Signing Key Manager | Versioned HMAC approval action binding keys decoupled from data encryption keys; instant revocation of compromised key ID (`kid`). |
| **Telemetry Prompt & Content Leakage** | Observability Engine & Safe Attributes | Zero-content telemetry invariant; strict `SAFE_ATTRIBUTE_ALLOWLIST` and `PROHIBITED_KEY_PATTERNS` drop all raw prompts, completions, and memory plaintext from OTel spans and logs. |
| **Metric Cardinality Denial of Service** | Observability Middleware & Normalizer | Dynamic path parameters (UUIDs, ints, prefixed IDs, canaries) normalized to `{id}` in Prometheus labels; eliminates timeseries explosion. |
| **Operational Log Credential Exposure** | Logging Redaction Filter | Inline regex scrubbing replaces Bearer tokens, OpenAI/Anthropic/GitHub API keys, and passwords with `[REDACTED_CREDENTIAL]`. Span exception recording scrubs secrets. |
| **Outbound SIEM Forwarding SSRF** | Enterprise SIEM Exporter | `MCPDestinationValidator` validates target URLs; blocks RFC 1918 private IPs, AWS IMDS `169.254.169.254`, and internal domain TLDs (.corp, .internal). |
| **Silent Security Control Failure** | Active Synthetic Canaries | 8 continuous automated canaries probe PII redaction, secret blocking, authorization, revocation, injection detection, memory isolation, SSRF, and KMS roundtrips, alerting immediately if controls fail to reject attacks. |

## Defense-in-Depth Principle

No machine learning classifier can guarantee 100% detection of adversarial prompt injection. Therefore:
1. Threat detection provides early warning.
2. The **Agent Broker** and **Capability-Based Access Control** provide the true enforcement boundary. Even if an agent follows an injected instruction, the underlying operation fails closed without an active, signed capability grant.

