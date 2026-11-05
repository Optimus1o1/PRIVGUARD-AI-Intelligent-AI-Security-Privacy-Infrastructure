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

## Defense-in-Depth Principle

No machine learning classifier can guarantee 100% detection of adversarial prompt injection. Therefore:
1. Threat detection provides early warning.
2. The **Agent Broker** and **Capability-Based Access Control** provide the true enforcement boundary. Even if an agent follows an injected instruction, the underlying operation fails closed without an active, signed capability grant.

