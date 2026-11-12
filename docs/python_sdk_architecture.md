# PRIVGUARD AI — Python SDK Architecture Specification

**Organization**: Moon Sanctum Labs  
**Motto**: Decode. Build. Evolve.  
**Package**: `privguard-sdk` (import: `privguard_sdk`)  
**Specification Version**: 1.0.0 (SDK Version: 0.1.0)  

---

## 1. Architectural Philosophy & Invariants

The `privguard-sdk` is an asynchronous and synchronous Python client library providing developers, agent frameworks, and enterprise platforms with a strongly typed, resilient interface to PRIVGUARD AI's security gateway, memory vault, tool execution sandbox, and compliance engine.

### Non-Negotiable Core Invariants

1. **Client Library Invariant**:  
   The SDK is strictly a typed, resilient transport client over PRIVGUARD AI HTTP REST APIs. It **never** duplicates backend security logic, simulates capability verification locally, or attempts to bypass server-side authorization, tenant isolation, row-level security (RLS), policy engine evaluations, or cryptographic ledger recording. All policy enforcement is authoritative on the server.
2. **Synchronous & Asynchronous Parity**:  
   Every capability exposed by `PrivGuardClient` is mirrored with exact naming, arguments, and return types on `AsyncPrivGuardClient`. Developers can seamlessly switch between synchronous agent loops (e.g., standard LangChain/CrewAI scripts) and high-concurrency asynchronous runtime systems (e.g., FastAPI, AutoGen, or asyncio pipelines).
3. **Zero ORM & Database Leakage**:  
   The SDK possesses zero dependencies on SQLAlchemy, databases, or backend ORM internals. All data models are strictly defined using standard Pydantic V2 schemas.
4. **Idempotency-Aware Resiliency**:  
   Automatic network retries with exponential backoff and full jitter are strictly bounded to idempotent HTTP operations (`GET`, `HEAD`, `OPTIONS`). Mutation operations (`POST`, `PATCH`, `DELETE`) are never automatically retried upon connection dropouts or socket timeouts to prevent double-spending tokens, re-executing non-idempotent tool calls, or corrupting state.
5. **Credential Safety**:  
   API keys and authorization tokens are stringently masked in `__repr__()` implementations, logs, and telemetry. Sensitive payloads are never written to unauthenticated crash traces.

---

## 2. Package Structure & Module Topology

```
sdk/python/
├── pyproject.toml                     # PEP 517 / PEP 621 build definition (Hatchling)
├── LICENSE                            # Apache 2.0 License
├── README.md                          # Quickstart, API overview, usage patterns
├── CHANGELOG.md                       # Release notes and migration guides
├── src/
│   └── privguard_sdk/
│       ├── __init__.py                # Package root exports, version string
│       ├── py.typed                   # PEP 561 inline typing indicator
│       ├── config.py                  # Client configuration with environment fallbacks
│       ├── types.py                   # Domain enumerations and type aliases
│       ├── exceptions.py              # Status-coded exception hierarchy & factory
│       ├── client.py                  # Synchronous PrivGuardClient
│       ├── async_client.py            # Asynchronous AsyncPrivGuardClient
│       ├── models/                    # Pydantic V2 data contracts
│       │   ├── __init__.py
│       │   ├── health.py
│       │   ├── gateway.py
│       │   ├── privacy.py
│       │   ├── threats.py
│       │   ├── agents.py
│       │   ├── tasks.py
│       │   ├── capabilities.py
│       │   ├── approvals.py
│       │   ├── tools.py
│       │   ├── memory.py
│       │   ├── audit.py
│       │   └── compliance.py
│       ├── transport/                 # HTTP transport, pooling & retry engine
│       │   ├── __init__.py
│       │   ├── base.py
│       │   ├── serialization.py
│       │   ├── retries.py
│       │   ├── sync.py
│       │   └── async_transport.py
│       ├── resources/                 # Resource namespaces (Sync & Async)
│       │   ├── __init__.py
│       │   ├── base.py
│       │   ├── health.py
│       │   ├── gateway.py
│       │   ├── privacy.py
│       │   ├── threats.py
│       │   ├── agents.py
│       │   ├── tasks.py
│       │   ├── capabilities.py
│       │   ├── approvals.py
│       │   ├── tools.py
│       │   ├── memory.py
│       │   ├── audit.py
│       │   └── compliance.py
│       └── verification/              # Standalone offline compliance verification
│           ├── __init__.py
│           ├── manifests.py
│           └── evidence.py
├── tests/                             # Automated test suite (Pytest)
└── examples/                          # Runnable integration scripts
```

---

## 3. Transport Engine & Connection Pooling

The SDK uses `httpx` as its foundational HTTP engine:

- **Connection Limits**: Default maximum connections are capped at 100, with up to 20 idle keep-alive connections maintained.
- **Timeouts**: Granular timeout configuration via `httpx.Timeout(timeout=30.0, connect=5.0, read=30.0, write=10.0)`.
- **Redirect Policy**: By default, `follow_redirects=False` is enforced across all client requests. This mitigates Server-Side Request Forgery (SSRF) and prevents unintentional token leakage across domain boundaries.
- **Resource Management**: Both `PrivGuardClient` and `AsyncPrivGuardClient` implement context management protocols (`__enter__`/`__exit__` and `__aenter__`/`__aexit__`), ensuring underlying HTTP socket pools and threads are cleanly terminated upon exit.

---

## 4. Resource Namespace Routing

To provide an ergonomic and discoverable developer experience, APIs are partitioned into 12 semantic namespaces accessible directly as attributes on the root client:

| Namespace | Synchronous Resource | Asynchronous Resource | Description |
| :--- | :--- | :--- | :--- |
| `health` | `HealthResource` | `AsyncHealthResource` | Service liveness, readiness, and subsystem status |
| `gateway` | `GatewayResource` | `AsyncGatewayResource` | Privacy-enforced chat completions and SSE streaming |
| `privacy` | `PrivacyResource` | `AsyncPrivacyResource` | PII/PHI detection, anonymization, and reversible deanonymization |
| `threats` | `ThreatsResource` | `AsyncThreatsResource` | Prompt injection, jailbreak detection, and threat scoring |
| `agents` | `AgentsResource` | `AsyncAgentsResource` | Agent registration, status updates, and lifecycle management |
| `tasks` | `TasksResource` | `AsyncTasksResource` | Delegated task creation, execution steps, and status tracking |
| `capabilities` | `CapabilitiesResource` | `AsyncCapabilitiesResource` | Ed25519 capability token minting, verification, and revocation |
| `approvals` | `ApprovalsResource` | `AsyncApprovalsResource` | Human-in-the-loop (HITL) approval workflows and decisions |
| `tools` | `ToolsResource` | `AsyncToolsResource` | Sandboxed tool execution with capability token verification |
| `memory` | `MemoryResource` | `AsyncMemoryResource` | Long-term memory proposals, approvals, search, and GDPR/DPDP deletion |
| `audit` | `AuditResource` | `AsyncAuditResource` | Querying cryptographic, tamper-evident security audit logs |
| `compliance` | `ComplianceResource` | `AsyncComplianceResource` | Controls, framework mappings, gap analysis, and evidence exports |

---

## 5. Offline Cryptographic Verification Engine

An isolated subsystem within `privguard_sdk.verification` allows compliance officers, security auditors, or CI/CD pipelines to verify exported compliance ZIP packages completely offline:

1. **RFC 8785 Canonical JSON**:  
   Manifest dictionaries are normalized according to RFC 8785 (deterministic sorting of keys, Unicode encoding, whitespace elimination) prior to cryptographic hashing or signature verification.
2. **SHA-256 Digest Verification**:  
   Every artifact referenced in the manifest (e.g. `audit_trail.jsonl`, `controls.json`, `git_provenance.json`) has its content hash computed and verified against the manifest checksum.
3. **Ed25519 Signature Verification**:  
   The manifest's digital signature is verified using the organization's public key (either embedded or externally supplied via PEM/raw bytes).

