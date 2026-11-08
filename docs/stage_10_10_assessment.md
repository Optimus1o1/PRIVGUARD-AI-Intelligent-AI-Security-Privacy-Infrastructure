# PRIVGUARD AI — Stage 10.10: Python SDK Distribution Assessment & Architecture

**Agency:** Moon Sanctum Labs — *Decode. Build. Evolve.*  
**Lead Engineer:** ANIKET NANDI (Kolkata, IST)  
**Baseline Commit:** `1ee1fcd` (Stage 10.9 completed)  
**SDK Package Name:** `privguard-sdk` (`privguard_sdk`)  
**Target Version:** `0.1.0`  
**Reference Date:** November 2026  

---

## 1. Executive Summary & Objectives

The primary objective of Stage 10.10 is to build a production-grade, secure, developer-friendly, distributable Python SDK (`privguard-sdk`) that allows external applications, autonomous AI agents, enterprise microservices, and compliance audit pipelines to seamlessly integrate with PRIVGUARD AI.

### Architectural Principles:
1. **Client Library Invariant:** The SDK is strictly a typed, resilient client interface over PRIVGUARD AI's existing HTTP APIs. It **never** duplicates backend enforcement logic or bypasses server-side authorization, tenant isolation, Row-Level Security, policy evaluation, or audit ledgers.
2. **Synchronous & Asynchronous Dual-Interface:** First-class support for both synchronous (`PrivGuardClient`) and asynchronous (`AsyncPrivGuardClient`) execution paradigms using `httpx`.
3. **Strong Typing & Zero SQLAlchemy Leakage:** Public models are built with strict Pydantic V2 / dataclasses / TypedDicts independent of internal database models or ORM schemas.
4. **Resilience with Idempotency Awareness:** Automatic retry policies with exponential backoff and jitter strictly bounded to idempotent operations (e.g., GET reads, health checks). Non-idempotent write operations (approvals, memory proposals, capability grants) are **never** blindly retried on network timeouts.
5. **Local Cryptographic Evidence Verification:** The SDK provides a local verification engine capable of parsing exported audit ZIP bundles, verifying SHA-256 artifact digests, validating RFC 8785 canonical JSON bytes, and cryptographically verifying Ed25519 manifest signatures against trusted public keys without server communication.

---

## 2. API Endpoint Inventory (Authoritative Mapping)

Only endpoints that actually exist in the PRIVGUARD AI backend (`backend/app/main.py`) are mapped into the SDK:

| Subsystem | HTTP Method | Endpoint | Existing Backend Router | SDK Resource Method |
| :--- | :--- | :--- | :--- | :--- |
| **Health** | `GET` | `/health` / `/health/live` | `app.api.health` | `client.health.check()` |
| | `GET` | `/health/ready` / `/ready` | `app.api.health` | `client.health.ready()` |
| **Gateway** | `POST` | `/v1/chat/completions` | `app.api.gateway` | `client.gateway.create(...)` / `client.gateway.stream(...)` |
| **Privacy** | `POST` | `/v1/privacy/inspect` | `app.api.privacy` | `client.privacy.inspect(text=...)` |
| | `POST` | `/v1/privacy/redact` | `app.api.privacy` | `client.privacy.redact(text=...)` |
| **Threats** | `POST` | `/v1/threats/inspect` | `app.api.threats` | `client.threats.inspect(text=..., source_type=...)` |
| | `GET` | `/v1/threats/events` | `app.api.threats` | `client.threats.list_events(...)` |
| **Agents** | `POST` | `/v1/agents/register` | `app.api.agents` | `client.agents.register(name=..., allowed_tools=...)` |
| | `GET` | `/v1/agents` | `app.api.agents` | `client.agents.list()` |
| | `GET` | `/v1/agents/{id}` | `app.api.agents` | `client.agents.get(agent_id=...)` |
| | `PATCH` | `/v1/agents/{id}/status` | `app.api.agents` | `client.agents.update_status(agent_id=..., status=...)` |
| **Tasks** | `POST` | `/v1/tasks` | `app.api.tasks` | `client.tasks.create(agent_id=..., ttl_seconds=..., max_steps=...)` |
| | `GET` | `/v1/tasks/{id}` | `app.api.tasks` | `client.tasks.get(task_id=...)` |
| | `GET` | `/v1/tasks` | `app.api.tasks` | `client.tasks.list(...)` |
| **Capabilities**| `POST` | `/v1/capabilities/request` | `app.api.capabilities` | `client.capabilities.request(agent_id=..., task_id=..., tool_name=...)` |
| | `POST` | `/v1/capabilities/validate`| `app.api.capabilities` | `client.capabilities.validate(token=..., tool_name=...)` |
| | `POST` | `/v1/capabilities/{token}/revoke` | `app.api.capabilities` | `client.capabilities.revoke(token=...)` |
| **Approvals** | `GET` | `/v1/approvals/pending` | `app.api.approvals` | `client.approvals.list_pending(...)` |
| | `GET` | `/v1/approvals/{id}` | `app.api.approvals` | `client.approvals.get(approval_id=...)` |
| | `POST` | `/v1/approvals/{id}/approve` | `app.api.approvals` | `client.approvals.approve(approval_id=..., approver_id=...)` |
| | `POST` | `/v1/approvals/{id}/reject` | `app.api.approvals` | `client.approvals.reject(approval_id=..., approver_id=...)` |
| | `POST` | `/v1/approvals/action-hash` | `app.api.approvals` | `client.approvals.compute_action_hash(...)` |
| **Tools** | `GET` | `/v1/tools` | `app.api.tools` | `client.tools.list()` |
| | `POST` | `/v1/tools/{name}/execute` | `app.api.tools` | `client.tools.execute(name=..., agent_id=..., task_id=..., token=..., parameters=...)` |
| **Memory** | `POST` | `/v1/memory/proposals` | `app.api.memory` | `client.memory.propose(...)` |
| | `GET` | `/v1/memory/proposals/pending` | `app.api.memory` | `client.memory.list_pending_proposals(...)` |
| | `POST` | `/v1/memory/proposals/{id}/consent` | `app.api.memory` | `client.memory.consent_proposal(proposal_id=...)` |
| | `POST` | `/v1/memory/proposals/{id}/reject` | `app.api.memory` | `client.memory.reject_proposal(proposal_id=...)` |
| | `POST` | `/v1/memory/items` | `app.api.memory` | `client.memory.store(key=..., value=..., category=...)` |
| | `GET` | `/v1/memory/items/{key}` | `app.api.memory` | `client.memory.retrieve(key=...)` |
| | `GET` | `/v1/memory/items` | `app.api.memory` | `client.memory.list_items(...)` |
| | `DELETE`| `/v1/memory/items/{key}` | `app.api.memory` | `client.memory.delete(key=...)` |
| | `POST` | `/v1/memory/search` | `app.api.memory` | `client.memory.search(query=..., category=...)` |
| | `POST` | `/v1/memory/erasure` | `app.api.memory` | `client.memory.cryptographic_erasure(...)` |
| **Audit** | `GET` | `/v1/audit/events` | `app.api.audit` | `client.audit.list_events(event_type=..., limit=...)` |
| **Compliance** | `GET` | `/v1/compliance/signing-keys/public` | `app.api.compliance` | `client.compliance.get_public_signing_key()` |
| | `GET` | `/v1/compliance/frameworks` | `app.api.compliance` | `client.compliance.list_frameworks()` |
| | `GET` | `/v1/compliance/frameworks/{id}` | `app.api.compliance` | `client.compliance.get_framework(framework_id=...)` |
| | `GET` | `/v1/compliance/controls` | `app.api.compliance` | `client.compliance.list_controls(...)` |
| | `GET` | `/v1/compliance/controls/{id}` | `app.api.compliance` | `client.compliance.get_control(control_id=...)` |
| | `GET` | `/v1/compliance/mappings` | `app.api.compliance` | `client.compliance.list_mappings(...)` |
| | `POST` | `/v1/compliance/evidence/collect` | `app.api.compliance` | `client.compliance.collect_evidence(...)` |
| | `GET` | `/v1/compliance/evidence` | `app.api.compliance` | `client.compliance.list_evidence(...)` |
| | `GET` | `/v1/compliance/gaps` | `app.api.compliance` | `client.compliance.get_gap_analysis(...)` |
| | `POST` | `/v1/compliance/exports` | `app.api.compliance` | `client.compliance.create_export(format=..., include_artifacts=...)` |
| | `GET` | `/v1/compliance/exports/{id}/download` | `app.api.compliance` | `client.compliance.download_export(export_id=..., destination_path=...)` |

---

## 3. Existing API Authentication & Security Model

1. **Authentication Headers:**
   - Supported: `X-API-Key: <api_key>` or `Authorization: Bearer <api_key>`.
   - The SDK will default to sending `X-API-Key: <key>` and optionally `Authorization: Bearer <key>`.
2. **Tenant Scoping & Multi-Tenancy:**
   - Supported: `X-Tenant-ID: <tenant_id>`.
   - The SDK client accepts `tenant_id` at instantiation and passes it on all tenant-aware API calls.
   - Crucial Invariant: The client-supplied tenant ID is treated merely as routing metadata; the server remains unconditionally authoritative for tenant verification.
3. **User Scoping (Personal AI Memory):**
   - Supported: `X-User-ID: <user_id>`.
   - Passed during memory retrieval, storage, and proposal actions to enforce per-user isolation.
4. **Credential Redaction in SDK:**
   - `repr(PrivGuardClient)` and `repr(AsyncPrivGuardClient)` **never** print the raw API key (masked as `sk-***...`).
   - Logging throughout transport layers redacts `X-API-Key` and `Authorization` headers.
   - Exception instances never include raw API keys or memory plaintext.

---

## 4. Python Version Compatibility & Dependency Strategy

### 4.1 Target Python Matrix
- **Python 3.10**: Minimum supported version (Enterprise LTS baseline).
- **Python 3.11**: Active production baseline.
- **Python 3.12**: Current PRIVGUARD development baseline.
- **Python 3.13**: Next-generation compatibility.

### 4.2 Minimal Runtime Dependency Strategy
To keep the SDK lightweight and avoid dependency bloat or conflicts with caller environments, runtime dependencies are strictly constrained:
- `httpx >= 0.27.0, < 0.29.0`: Core synchronous and asynchronous HTTP/1.1 and HTTP/2 transport, streaming, connection pooling, and timeouts.
- `pydantic >= 2.6.0, < 3.0.0`: Type-safe request/response schema modeling and validation.
- `cryptography >= 42.0.0, < 45.0.0`: Ed25519 signature verification, public key PEM parsing, and RFC 8785 SHA-256 digest validation.

Optional / Development Dependencies:
- `pytest`, `pytest-asyncio`, `pytest-cov`: Testing frameworks.
- `ruff`: Formatting and linting.
- `mypy`: Strict static type checking.
- `build`, `twine`: PEP 517 build and verification tooling.

---

## 5. Packaging Strategy

- **Build Backend:** `hatchling` (modern PEP 517 / PEP 621 compliant backend).
- **Project Configuration:** `sdk/python/pyproject.toml`.
- **Inline Typing Marker:** `src/privguard_sdk/py.typed` included in package root.
- **Distribution Formats:**
  - Source Distribution (`sdist`): `.tar.gz`
  - Pure Python Wheel (`bdist_wheel`): `.whl` (Platform-agnostic `py3-none-any.whl`).
- **Clean Distribution Hygiene:**
  - Strict exclusion of tests, local `.env`, backend database files, secrets, and developer artifacts from published distributions.
  - Verification via `twine check` and fresh virtualenv installations.

---

## 6. Implementation Sequence

1. **Preflight Confirmation:** Verify HEAD (`1ee1fcd`) and clean git tree. (Complete)
2. **SDK Directory & Project Setup:** Author `pyproject.toml`, `README.md`, `LICENSE`, `CHANGELOG.md`, and `py.typed` under `sdk/python/`.
3. **Core Exceptions & Configuration:** Build `exceptions.py` (hierarchical, status-coded, safe) and `config.py`.
4. **Transport Layer:** Build `transport/sync.py`, `transport/async_transport.py`, `retries.py` (idempotent-only), and `serialization.py`.
5. **Typed Public Models:** Build `models/` covering all mapped API resources.
6. **Resource Interfaces:** Build `resources/` (health, gateway, agents, tasks, capabilities, approvals, tools, memory, audit, threats, compliance).
7. **Local Evidence Verification Engine:** Build `verification/evidence.py` and `verification/manifests.py` for offline audit package cryptographic validation.
8. **Top-Level Clients:** Build `client.py` (`PrivGuardClient`) and `async_client.py` (`AsyncPrivGuardClient`).
9. **Automated SDK Tests:** Author unit, async, reliability, security, and packaging tests under `sdk/python/tests/`.
10. **CI/CD Pipeline Integration:** Author `.github/workflows/sdk-ci.yml` supporting multi-version matrix testing and PyPI Trusted Publishing preparation.
11. **Documentation & Examples:** Author comprehensive documentation files and executable examples.
12. **Quality Gates & Walkthrough:** Execute all tests, build wheels/sdist, verify clean installation, create walkthrough artifact, and git commit.

