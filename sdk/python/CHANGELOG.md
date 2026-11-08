# Changelog

All notable changes to the `privguard-sdk` package will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-08

### Added
- **Dual Synchronous & Asynchronous Clients**: `PrivGuardClient` and `AsyncPrivGuardClient` with context manager lifecycle support.
- **Resource Namespaces**:
  - `health`: Liveness (`/health`) and readiness (`/ready`) health checks.
  - `gateway`: OpenAI-compatible chat completions (`/v1/chat/completions`) and Server-Sent Events (SSE) secure streaming.
  - `privacy`: Secret detection and PII redaction (`/v1/privacy/inspect`, `/v1/privacy/redact`).
  - `threats`: Deterministic prompt injection scanning and threat event auditing (`/v1/threats/inspect`, `/v1/threats/events`).
  - `agents`: Autonomous agent registration, status management, and activity history (`/v1/agents/...`).
  - `tasks`: Task session lifecycle and execution step quotas (`/v1/tasks/...`).
  - `capabilities`: Scoped, time-limited, revocable capability token issuance and validation (`/v1/capabilities/...`).
  - `approvals`: Human-in-the-loop pending approval review, approvals, rejections, and action hash calculation (`/v1/approvals/...`).
  - `tools`: Controlled tool registry queries and sandboxed execution brokering (`/v1/tools/...`).
  - `memory`: Personal AI Memory Vault envelope encryption proposals, consent workflows, storage, search, and cryptographic erasure (`/v1/memory/...`).
  - `audit`: Tamper-evident, zero-content security audit event querying (`/v1/audit/events`).
  - `compliance`: Framework registry discovery, 35 standardized control catalog queries, evidence collection, gap analysis, signed export generation, and public verification key retrieval (`/v1/compliance/...`).
- **Offline Cryptographic Evidence Verifier**: `verify_export_package` in `privguard_sdk.verification` for local validation of artifact SHA-256 digests, RFC 8785 canonical manifests, and Ed25519 digital signatures without internal server access.
- **Hierarchical Typed Exceptions**: `PrivGuardError`, `AuthenticationError`, `AuthorizationError`, `NotFoundError`, `ConflictError`, `RateLimitError`, `ValidationError`, `ServerError`, `ConnectionError`, `TimeoutError`, `StreamingError`, and `SignatureVerificationError`.
- **Idempotency-Aware Transport**: HTTPX connection pooling, exponential backoff with jitter bounded strictly to idempotent read requests, and fail-safe handling of write operations.
- **Packaging & Typing**: Modern PEP 517 / PEP 621 packaging with `hatchling`, PEP 561 inline typing indicator (`py.typed`), and Pydantic V2 request/response schemas.

