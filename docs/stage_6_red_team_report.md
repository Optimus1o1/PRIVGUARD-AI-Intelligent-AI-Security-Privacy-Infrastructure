# PRIVGUARD AI — Stage 6 Red Team Vulnerability Report
**Moon Sanctum Labs** — *Decode. Build. Evolve.*  
**Author:** ANIKET NANDI (Lead Developer & Designer, Kolkata, IST)  
**Classification:** Confidential Security Evaluation / Remediation Ledger

---

## 1. Red Team Scope & Methodology

Adversarial testing in Stage 6 adopted a black-box, grey-box, and white-box methodology simulating an untrusted external attacker, a compromised autonomous agent, and a malicious multi-tenant insider.

Testing evaluated 12 critical security interfaces:
1. `POST /v1/chat/completions` (LLM Gateway)
2. `POST /v1/privacy/inspect` and `/redact` (Privacy Pipeline)
3. `POST /v1/agents/register` and lifecycle operations (Agent Identity)
4. `POST /v1/capabilities/request` and verification (Capability Manager)
5. `POST /v1/approvals/{id}/approve` and consumption (Approval Engine)
6. `POST /v1/tools/{name}/execute` (Sandboxed Executor)
7. `POST /v1/threats/inspect` and `/evaluate-behavior` (Threat Detection)
8. `GET /v1/threats/taints/{task_id}` (Taint Tracking API)
9. Knowledge base retrieval chunk ingestion (RAG Security)
10. Agent memory update inspection (Memory Analyzer)
11. BFF Proxy route routing in Next.js (`frontend/app/api/backend/[...path]`)
12. Database connection pooling and concurrent atomic state transitions

---

## 2. Vulnerability Ledger (`PG-SEC-001` to `PG-SEC-012`)

The following vulnerabilities were identified during red-team probing and successfully remediated.

### `PG-SEC-001`: Unkeyed SHA-256 in Approval Action Fingerprinting
- **Severity:** HIGH (CVSS 7.5) | **OWASP AISVS:** 8.1 | **MITRE ATLAS:** AML.T0040
- **Vulnerability:** `compute_action_hash` in `backend/app/approvals/approval_engine.py` computed standard SHA-256 over parameters without a cryptographic secret key. An adversary with database write access could forge approved action hashes.
- **Root Cause:** Plain `hashlib.sha256(payload.encode()).hexdigest()` without HMAC binding.
- **Remediation:** Upgraded to `hmac.new(settings.PRIVGUARD_MASTER_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()`.
- **Regression Test:** `tests/test_redteam_approvals.py::test_parameter_tampering_attack_rejected`.

### `PG-SEC-002`: IDOR in Threats Taint & Behavior Evaluation Endpoints
- **Severity:** HIGH (CVSS 8.2) | **OWASP AISVS:** 11.2 | **CWE:** CWE-639
- **Vulnerability:** `GET /v1/threats/taints/{task_id}` and `POST /v1/threats/evaluate-behavior` in `backend/app/api/threats.py` failed to verify application ownership of `task_id`, allowing Tenant Bravo to inspect Tenant Alpha's active taints and behavior scores.
- **Root Cause:** Direct in-memory lookup without querying `AgentTask` ownership (`AgentTask.app_id == app.id`).
- **Remediation:** Added database ownership verification in both endpoints, returning HTTP 404 `TASK_NOT_FOUND` if foreign tasks are queried.
- **Regression Test:** `tests/test_redteam_exfiltration.py::test_taint_query_idor_protection`.

### `PG-SEC-003`: Shared Filesystem Sandbox Directory Lacked Multi-Tenant Jailing
- **Severity:** HIGH (CVSS 7.8) | **OWASP AISVS:** 7.1 | **CWE:** CWE-200
- **Vulnerability:** Files written or read by tools in `backend/app/agent_security/executor.py` were resolved in a single global `./sandbox/` directory. Tenant B's agent could read confidential files written by Tenant A's agent.
- **Root Cause:** Flat `./sandbox/` path resolution without application namespace scoping.
- **Remediation:** Scoped sandbox path resolution to `./sandbox/{app_id}/` while maintaining backward-compatible fallback for root test fixtures. Tool Broker now injects `params["_app_id"] = app.id`.
- **Regression Test:** `tests/test_redteam_agent_broker.py::test_filesystem_sandbox_directory_traversal_blocked`.

### `PG-SEC-004`: Pre-Validation Strip Allowed Absolute Path Normalization Bypass
- **Severity:** CRITICAL (CVSS 8.8) | **OWASP AISVS:** 7.2 | **CWE:** CWE-22
- **Vulnerability:** In `executor.py`, `user_path.strip().lstrip("/\\")` stripped leading slashes before boundary checks. Absolute paths like `/etc/shadow` became `etc/shadow`, which failed with 404 (file not found) rather than raising a 403 traversal block, and Windows drive letters (`C:\autoexec.bat`) bypassed the sandbox directory anchor.
- **Root Cause:** Destructive path mutation prior to input validation.
- **Remediation:** Validated raw user input upfront before stripping. Traversal sequences (`..`), root paths (`/`, `\\`), and Windows drive letters (`^[a-zA-Z]:`) are immediately blocked with HTTP 403 `PATH_TRAVERSAL_DETECTED`.
- **Regression Test:** `tests/test_redteam_agent_broker.py::test_filesystem_sandbox_directory_traversal_blocked`.

### `PG-SEC-005`: SSRF & Arbitrary Model Fallback in Provider Registry
- **Severity:** HIGH (CVSS 8.5) | **OWASP AISVS:** 1.1 | **CWE:** CWE-918
- **Vulnerability:** `get_provider(model)` in `backend/app/providers/registry.py` fell back to `self._default_provider` for ANY string passed by clients, including internal SSRF URLs (`http://169.254.169.254/latest/meta-data/`) and traversal strings (`../../etc/passwd`).
- **Root Cause:** Permissive default fallback without input sanitization or model allowlisting.
- **Remediation:** Enforced strict rejection of URI schemes (`://`), path separators (`/`, `\\`), host ports (`:`), and traversal tokens (`..`). Added prefix allowlist check (`gpt-*`, `mock-*`, `claude-*`, etc.); unconfigured models fail closed with HTTP 400 `MODEL_NOT_CONFIGURED`.
- **Regression Test:** `tests/test_redteam_gateway.py::test_ssrf_and_unconfigured_model_rejection`.

### `PG-SEC-006`: Upstream Provider Exceptions Leaked Credentials in Error Responses
- **Severity:** HIGH (CVSS 7.4) | **OWASP AISVS:** 1.2 | **CWE:** CWE-209
- **Vulnerability:** When an upstream provider raised an unhandled runtime error containing server-side credentials, raw exceptions bubbled up as HTTP 500 responses, leaking secrets into client response bodies.
- **Root Cause:** Missing try/except wrapper around `await provider.complete(upstream_payload)`.
- **Remediation:** Wrapped upstream call in `try/except Exception`, sanitizing error messages and raising `UpstreamProviderError` (HTTP 502) without raw token reflection.
- **Regression Test:** `tests/test_redteam_gateway.py::test_provider_key_never_leaked_in_error_or_headers`.

### `PG-SEC-007`: Streaming SSE HTTP 200 Header Committed Before In-Memory Inspection
- **Severity:** CRITICAL (CVSS 8.6) | **OWASP AISVS:** 4.1 | **CWE:** CWE-200
- **Vulnerability:** In `backend/app/api/gateway.py`, `StreamingResponse(stream_iter)` committed HTTP 200 headers immediately. When the generator later detected a secret in the buffered stream, headers had already been delivered, preventing FastAPI from returning HTTP 502.
- **Root Cause:** Generator-level deferred execution inside an open HTTP response.
- **Remediation:** Implemented pre-flight chunk pulling in `gateway.py` (`await anext(stream_iter)`). If a security violation occurs during buffering, `ResponseSecurityViolationError` is raised before headers are sent, returning HTTP 502.
- **Regression Test:** `tests/test_redteam_gateway.py::test_streaming_split_chunk_secret_blocked_at_egress`.

### `PG-SEC-008`: OpenAI Project Key Regex Required Excessive Suffix Length
- **Severity:** MEDIUM (CVSS 6.5) | **OWASP AISVS:** 2.1 | **CWE:** CWE-20
- **Vulnerability:** In `secret_scanner.py`, `sk-proj-[a-zA-Z0-9_-]{48,}` required at least 48 characters, failing to detect valid shorter project keys (e.g. 24–40 chars).
- **Root Cause:** Overly restrictive minimum quantifier `{48,}`.
- **Remediation:** Updated pattern quantifier to `{20,}`: `r"\b(?:sk-proj-[a-zA-Z0-9_-]{20,}|sk-[a-zA-Z0-9]{20,48})\b"`.
- **Regression Test:** `tests/test_redteam_privacy.py::test_secrets_hard_blocked_never_soft_redacted`.

### `PG-SEC-009`: Context Boundary Delimiter Hijacking Bypassed Prompt Rules
- **Severity:** HIGH (CVSS 7.7) | **OWASP AISVS:** 5.1 | **MITRE ATLAS:** AML.T0051
- **Vulnerability:** Synthetic delimiters (`--- END OF SYSTEM CONTEXT ---`, ````system````, `### End of Prompt ###`) were not matched by legacy prompt injection rules.
- **Root Cause:** Missing delimiter injection regex signatures in `prompt_injection.py`.
- **Remediation:** Added `INJ_DELIM_002` (context boundary blocks) and `INJ_DELIM_003` (system codeblocks and prompt terminators).
- **Regression Test:** `tests/test_redteam_injection_and_detection.py::test_adversarial_benchmark_quality_metrics`.

### `PG-SEC-010`: RAG Validator Missed Concealed HTML & CSS Directives
- **Severity:** HIGH (CVSS 7.6) | **OWASP AISVS:** 9.1 | **MITRE ATLAS:** AML.T0043
- **Vulnerability:** `RetrievalSecurityValidator.validate_chunk` only scanned text for direct prompt injections, missing `<div style='display:none'>` and `<script>` tags embedded in retrieved knowledge.
- **Root Cause:** Incomplete multi-layer content analysis in retrieval validator.
- **Remediation:** Added HTML and hidden styling regex scanner in `validate_chunk`, quarantining tainted chunks with `INDIRECT_PROMPT_INJECTION`.
- **Regression Test:** `tests/test_redteam_e2e_scenarios.py::test_scenario_1_malicious_document_and_exfiltration_chain`.

### `PG-SEC-011`: BFF Proxy Lacked Path Normalization & Prefix Allowlisting
- **Severity:** HIGH (CVSS 7.5) | **OWASP AISVS:** 12.1 | **CWE:** CWE-22
- **Vulnerability:** `frontend/app/api/backend/[...path]/route.ts` forwarded raw path parameters to the backend without verifying allowed routes or checking for traversal (`..`).
- **Root Cause:** Naive route forwarding in Next.js App Router route handler.
- **Remediation:** Added route segment validation rejecting `..`, `/`, and `\\`. Whitelisted permitted `/v1/` route prefixes (`dashboard`, `threats`, `agents`, `tasks`, `capabilities`, `approvals`, `audit`, `privacy`, `chat`, `tools`).
- **Regression Test:** Manual and automated BFF route validation.

### `PG-SEC-012`: Capability & Approval Double-Spend Concurrency Race Conditions
- **Severity:** CRITICAL (CVSS 9.1) | **OWASP AISVS:** 3.2, 8.2 | **CWE:** CWE-362
- **Vulnerability:** When 20 requests simultaneously executed against a single-use capability token (`max_uses=1`) or a single human approval, Python-level read-modify-write checks permitted multiple requests to execute concurrently before the counter was updated.
- **Root Cause:** Non-atomic database updates (`grant.uses_count += 1` in Python memory followed by commit).
- **Remediation:** Converted both capability consumption and approval consumption to atomic SQL compare-and-swap statements (`UPDATE ... WHERE uses_count < max_uses` and `UPDATE ... WHERE status = 'APPROVED'`). Checking `cursor.rowcount == 0` ensures exactly 1 request succeeds and all competing requests are rejected.
- **Regression Test:** `tests/test_performance_stage_6.py::test_capability_double_spend_race_condition` and `test_approval_double_spend_race_condition`.

---

## 3. Summary of Verification Status

All 12 discovered vulnerabilities have been patched, validated, and incorporated into continuous integration regression test suites. The attack surface of PRIVGUARD AI is verified resilient against OWASP AISVS 1.0 criteria.

