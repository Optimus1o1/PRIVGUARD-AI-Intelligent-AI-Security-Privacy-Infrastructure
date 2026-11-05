# PRIVGUARD AI — Stage 6 Remediation Log & Security Ledger
**Moon Sanctum Labs** — *Decode. Build. Evolve.*  
**Author:** ANIKET NANDI (Kolkata, IST)

---

## 1. Remediation Summary Table

| Finding ID | Vulnerability Classification | Affected Component | File Modified | Status |
| :---: | :---: | :---: | :---: | :---: |
| **`PG-SEC-001`** | Action Hash HMAC Keying | Approval Engine | `backend/app/approvals/approval_engine.py` | **VERIFIED** |
| **`PG-SEC-002`** | IDOR on Taint & Behavior APIs | Threats API | `backend/app/api/threats.py` | **VERIFIED** |
| **`PG-SEC-003`** | Multi-Tenant Sandbox Jailing | Sandboxed Executor | `backend/app/agent_security/executor.py` | **VERIFIED** |
| **`PG-SEC-004`** | Path Traversal & Drive Stripping | Sandboxed Executor | `backend/app/agent_security/executor.py` | **VERIFIED** |
| **`PG-SEC-005`** | SSRF & Arbitrary Model Fallback | Provider Registry | `backend/app/providers/registry.py` | **VERIFIED** |
| **`PG-SEC-006`** | Upstream Exception Token Leakage | Upstream Proxy | `backend/app/gateway/upstream.py` | **VERIFIED** |
| **`PG-SEC-007`** | Streaming Pre-Flight Validation | Gateway API & Stream | `backend/app/api/gateway.py` | **VERIFIED** |
| **`PG-SEC-008`** | OpenAI Project Key Suffix Length | Secret Scanner | `backend/app/privacy/secret_scanner.py` | **VERIFIED** |
| **`PG-SEC-009`** | Synthetic Context Delimiters | Injection Rules | `backend/app/threat_detection/rules/prompt_injection.py` | **VERIFIED** |
| **`PG-SEC-010`** | RAG HTML/CSS Poisoning Scan | Retrieval Security | `backend/app/threat_detection/retrieval_security.py` | **VERIFIED** |
| **`PG-SEC-011`** | BFF Proxy Traversal & Route Filter | Next.js BFF Route | `frontend/app/api/backend/[...path]/route.ts` | **VERIFIED** |
| **`PG-SEC-012`** | Double-Spend CAS Race Conditions | Capability & Approval | `backend/app/agent_security/capability_manager.py` | **VERIFIED** |

---

## 2. Technical Remediation Entries

### `PG-SEC-001`: Cryptographic Action Hash HMAC Keying
- **Location:** `backend/app/approvals/approval_engine.py`
- **Root Cause:** Parameters were hashed using standard unkeyed SHA-256.
- **Fix:** Switched to HMAC-SHA256 keyed with `settings.PRIVGUARD_MASTER_KEY`:
  ```python
  hmac.new(settings.PRIVGUARD_MASTER_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
  ```
- **Regression Suite:** `tests/test_redteam_approvals.py::test_parameter_tampering_attack_rejected`.

### `PG-SEC-002`: IDOR Protection on Taint & Behavior APIs
- **Location:** `backend/app/api/threats.py`
- **Root Cause:** Task IDs were queried without checking ownership against `app.id`.
- **Fix:** Added tenant-scoped database query `select(AgentTask).where(AgentTask.id == task_id, AgentTask.app_id == app.id)` raising HTTP 404 `TASK_NOT_FOUND` if task does not belong to the calling application.
- **Regression Suite:** `tests/test_redteam_exfiltration.py::test_taint_query_idor_protection`.

### `PG-SEC-003` & `PG-SEC-004`: Sandbox Traversal & Multi-Tenant Jailing
- **Location:** `backend/app/agent_security/executor.py` & `tool_broker.py`
- **Root Cause:** Path strings were stripped before boundary validation, converting absolute paths into relative paths, and files were placed in a global directory.
- **Fix:** Validated raw paths upfront before stripping, rejecting `/`, `\\`, `..`, and drive letters with HTTP 403 `PATH_TRAVERSAL_DETECTED`. Scoped directory resolution to `(SANDBOX_DIR / app_id)`. Tool Broker now injects `params["_app_id"] = app.id`.
- **Regression Suite:** `tests/test_redteam_agent_broker.py::test_filesystem_sandbox_directory_traversal_blocked`.

### `PG-SEC-005`: SSRF & Arbitrary Model Parameter Rejection
- **Location:** `backend/app/providers/registry.py`
- **Root Cause:** Default fallback accepted arbitrary model strings, permitting SSRF and internal port probing.
- **Fix:** Rejected URIs, path separators, and port delimiters. Enforced strict prefix checking against allowed model families (`gpt-*`, `mock-*`, `claude-*`, etc.); unconfigured models fail closed with HTTP 400 `MODEL_NOT_CONFIGURED`.
- **Regression Suite:** `tests/test_redteam_gateway.py::test_ssrf_and_unconfigured_model_rejection`.

### `PG-SEC-006`: Upstream Provider Exception Token Sanitization
- **Location:** `backend/app/gateway/upstream.py`
- **Root Cause:** Raw provider exceptions bubbled up as unhandled HTTP 500 errors.
- **Fix:** Caught exceptions in `execute_completion`, sanitizing messages and returning `UpstreamProviderError` (HTTP 502) without leaking credentials or internal host details.
- **Regression Suite:** `tests/test_redteam_gateway.py::test_provider_key_never_leaked_in_error_or_headers`.

### `PG-SEC-007`: Pre-Flight Streaming Buffer Egress Protection
- **Location:** `backend/app/api/gateway.py` & `backend/app/gateway/streaming.py`
- **Root Cause:** `StreamingResponse` committed HTTP 200 headers before the generator could inspect buffered text.
- **Fix:** Implemented pre-flight chunk pulling in `gateway.py`. If a violation is caught in the buffer, `ResponseSecurityViolationError` is raised before headers are sent, returning HTTP 502.
- **Regression Suite:** `tests/test_redteam_gateway.py::test_streaming_split_chunk_secret_blocked_at_egress`.

### `PG-SEC-008`: OpenAI Project Key Regex Quantifier Update
- **Location:** `backend/app/privacy/secret_scanner.py`
- **Root Cause:** Suffix length `{48,}` was too strict, failing on shorter project keys.
- **Fix:** Updated regex to `r"\b(?:sk-proj-[a-zA-Z0-9_-]{20,}|sk-[a-zA-Z0-9]{20,48})\b"`.
- **Regression Suite:** `tests/test_redteam_privacy.py::test_secrets_hard_blocked_never_soft_redacted`.

### `PG-SEC-009`: Synthetic Context Boundary Delimiter Rules
- **Location:** `backend/app/threat_detection/rules/prompt_injection.py`
- **Root Cause:** Boundary overrides (`--- END OF SYSTEM CONTEXT ---`, ````system````, `### End of Prompt`) were unmonitored.
- **Fix:** Added `INJ_DELIM_002` and `INJ_DELIM_003` to match boundary tokens, markdown enclosures, and section terminators.
- **Regression Suite:** `tests/test_redteam_injection_and_detection.py::test_adversarial_benchmark_quality_metrics`.

### `PG-SEC-010`: RAG Knowledge Chunk Multi-Layer Poisoning Scan
- **Location:** `backend/app/threat_detection/retrieval_security.py`
- **Root Cause:** Validator only checked direct prompt injections, missing embedded scripts and hidden CSS.
- **Fix:** Integrated regex scanning for HTML tags, `<script>`, and hidden CSS properties in `validate_chunk`.
- **Regression Suite:** `tests/test_redteam_e2e_scenarios.py::test_scenario_1_malicious_document_and_exfiltration_chain`.

### `PG-SEC-011`: BFF Proxy Hardening & Route Whitelisting
- **Location:** `frontend/app/api/backend/[...path]/route.ts`
- **Root Cause:** Path segments were forwarded directly without validation.
- **Fix:** Validated path segments for traversal (`..`), checked root prefix against an allowlist of permitted `/v1/` routes, and failed closed if the backend API key is unset.
- **Regression Suite:** BFF Proxy route unit tests.

### `PG-SEC-012`: Atomic Compare-and-Swap Concurrency Fixes
- **Location:** `backend/app/agent_security/capability_manager.py` & `backend/app/approvals/approval_engine.py`
- **Root Cause:** Read-modify-write pattern in Python memory permitted race conditions under 20 concurrent requests.
- **Fix:** Migrated to atomic SQL updates (`UPDATE ... WHERE uses_count < max_uses` and `UPDATE ... WHERE status = 'APPROVED'`). Checking `cursor.rowcount == 0` guarantees exactly 1 request succeeds and all others are rejected.
- **Regression Suite:** `tests/test_performance_stage_6.py::test_capability_double_spend_race_condition` and `test_approval_double_spend_race_condition`.

