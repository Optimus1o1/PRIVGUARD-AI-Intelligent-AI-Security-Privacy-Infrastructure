# Failure Mode & Effects Analysis (FMEA)

**PRIVGUARD AI** — *Independent Security & Privacy Enforcement Layer for Agentic AI*  
**Organization:** Moon Sanctum Labs — *Decode. Build. Evolve.*  
**Lead Engineer:** ANIKET NANDI (Kolkata, IST)

---

## 1. FMEA Scope & Methodology

This analysis catalogs all critical failure modes across the PRIVGUARD AI architecture, evaluating:
- **Severity (S):** 1 (negligible) to 10 (catastrophic / security breach)
- **Occurrence (O):** 1 (extremely rare) to 10 (inevitable in distributed environments)
- **Detection (D):** 1 (immediately detected at edge) to 10 (silent failure / undetected)
- **Risk Priority Number (RPN):** $S \times O \times D$ (Range: 1 – 1000)

Every failure mode with RPN > 100 has dedicated automated mitigation and deterministic chaos test coverage.

---

## 2. Failure Mode Catalog

| Failure Mode ID | Component / Boundary | Potential Cause | Failure Effect | S | O | D | RPN | Mitigation Strategy | Chaos Test Coverage |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **FM-01** | **PostgreSQL Connection Pool** | Connection leak or slow queries | `TimeoutError` on DB connection checkout | 8 | 4 | 2 | **64** | SQLAlchemy pool timeout (30s), recycled connections (1800s), health probes emit HTTP 503 | `backend/tests/chaos/test_distributed_chaos.py` |
| **FM-02** | **Redis Complete Outage** | Network partition, node restart | Distributed cache & pub/sub inaccessible | 7 | 5 | 2 | **70** | Fail-closed on sensitive reads; fallback to PostgreSQL authoritative state; zero ghost capabilities | `backend/tests/chaos/test_security_fail_closed.py` |
| **FM-03** | **KMS Outage during Memory Read** | Cloud KMS network drop, 500 error | Decryption of user memory fails | 9 | 3 | 2 | **54** | Fail-closed; raise `MemorySecurityError`; zero fallback to unencrypted memory or cached plaintext | `backend/tests/chaos/test_security_fail_closed.py` |
| **FM-04** | **Approval Parameter Tampering** | Adversary injects modified command post-approval | Malicious tool action executed under valid approval | 10 | 3 | 1 | **30** | Cryptographic HMAC action hash verification (`APPROVAL_TAMPERING_DETECTED`, HTTP 403) | `backend/tests/chaos/test_adversarial_chaos.py` |
| **FM-05** | **Approval Replay / Double-Spend** | Concurrent coroutines racing to consume single approval | Tool executed multiple times from 1 approval | 9 | 5 | 1 | **45** | SQL-level atomic Compare-And-Swap (`UPDATE ... WHERE status = 'APPROVED'`) | `backend/tests/chaos/test_concurrency_and_races.py` |
| **FM-06** | **Capability Quota Exhaustion Race** | Parallel threads executing on single-use capability token | Quota exceeded / unauthorized tool execution | 8 | 5 | 1 | **40** | SQL-level atomic counter increment (`uses_count < max_uses`) | `backend/tests/chaos/test_concurrency_and_races.py` |
| **FM-07** | **Oversized Payload Memory Exhaustion** | Adversary transmits > 100 MB request body | API gateway Out-Of-Memory (OOM) crash | 8 | 5 | 1 | **40** | `RequestSizeLimitMiddleware` terminates requests > 10 MB at ASGI layer with HTTP 413 | `backend/tests/chaos/test_resource_exhaustion.py` |
| **FM-08** | **Streaming Chunk Exhaustion Attack** | Chunked streaming body lacking Content-Length | Slowloris / streaming buffer memory exhaustion | 8 | 4 | 1 | **32** | Cumulative byte counter in `limited_receive()` aborts mid-stream upon reaching 10 MB limit | `backend/tests/chaos/test_resource_exhaustion.py` |
| **FM-09** | **Runaway Agent Tool Loop** | Prompt injection / model hallucination infinite loop | System resource exhaustion & runaway API costs | 7 | 6 | 1 | **42** | `record_step()` tracks task steps; transitions to `STEP_LIMIT_EXCEEDED` (HTTP 429); revokes tokens | `backend/tests/chaos/test_resource_exhaustion.py` |
| **FM-10** | **Hanging Upstream MCP Server** | Upstream MCP tool or external network socket hangs | Worker coroutine thread exhaustion | 8 | 5 | 1 | **40** | `asyncio.wait_for()` timeout enforced per tool; raises HTTP 504 `TOOL_EXECUTION_TIMEOUT` | `backend/tests/chaos/test_resource_exhaustion.py` |
| **FM-11** | **Cross-Tenant Header Injection** | Malicious tenant attempts to pass foreign Tenant ID | Cross-tenant data leakage / privilege escalation | 10 | 2 | 1 | **20** | `resolve_tenant_context` validates API key against tenant ownership; raises `TenantIsolationError` | `backend/tests/chaos/test_adversarial_chaos.py` |
| **FM-12** | **Ciphertext Storage Bit Corruption** | Hardware fault or unauthorized direct DB modification | Corrupted plaintext returned to caller | 9 | 2 | 1 | **18** | AES-256-GCM authentication tag verification fails; raises `MemoryTamperingError` | `backend/tests/chaos/test_adversarial_chaos.py` |
| **FM-13** | **Upstream Tool Credential Poisoning** | External MCP server returns output containing credentials | Sensitive credentials leaked into agent prompt | 9 | 4 | 1 | **36** | Output secret scanner intercepts AWS/API keys; raises `ResponseSecurityViolationError` (HTTP 502) | `backend/tests/chaos/test_adversarial_chaos.py` |
| **FM-14** | **Outbox Relay Worker Crash** | Worker process dies mid-batch | Un-dispatched audit events stranded | 7 | 4 | 2 | **56** | Transactional outbox retains events in PostgreSQL; survivor worker resumes FIFO dispatch | `backend/tests/chaos/test_distributed_chaos.py` |
| **FM-15** | **Poison Pill Event in Outbox** | Un-serializable event payload repeatedly crashes relay | Entire audit log dispatch pipeline blocked | 8 | 3 | 2 | **48** | Retry counter increments; transitions to `FAILED_DEAD_LETTER` after 5 failures | `backend/tests/chaos/test_distributed_chaos.py` |

---

## 3. Residual Risk Assessment

All 15 identified failure modes have technical controls and automated tests validating that:
1. **No single point of failure** can lead to plaintext leakage or privilege escalation.
2. **Fail-Closed Guarantees** ensure that any ambiguity in state or network connectivity results in execution denial rather than permissive bypass.
3. **Audit Trails are preserved** even when external logging systems are temporarily unavailable.

