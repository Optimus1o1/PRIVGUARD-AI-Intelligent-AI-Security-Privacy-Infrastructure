# Deterministic Chaos Engineering Framework

**PRIVGUARD AI** — *Independent Security & Privacy Enforcement Layer for Agentic AI*  
**Organization:** Moon Sanctum Labs — *Decode. Build. Evolve.*  
**Lead Engineer:** ANIKET NANDI (Kolkata, IST)

---

## 1. Overview & Principles

Unlike stochastic fault injection (e.g., Chaos Monkey) that relies on random instance termination in staging environments, PRIVGUARD AI requires **deterministic, repeatable chaos engineering**. 

Every failure mode must be reproducible in continuous integration with sub-second feedback loops, verifying that security invariants hold under extreme distributed-system stress.

### Core Chaos Principles
1. **Determinism:** Tests run predictably in standard CI environments without flaky timeouts or race flakiness.
2. **Authoritative State Isolation:** PostgreSQL is the single authoritative source of truth. Redis outages must never lead to permissive fail-open conditions or stale authorization grants.
3. **Cryptographic Tag Integrity:** Any bit-level tampering in ciphertext or action parameters must be intercepted before decryption or execution occurs.
4. **Zero-Plaintext Invariant:** Regardless of how a downstream service (KMS, Redis, LLM, Database) fails, unencrypted data must never be returned to client or logged.

---

## 2. Framework Architecture & Fixtures

Located at [`backend/tests/chaos/conftest.py`](file:///c:/Users/ANIKET/OneDrive/Documents/RIVA_AI/backend/tests/chaos/conftest.py):

```
                   +----------------------------------+
                   |       Chaos Test Harness         |
                   +----------------------------------+
                                    |
          +-------------------------+-------------------------+
          |                         |                         |
          v                         v                         v
+-------------------+     +-------------------+     +-------------------+
|  ChaosRedisClient |     |  ChaosKMSProvider |     |  chaos_db_factory |
| - disconnect()    |     | - simulate_500()  |     | - SQLite WAL Mode |
| - timeout()       |     | - drop_socket()   |     | - Multi-Session   |
| - partition()     |     | - corrupt_tag()   |     | - Concurrency CAS |
+-------------------+     +-------------------+     +-------------------+
```

### 2.1 `ChaosRedisClient`
Simulates distributed cache and pub/sub transport disruptions:
- `disconnect()`: Simulates network severance (`ConnectionError: Connection refused`).
- `inject_timeout(latency_sec)`: Injects artificial network latency exceeding client thresholds (`TimeoutError`).
- `network_partition()`: Rejects read/write operations while retaining existing memory keys to simulate split-brain conditions.

### 2.2 `ChaosKMSProvider`
Validates envelope encryption security when external Key Management Services fail:
- Simulates HTTP 500 / 503 internal KMS outages during `unwrap_dek()`.
- Drops TCP connections mid-handshake.
- Injects corrupted key encryption tags to verify `CryptographicVerificationError` and `MemorySecurityError`.

### 2.3 `chaos_db_factory`
Provides high-concurrency database isolation:
- Operates on a dedicated temporary SQLite instance running with `PRAGMA journal_mode=WAL;` and `PRAGMA synchronous=NORMAL;`.
- Allows multiple independent asynchronous sessions (`AsyncSession`) to run concurrently without table-locking or cursor collision bugs.
- Perfectly validates SQL compare-and-swap (CAS) queries and transaction rollbacks under high coroutine concurrency.

---

## 3. Test Suites Directory

The chaos test suite resides in [`backend/tests/chaos/`](file:///c:/Users/ANIKET/OneDrive/Documents/RIVA_AI/backend/tests/chaos/):

```
backend/tests/chaos/
├── conftest.py                       # Chaos test fixtures & fault injectors
├── test_security_fail_closed.py      # Redis & KMS outage fail-closed verification (4 tests)
├── test_distributed_chaos.py         # Outbox relay durability & dead-letter queue (3 tests)
├── test_concurrency_and_races.py     # Concurrent approval & capability CAS races (4 tests)
├── test_resource_exhaustion.py       # Payload size limits, step quotas, timeouts (4 tests)
└── test_adversarial_chaos.py         # Parameter tampering, tenant injection, poisoned tools (4 tests)
```

### Summary of Verifications

| Test Module | Tests | Description |
| :--- | :--- | :--- |
| `test_security_fail_closed.py` | 4 | Verifies Redis/KMS outages trigger HTTP 503 / `MemorySecurityError` with zero plaintext leakage; agent revocation in DB survives Redis death; mid-task revocation stops execution. |
| `test_distributed_chaos.py` | 3 | Verifies outbox events persist during Redis disconnection and flush upon recovery; verifies poisoned events transition to dead-letter queue after 5 retries; verifies transaction atomicity. |
| `test_concurrency_and_races.py` | 4 | Tests 10 concurrent requests consuming 1 approval (1 succeeds, 9 fail with `APPROVAL_ALREADY_CONSUMED`); 10 concurrent requests consuming single-use capability (1 succeeds, 9 fail); mid-task revocation race; task expiry race. |
| `test_resource_exhaustion.py` | 4 | Tests rejection of >10 MB payloads with HTTP 413; chunked streaming byte limit enforcement; agent step budget enforcement (`STEP_LIMIT_EXCEEDED`); upstream socket timeout enforcement (HTTP 504). |
| `test_adversarial_chaos.py` | 4 | Tests approval parameter tampering detection (`APPROVAL_TAMPERING_DETECTED`); cross-tenant parameter injection (`TenantIsolationError`); ciphertext bit-flipping failure (`MemoryTamperingError`); MCP output credential leak detection (`ResponseSecurityViolationError`). |

---

## 4. How to Run the Chaos Test Suite

Execute all deterministic chaos tests locally:

```bash
# Run complete chaos suite with verbose progress
pytest backend/tests/chaos/ -v

# Run specific chaos module
pytest backend/tests/chaos/test_concurrency_and_races.py -v

# Run with execution timing profile
pytest backend/tests/chaos/ -v --durations=10
```
