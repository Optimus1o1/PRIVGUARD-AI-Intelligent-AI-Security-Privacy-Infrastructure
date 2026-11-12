# System Recovery & Self-Healing Behavior

**PRIVGUARD AI** — *Independent Security & Privacy Enforcement Layer for Agentic AI*  
**Organization:** Moon Sanctum Labs — *Decode. Build. Evolve.*  
**Lead Engineer:** ANIKET NANDI (Kolkata, IST)

---

## 1. Recovery Objectives & SLAs

In distributed systems, infrastructure components (caches, message brokers, external key vaults) inevitably experience partitions, restarts, and network partitions. PRIVGUARD AI is engineered around predictable recovery timelines and strict zero-loss, zero-leak guarantees.

| Architectural Component | Recovery Mechanism | Target RTO | Target RPO | Measured Consistency |
| :--- | :--- | :--- | :--- | :--- |
| **PostgreSQL Database** | Managed WAL standby promotion & pooled reconnects | < 30 seconds | 0 seconds (RPO=0) | ACID transactions guarantee atomicity |
| **Redis Cache / PubSub** | Automatic exponential backoff & fail-closed bypass | < 5 seconds | N/A (ephemeral) | Stored state in PostgreSQL is authoritative |
| **Transactional Outbox** | Background worker polling & guaranteed delivery | < 10 seconds | 0 seconds (RPO=0) | Zero lost events; deduplicated via event IDs |
| **Dead-Letter Queue (DLQ)** | Automated quarantine after 5 failed retries | Immediate | 0 seconds (RPO=0) | Poison pill isolated; healthy events resume |
| **KMS Key Vault** | Retry with jitter & circuit-breaker trip | < 15 seconds | 0 seconds (RPO=0) | Envelope encryption blocks unverified requests |
| **MCP Tool Upstream** | Per-tool timeout & immediate caller notification | Immediate | N/A | HTTP 504 emitted; agent state marked for retry |

---

## 2. Component Recovery Lifecycles

### 2.1 Transactional Outbox Recovery
When Redis or the external SIEM forwarder experiences an outage, audit events cannot be pushed into the live stream:
1. **Durable Persistence:** The FastAPI gateway writes the audit event directly into the `audit_outbox` table within the same PostgreSQL transaction as the operational record.
2. **Backpressure Containment:** The outbox worker detects the Redis connection failure, increments `retry_count`, and pauses dispatch with exponential backoff (initial: 100ms, max: 10s).
3. **Resumption & Flushing:** Once the connection is re-established, the worker processes un-dispatched events in FIFO order by `created_at`.
4. **Dead-Letter Isolation:** If an individual event triggers a persistent deserialization or payload error 5 consecutive times, it is marked `FAILED_DEAD_LETTER` to prevent pipeline head-of-line blocking.

```
+--------------------+        +-------------------------+
| FastAPIGateway     | -----> | PostgreSQL Transaction  |
| (Records Action)   |        | [Operation + Outbox Row]|
+--------------------+        +-------------------------+
                                           |
                                           v
+--------------------+        +-------------------------+
| Redis / SIEM       | <====  | Background Outbox Relay |
| (Down / Outage)    |  PAUSE | (Polls & Retries FIFO)  |
+--------------------+        +-------------------------+
```

### 2.2 Redis Outage & Cache Reconciliation
1. **Authoritative Revocations:** Agent, task, and capability revocations are committed synchronously to PostgreSQL.
2. **Fail-Closed Fallback:** When Redis is unreachable:
   - Sensitive cache reads (e.g. distributed policy bundles, live secrets) fail closed and query PostgreSQL directly or return HTTP 503.
   - Non-critical telemetry falls back gracefully without impeding API availability.
3. **Cache Invalidation on Recovery:** Upon Redis reconnection, cached agent tokens with stale `ACTIVE` statuses are superseded because authorization checks perform authoritative DB lookups.

### 2.3 KMS Outage & Memory Vault Recovery
1. **Zero-Plaintext Policy:** If the external KMS provider (AWS KMS, Google Cloud KMS, Vault) is down during memory retrieval, decryption of the wrapped DEK fails immediately.
2. **Circuit Breaking:** The KMS provider client trips its circuit breaker after 5 consecutive failures, fast-failing subsequent decryption requests for 30 seconds to prevent downstream thread starvation.
3. **Self-Healing Probes:** Background health checks periodically issue a test unwrap operation. As soon as the probe succeeds, the circuit breaker resets to closed.

---

## 3. Disaster Recovery & Manual Runbooks

### 3.1 Unwedging Stuck Tasks
If an agent task hangs waiting for an upstream tool that never responded and the worker crashed before timeout could trigger:
```bash
# Cancel stuck task and automatically revoke active capability tokens
curl -X POST "https://privguard.internal/v1/tasks/{task_id}/cancel" \
  -H "X-API-Key: $ADMIN_API_KEY"
```

### 3.2 Reprocessing Dead-Letter Outbox Events
Once the downstream SIEM or Redis consumer issue is resolved:
```sql
-- Identify failed dead-letter events
SELECT id, event_type, retry_count, last_error, created_at 
FROM audit_outbox 
WHERE status = 'FAILED_DEAD_LETTER' 
ORDER BY created_at DESC;

-- Requeue events for reprocessing
UPDATE audit_outbox 
SET status = 'PENDING', retry_count = 0 
WHERE status = 'FAILED_DEAD_LETTER';
```

