# Transactional Outbox Pattern in PRIVGUARD AI
## Atomic State Mutations and Event Sourcing Guarantees
**Agency**: Moon Sanctum Labs — *Decode. Build. Evolve.*  

---

## 1. The Distributed Inconsistency Problem

In distributed systems, updating a database and publishing an event to a message broker (such as Redis or Kafka) in two separate operations introduces dual-write hazards:
1. The database commit succeeds, but the message broker publish fails (the system state changes, but other nodes are never notified).
2. The message broker publish succeeds, but the database transaction rolls back (ghost events are received by other nodes for state that never existed).

---

## 2. PRIVGUARD's Transactional Outbox Solution

PRIVGUARD AI solves dual-write inconsistencies using the **Transactional Outbox Pattern**:

```
+-------------------------------------------------------------+
|               POSTGRESQL DATABASE TRANSACTION               |
|                                                             |
|  1. UPDATE fleet_resources SET status = 'REVOKED'           |
|  2. UPDATE capability_grants SET is_revoked = TRUE          |
|  3. INSERT INTO outbox_events (event_type, aggregate_id,    |
|                                payload, status)             |
|     VALUES ('AGENT_REVOKED', 'agent_123', '{...}',          |
|             'PENDING')                                      |
|                                                             |
|                         [ COMMIT ]                          |
+-------------------------------------------------------------+
                              |
                              v (Atomic: all 3 succeed or none do)
                     [ OUTBOX EVENT TABLE ]
                              |
                              v (Polled by OutboxPublisher)
                  +------------------------+
                  |  PRIVGUARD WORKER DAEMON|
                  +------------------------+
                              |
              +---------------+---------------+
              |                               |
              v                               v
    [ REDIS STREAM (Durable) ]     [ REDIS PUB/SUB (Fast) ]
    `stream:events:{tenant_id}`    `channel:events:{tenant_id}`
```

---

## 3. Database Schema

The `outbox_events` table is protected by PostgreSQL Row-Level Security (`FORCE ROW LEVEL SECURITY`):

```sql
CREATE TABLE outbox_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(64) NOT NULL,
    workspace_id VARCHAR(64),
    event_type VARCHAR(64) NOT NULL,
    aggregate_id VARCHAR(128) NOT NULL,
    aggregate_version INTEGER DEFAULT 1,
    payload TEXT NOT NULL,
    status VARCHAR(32) DEFAULT 'PENDING',
    retry_count INTEGER DEFAULT 0,
    last_attempt_at TIMESTAMP WITH TIME ZONE,
    published_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

---

## 4. Secret Sanitization

Before serializing the payload into `outbox_events`, `emit_outbox_event()` automatically scrubs all forbidden credential patterns:
- Any payload keys containing `secret`, `password`, `token`, `key`, `dek`, or `kek` are stripped.
- Sensitive credentials remain in hardware or KMS/PostgreSQL and never transit Redis event streams.

---

## 5. Publishing Protocol

1. `OutboxPublisher.publish_pending_events()` polls up to `batch_size` pending events in ascending creation order.
2. For each event, it pushes to Redis Streams with `maxlen=10000` to prevent memory exhaustion:
   ```python
   await redis.xadd(f"stream:events:{tenant_id}", message_dict, maxlen=10000)
   ```
3. It broadcasts to Redis Pub/Sub for sub-millisecond local cache invalidation across live replicas:
   ```python
   await redis.publish(f"channel:events:{tenant_id}", json_string)
   ```
4. Upon successful push, it updates the database record status to `'PUBLISHED'` with `published_at = NOW()`.
5. If publishing fails, the event remains `'PENDING'` with incremented `retry_count` for safe backoff.
