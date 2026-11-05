# PRIVGUARD AI — Stage 10.3 Architecture Specification
## Distributed State Management, Redis Coordination & PostgreSQL Authority
**Agency**: Moon Sanctum Labs — *Decode. Build. Evolve.*  
**Lead Developer**: Aniket Nandi (Kolkata, IST)  
**Milestone**: Stage 10.3  

---

## 1. Architectural Vision

When enterprise customers deploy PRIVGUARD AI in production, high availability and horizontal scalability necessitate running multiple backend instances (e.g. 3+ replicas) behind a reverse proxy or load balancer. 

Stage 10.3 guarantees **cluster-wide security invariants**:
An administrative revocation or taint event issued on Instance 1 must be authoritatively enforced on Instances 2 and 3 without window-of-vulnerability races.

```
                            INTERNET
                               |
                               v
                       [ REVERSE PROXY ]
                    TLS Termination / Caddy
                               |
              +----------------+----------------+
              |                                 |
              v                                 v
    [ NEXT.JS FRONTEND 1 ]            [ NEXT.JS FRONTEND 2 ]
              |                                 |
              +----------------+----------------+
                               |
              +----------------+----------------+
              |                                 |
              v                                 v
     [ PRIVGUARD BACKEND 1 ]           [ PRIVGUARD BACKEND 2 ]
     FastAPI (Port 8000)               FastAPI (Port 8000)
              |                                 |
              +----------------+----------------+
                               |
                 +-------------+-------------+
                 |                           |
                 v                           v
     +-----------------------+   +-----------------------+
     |   POSTGRESQL 16 (RLS) |   |        REDIS 7        |
     |  Authoritative Truth  |   | Coordination & Cache  |
     |                       |   |                       |
     | - Outbox Events       |   | - Sliding Window RL   |
     | - Active Taints       |   | - Event Streams       |
     | - Capability Grants   |   | - Distributed Taint   |
     | - Policies & Fleet    |   | - Invalidation PubSub |
     +-----------------------+   +-----------------------+
                 ^                           ^
                 |                           |
                 +-------------+-------------+
                               |
                     [ PRIVGUARD WORKER ]
                  Outbox Relay & Stream Bus
```

---

## 2. The Five Invariants

| Invariant | Description | Enforcement Mechanism |
|---|---|---|
| **1. PostgreSQL as Sole Authority** | Redis is strictly a transient coordination layer and cache. System state, capability grants, audit records, and policies live permanently in PostgreSQL. | If Redis fails or is partitioned, PostgreSQL transactions continue and outbox events accumulate until Redis recovers. |
| **2. Transactional Outbox** | Mutating security state and emitting an event happen in the exact same SQL transaction. | `emit_outbox_event()` creates an `OutboxEvent` record inside the active transaction. If the transaction rolls back, no event is published. |
| **3. At-Least-Once Delivery** | Redis Streams with consumer groups guarantee messages survive process restarts and node crashes. | `XREADGROUP` reads messages; `XACK` is only sent after successful handler execution. Duplicate IDs are pruned via runtime deduplication caches. |
| **4. Execution-Time Revocation** | In addition to Redis Pub/Sub invalidation, the Agent Security Broker checks PostgreSQL at tool execution time. | Offline agents or partitioned nodes cannot execute tools using revoked capabilities. |
| **5. Monotonic Taint Tracking** | Once a task session touches confidential data, that taint persists across all replicas. | Taint is recorded in PostgreSQL `ActiveTaint` and cached in Redis. Querying taint checks both Redis and PostgreSQL monotonically. |

---

## 3. Component Breakdown

- **`app.infrastructure.redis_client`**: Centralized async Redis connection pool (`redis.asyncio.ConnectionPool`) with tenant-aware key namespacing (`rl:`, `taint:`, `policy:`, `revocations:`, `stream:events:`).
- **`app.infrastructure.rate_limiter`**: Distributed sliding-window rate limiter evaluated via an atomic Lua script on Redis sorted sets. Falls back to process-local sliding windows if Redis is unavailable.
- **`app.infrastructure.outbox`**: Transactional outbox implementation (`emit_outbox_event`) and background batch publisher (`OutboxPublisher`).
- **`app.infrastructure.event_bus`**: Redis Streams consumer group manager with idempotent dispatch and explicit ACK protocol.
- **`app.infrastructure.event_worker`**: Dedicated background daemon service continuously relaying pending outbox events to Redis Streams.
- **`app.infrastructure.taint_store`**: Monotonic distributed taint manager backed by PostgreSQL `active_taints` and Redis sets.
- **`app.api.system`**: Operational health probes and cluster state diagnostics (`/health/redis`, `/health/database`, `/v1/system/distributed-state`, `/v1/system/rate-limit-statistics`, `/v1/system/event-processing`).
