# PRIVGUARD AI — Redis State Reconstruction & Recovery Semantics

Organization: Moon Sanctum Labs  
Motto: *Decode. Build. Evolve.*  
Date: November 2026

---

## 1. Redis State Classification

PRIVGUARD AI uses Redis for high-throughput distributed caching, token bucket rate limiting, and real-time event streaming. Following a Redis outage, flush, or disaster recovery restart, state is reconstructed category-by-category:

| State Category | Persistence Strategy | Recovery Reconstruction Action |
| :--- | :--- | :--- |
| **Revocation Cache** | Volatile in Redis | Reconstructed from PostgreSQL `CapabilityGrant.is_revoked` and the independent `revocation_journal.log`. |
| **Active Taint State** | Volatile in Redis | Reconstructed from PostgreSQL `ActiveTaint` records. |
| **Policy Bundles** | Volatile in Redis | Re-parsed and loaded from PostgreSQL `PolicyBundle` records where `status = 'ACTIVE'`. |
| **Outbox Event Streams** | In Redis Stream `stream:events` | Pending events from PostgreSQL `OutboxEvent` (`status = 'PENDING'`) are re-published with `replayed_on_recovery: true`. |
| **Distributed Rate Limits** | Ephemeral sliding window counters | **Safe Restriction Mode** engages for 10 minutes (600s), enforcing a strict 50% capacity ceiling to prevent post-restart abuse. |

---

## 2. Reconciliation Protocol (`app.recovery.redis_reconciliation`)

On service boot or disaster recovery execution, `reconcile_redis_on_recovery()` runs automatically:

```python
from app.recovery.redis_reconciliation import reconcile_redis_on_recovery

summary = await reconcile_redis_on_recovery(
    db=db_session,
    redis_client=redis_client,
    warmup_safe_mode_seconds=600,
)
```

### Warmup Rate Limiting (Safe Restriction Mode)
During the 10-minute warmup window:
1. `system:safe_restriction_mode` is set with a 600-second TTL.
2. The distributed rate limiter checks this key:
   - If present, standard rate limits are cut by 50%.
   - In-flight abuse bursts following a cold start are blocked immediately.
   - Once the TTL expires, normal traffic limits resume automatically.

