# Distributed Taint Tracking in PRIVGUARD AI
## Multi-Node Provenance & Monotonic Exfiltration Defense (MITRE ATT&CK T1700)
**Agency**: Moon Sanctum Labs — *Decode. Build. Evolve.*  

---

## 1. Problem Statement

Autonomous agents perform complex workflows across multiple subtasks. When an agent reads sensitive data (e.g. employee compensation, API credentials, customer PII) on **Node 1**, the task context becomes **tainted**.

If the agent later delegates an outbound request (such as sending an HTTP webhook or email) that is handled by **Node 2**, Node 2 must be aware of the prior taint to prevent covert data exfiltration.

---

## 2. Distributed Taint Architecture

PRIVGUARD implements monotonic taint tracking using `DistributedTaintStore`:

```
[ NODE 1 ]
Agent reads 'customer_pii.csv' via SENSITIVE_READ_TOOLS
    |
    v
DistributedTaintStore.add_taint()
    |
    +---> 1. Persist to PostgreSQL `active_taints` table
    +---> 2. SADD to Redis set `taint:{tenant_id}:{task_id}` (24h TTL)
    +---> 3. Update Node 1 local in-memory cache

--------------------------------------------------------------

[ NODE 2 ]
Agent attempts `post_webhook` to external untrusted URL
    |
    v
ExfiltrationDetector.evaluate_outbound_tool()
    |
    v
DistributedTaintStore.is_task_tainted()
    |
    +---> 1. SCARD `taint:{tenant_id}:{task_id}` on Redis
    |        (Returns > 0 -> Tainted!)
    |
    +---> 2. If Redis offline: Fallback query to PostgreSQL `active_taints`
    |
    v
Destination Allowlist Check:
    'https://attacker.evil.com/leak' not in allowlisted domains!
    |
    v
[ ACTION: BLOCK & RAISE THREAT ALERT ]
```

---

## 3. Monotonic Guarantee

Taint is strictly monotonic:
- **Taint can only be added** during a task session; it cannot be diminished or partially cleared while the session is active.
- Clearing taint (`clear_task_taints`) is only permitted when a task explicitly terminates, and atomically purges both the PostgreSQL table and the Redis set.
- If Redis is partitioned, the PostgreSQL fallback ensures that no node will erroneously treat a tainted task as clean.
