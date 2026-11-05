# Redis Streams and Event Infrastructure in PRIVGUARD AI
## Durable Event Streams, Consumer Groups & At-Least-Once Delivery
**Agency**: Moon Sanctum Labs — *Decode. Build. Evolve.*  

---

## 1. Why Redis Streams Over Redis Pub/Sub?

Standard Redis Pub/Sub is fire-and-forget: if a subscriber replica is disconnected, restarting, or slow during an event broadcast, the message is permanently lost. 

In PRIVGUARD AI, critical security state changes—such as agent revocation, policy deployments, or threat alerts—**cannot be dropped**. Redis Streams provides:
- **Persistent storage** within Redis append-only logs (`appendonly yes`).
- **Consumer Groups** (`XGROUP`, `XREADGROUP`) distributing work across worker processes.
- **Explicit Acknowledgement** (`XACK`) ensuring failed messages are redelivered.
- **Pending Entries List (PEL)** tracking unacknowledged messages for dead-letter processing.

PRIVGUARD combines both: Redis Pub/Sub for immediate cache invalidation, and Redis Streams for guaranteed state synchronization.

---

## 2. Event Types and Topologies

| Event Type | Producer | Consumers | Guarantee |
|---|---|---|---|
| `AGENT_REVOKED` | Fleet Manager | Security Broker, Cache Invalidator | Immediate disconnect and rejection of future requests. |
| `CAPABILITY_REVOKED` | Capability Manager | Security Broker, Token Validator | Instant revocation of temporary tool tokens. |
| `POLICY_ACTIVATED` | Governance Manager | Policy Cache, Fleet Synchronizer | Hot-reload of signed Ed25519 bundles. |
| `POLICY_ROLLED_BACK`| Governance Manager | Policy Cache, Fleet Synchronizer | Immediate rollback to previous policy version. |
| `TAINT_PROPAGATED` | Taint Store | Exfiltration Detectors | Cluster-wide synchronization of tainted tasks. |
| `THREAT_DETECTED` | Threat Engine | SIEM Export, Alerting Pipeline | Real-time incident response and audit logging. |

---

## 3. Consumer Group Lifecycle & Idempotency

```
+-------------------------------------------------------------------------+
|                  REDIS STREAM: stream:events:{tenant_id}                |
|                                                                         |
|  [Msg 1: AGENT_REVOKED] -> [Msg 2: POLICY_ACTIVATED] -> [Msg 3: ...]    |
+-------------------------------------------------------------------------+
           |                                             |
           | XREADGROUP (privguard_workers)             | XREADGROUP
           v                                             v
+--------------------------+                  +--------------------------+
|  PRIVGUARD WORKER 1      |                  |  PRIVGUARD WORKER 2      |
|                          |                  |                          |
| 1. Deduplication Check   |                  | 1. Deduplication Check   |
| 2. Execute Handlers      |                  | 2. Execute Handlers      |
| 3. XACK stream message   |                  | 3. XACK stream message   |
+--------------------------+                  +--------------------------+
```

### Idempotency Enforcement

At-least-once delivery implies that duplicate messages can be delivered in failure recovery scenarios. PRIVGUARD enforces idempotency through:
1. **Unique Event IDs**: Every outbox event has an immutable UUID (`event_id`).
2. **Runtime Deduplication Set**: Consumer workers track recently processed `event_id` values. If a redelivered message is received, `XACK` is sent immediately without re-executing handlers.
3. **Database Version Check**: Handlers verify the `aggregate_version` before applying state changes to prevent out-of-order stale updates.
