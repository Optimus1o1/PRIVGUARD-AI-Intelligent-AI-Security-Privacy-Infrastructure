# Distributed Revocation Enforcement in PRIVGUARD AI
## Immediate Cross-Replica Agent & Capability Disablement
**Agency**: Moon Sanctum Labs — *Decode. Build. Evolve.*  

---

## 1. The Revocation Challenge

Consider an autonomous AI agent operating across a fleet:
- The agent is currently connected to **Replica 1**.
- A security administrator discovers a security breach and triggers revocation via the Control Center connected to **Replica 2**.
- The agent initiates a high-risk tool call (e.g., executing a database write or file deletion) routed to **Replica 3**.

If Replica 3 relies on stale local in-memory state, the rogue agent will successfully execute unauthorized operations.

---

## 2. PRIVGUARD's Multi-Tier Revocation Architecture

PRIVGUARD enforces revocation across three coordinated tiers:

```
[ ADMIN ACTION ] -> Replica 2
        |
        +---> 1. Database Tier (PostgreSQL Authority)
        |        - FleetResource.status = 'REVOKED'
        |        - Agent.status = 'REVOKED'
        |        - CapabilityGrant.is_revoked = TRUE
        |        - INSERT INTO outbox_events ('AGENT_REVOKED')
        |        [ COMMIT ]
        |
        +---> 2. Fast Invalidation Tier (Redis Pub/Sub & Key Expire)
        |        - DEL revocations:{tenant_id}:{agent_id}
        |        - PUBLISH channel:events:{tenant_id} (Revocation payload)
        |        - Replica 1 & Replica 3 purge local caches within < 5ms
        |
        +---> 3. Execution-Time Verification (Broker Fallback)
                 - Agent Security Broker queries PostgreSQL before dispatching tools
                 - Revoked agent is blocked even if Redis is completely partitioned
```

---

## 3. Tool Execution Mediation Workflow

Whenever an agent attempts to execute a tool:
1. The **Agent Security Broker** checks the agent's active status.
2. The broker checks the specific temporary capability token.
3. If either the agent or the capability is marked as `REVOKED` in PostgreSQL, the request is immediately aborted with `UnauthorizedToolError`.
4. The event is recorded in `threat_events` and SIEM audit logs as an attempted unauthorized execution post-revocation.
