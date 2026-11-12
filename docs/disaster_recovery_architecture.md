# PRIVGUARD AI — Disaster Recovery Architecture & Invariant Guarantees

Organization: Moon Sanctum Labs  
Motto: *Decode. Build. Evolve.*  
Engineering Lead: Aniket Nandi (Kolkata, IST)  
Milestone: Stage 10.11

---

## 1. Architectural Mission

Disaster recovery in an autonomous security and privacy enforcement layer presents a unique hazard: **recovering infrastructure must never reverse or compromise prior security decisions or privacy erasures.**

Standard enterprise recovery patterns (restoring a database snapshot or replaying transactions) create dangerous vulnerabilities:
- Restoring an earlier database snapshot revives capabilities that were revoked after the snapshot was taken.
- Restoring historical database rows resurrects personal data that was permanently erased under GDPR Article 17 or DPDP Section 12.
- Cold-starting distributed state (Redis) creates an abuse window where rate limits reset to zero and active exfiltration taints vanish.

PRIVGUARD AI resolves this fundamentally by decoupling **state recovery** from **security authority**.

```
+-----------------------------------------------------------------------------------+
|                           PRIVGUARD AI RECOVERY DOMAIN                            |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  +-----------------------------+               +-------------------------------+  |
|  |     POSTGRESQL AUTHORITY    |               |  INDEPENDENT SECURITY LEDGERS |  |
|  |                             |               |                               |  |
|  | - Physical Base Backups     |               | - Security Epoch State        |  |
|  | - Continuous WAL Archiving  |               | - Hash-Chained Revocation Log |  |
|  | - Point-in-Time Recovery    |               | - Erasure Tombstone Ledger    |  |
|  | - Cryptographic Manifests   |               | - Synchronous fsync to disk   |  |
|  +--------------+--------------+               +---------------+---------------+  |
|                 |                                              |                  |
|                 |                                              |                  |
|                 v                                              v                  |
|  +-------------------------------------------------------------+---------------+  |
|  |                      POST-RECOVERY STATE RECONCILIATION                     |  |
|  |                                                                             |  |
|  | 1. Increment Security Recovery Epoch (Invalidates all prior capability keys)|  |
|  | 2. Replay Revocation Journal against restored DB (Re-revokes capabilities)  |  |
|  | 3. Reconcile Erasure Tombstones against restored DB (Scrubs ciphertexts)    |  |
|  | 4. Reconstruct Redis State (Taints, Bundles, Revocations, Outbox Stream)   |  |
|  | 5. Engage Safe Restriction Mode (50% defensive rate limit ceiling for 10m)  |  |
|  +-----------------------------------------------------------------------------+  |
+-----------------------------------------------------------------------------------+
```

---

## 2. The Core Non-Negotiable Invariants

### Invariant 1: Zero-Revocation-Loss
*A capability grant, human approval, or agent execution authorization revoked at timestamp $T_{rev}$ must NEVER become valid again if the database is restored to $T_{restore} \le T_{rev}$.*

**Implementation:**
1. **Security Recovery Epoch**: Every capability token is bound to a monotonic recovery epoch (`pg_cap_e{epoch}_{secret}`). When disaster recovery occurs, `advance_security_epoch()` increments the epoch. Any token minted in epoch $E < E_{current}$ is immediately rejected at the API gateway before database queries.
2. **Independent Revocation Journal**: Revocations are committed and `fsync`ed to an append-only, SHA-256 hash-chained journal outside the database backup domain. On database restore, `replay_revocations_into_db()` re-revokes every item.

### Invariant 2: Anti-Resurrection Privacy
*Personal data intentionally erased under GDPR Article 17 or DPDP Section 12 must NEVER become readable or recoverable if a database backup containing historical ciphertext is restored.*

**Implementation:**
1. **Independent Erasure Tombstone Ledger**: Erasure events generate an immutable tombstone with SHA-256 HMAC and minimal pseudonymous identifiers, fsynced to disk outside PostgreSQL.
2. **Fail-Closed Retrieval Guard**: `memory_vault.get_memory()` evaluates `is_memory_tombstoned(memory_id)`. If tombstoned, it returns `MemoryNotFoundError` immediately, refusing decryption even if ciphertext exists.
3. **Database Scrubbing**: `reconcile_database_erasures()` scans the restored database for tombstoned IDs, wiping `encrypted_content`, destroying wrapped DEKs, and setting status to `DELETED`.

### Invariant 3: Cold-Start Rate Limit Safe Mode
*Following Redis loss or restart, rate limit counters reset to zero, creating an abuse window.*

**Implementation:**
1. During recovery reconciliation, `system:safe_restriction_mode` is set in Redis with a 600-second (10-minute) TTL.
2. Gateway rate limiters enforce a 50% stricter capacity ceiling during this window to absorb traffic while distributed counters normalize.

### Invariant 4: Production Break-Glass Boundary
*Automated scripts MUST NEVER execute recovery against production without interactive human authorization.*

**Implementation:**
1. CLI tools (`restore_postgres.py`, `run_recovery_drill.py`) reject `--env production` with `PermissionError`.
2. Production recovery requires the dual-operator manual runbook in `docs/application_restoration_runbook.md`.

