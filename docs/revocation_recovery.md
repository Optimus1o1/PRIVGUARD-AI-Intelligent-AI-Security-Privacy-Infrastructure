# PRIVGUARD AI — Security Recovery Epoch & Revocation Preservation

Organization: Moon Sanctum Labs  
Motto: *Decode. Build. Evolve.*  
Date: November 2026

---

## 1. The Zero-Revocation-Loss Guarantee

In multi-agent systems, agents hold temporary cryptographic capability tokens allowing them to perform actions (e.g. read files, execute SQL, call APIs). If an agent is detected behaving maliciously, an operator revokes the capability immediately.

If the PostgreSQL database later crashes and is restored from a backup taken before that revocation, the restored database will show the capability as active.

PRIVGUARD AI solves this with two complementary mechanisms:
1. **Security Recovery Epochs**
2. **Independent Revocation Journals**

---

## 2. Monotonic Security Recovery Epoch

Every issued capability token encodes the active security epoch in its secret token:
```
pg_cap_e{epoch}_{random_secret}
Example: pg_cap_e1_9KzM31qX...
```

- When PostgreSQL is restored from any historical backup, the operator or automated recovery script calls `advance_security_epoch()`.
- The epoch increments from `1 -> 2`.
- When an agent presents `pg_cap_e1_9KzM31qX...` to `validate_and_consume()`, PRIVGUARD extracts the epoch:
  ```python
  if token_epoch < current_epoch:
      raise PrivGuardException("CAPABILITY_EPOCH_INVALIDATED")
  ```
- **Result:** Every capability token issued prior to the disaster is invalidated instantly at the epoch boundary, without needing to inspect database rows!

---

## 3. Independent Revocation Journal

For entity-level revocations (agent suspension, user permissions, approval requests), PRIVGUARD writes each revocation to an append-only, SHA-256 hash-chained log (`var/recovery/revocation_journal.log`):
1. **Synchronous fsync**: The API call does not return success to the operator until the journal line is physically committed to disk.
2. **Post-Restore Replay**: Following database restoration, `replay_revocations_into_db(db)` re-applies every recorded revocation to the restored database tables.

