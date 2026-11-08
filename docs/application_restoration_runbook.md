# PRIVGUARD AI — Production Application Restoration Runbook

Organization: Moon Sanctum Labs  
Motto: *Decode. Build. Evolve.*  
Date: November 2026  
Classification: **OPERATIONAL BREAK-GLASS PROCEDURE**

---

## 1. Safety Notice & Dual Authorization

> [!CAUTION]
> Automated CLI execution against `--env production` is strictly prohibited by code.
> Production restoration is a high-impact, manual operator-driven break-glass procedure requiring dual authorization from:
> 1. Lead Systems Engineer (SRE)
> 2. Security / Privacy Officer

---

## 2. Step-by-Step Restoration Protocol

### Phase 1: Incident Containment & Traffic Divert
1. Divert incoming API traffic away from the affected region/cluster to the maintenance page or warm DR stand-by.
2. Confirm that the primary PostgreSQL and Redis instances are halted to prevent split-brain writes:
   ```bash
   systemctl stop privguard-backend
   systemctl stop postgresql
   ```

### Phase 2: Backup Manifest Cryptographic Verification
3. Download the target physical base backup and its `manifest.json`.
4. Run manifest verification against the trusted public key:
   ```bash
   python scripts/recovery/restore_postgres.py \
       --backup-dir "/mnt/cold_storage/backups/pg_backup_20261108_0200" \
       --trusted-key "/etc/privguard/keys/backup_signing_public.pem" \
       --env staging \
       --target-dir "/var/lib/postgresql/restored_data"
   ```
5. Confirm output indicates: `Backup manifest signature VERIFIED` and `All backup artifacts verified with authentic SHA-256 digests`.

### Phase 3: Point-in-Time WAL Replay
6. Replay continuous WAL segments up to the declared recovery target:
   ```bash
   python scripts/recovery/pitr_replay.py \
       --wal-dir "/mnt/wal_archive" \
       --target-time "2026-11-08T12:00:00Z"
   ```

### Phase 4: State Reconciliation (Invariants Enforcement)
7. Advance the Security Recovery Epoch to immediately invalidate pre-disaster capability tokens:
   ```bash
   python -c "from app.recovery.security_epoch import advance_security_epoch; print('New Epoch:', advance_security_epoch('PROD_DISASTER_RESTORE', 'sre_alice'))"
   ```
8. Run the recovery reconciliation tool:
   ```bash
   python scripts/recovery/reconcile_recovery.py --env staging
   ```
   This performs:
   - Scrubbing of resurrected memories matching the Erasure Tombstone Ledger.
   - Replay of independent Revocation Journal against restored tables.
   - Reconstruction of active taints and active signed policy bundles in Redis.
   - Activation of 10-minute Safe Restriction Mode.

### Phase 5: Production Swap & Validation
9. Promote restored staging data directory to production:
   ```bash
   mv /var/lib/postgresql/restored_data /var/lib/postgresql/data
   systemctl start postgresql
   systemctl start privguard-backend
   ```
10. Run non-destructive synthetic health canary:
    ```bash
    curl -f http://localhost:8000/v1/health/canary
    ```
11. Re-open API traffic and monitor Prometheus metrics:
    - `privguard_dr_security_epoch`
    - `privguard_dr_safe_restriction_mode_active`
    - `privguard_dr_wal_archive_lag_seconds`

