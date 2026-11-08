# PRIVGUARD AI — PostgreSQL Backup & PITR Operational Guide

Organization: Moon Sanctum Labs  
Motto: *Decode. Build. Evolve.*  
Date: November 2026

---

## 1. Backup Topology & Architecture

PRIVGUARD AI utilizes PostgreSQL physical streaming base backups combined with continuous Write-Ahead Log (WAL) archiving.

- **Physical Base Backup (`pg_basebackup`)**:
  - Full binary copy of PostgreSQL database cluster (`data/base.tar.gz`).
  - Frequency: Daily at 02:00 UTC.
  - Retention: 30 days on secondary object storage (S3 / GCS / local cold storage).
  - Checksum: SHA-256 computed on completed archive.
  - Manifest: Cryptographically signed with Ed25519 `KeyPurpose.BACKUP_SIGNING` key.

- **Continuous WAL Archiving (`archive_command`)**:
  - 16MB WAL segment files shipped to archive storage upon completion or timeout (`archive_timeout = 300s`).
  - Target RPO: < 5 minutes (enforced by 300s archive timeout and Prometheus alert `PrivguardWalArchiveLagHigh`).
  - WAL segments sorted and validated for gapless sequence continuity.

---

## 2. Backup Execution Procedures

### Automated Base Backup Generation (`scripts/recovery/backup_postgres.py`)

```bash
# Execute physical base backup and generate signed manifest
python scripts/recovery/backup_postgres.py \
    --backup-id "pg_backup_$(date +%Y%m%d_%H%M%S)" \
    --output-dir "/var/backups/privguard/postgres" \
    --signing-key "/etc/privguard/keys/backup_signing_private.pem" \
    --signing-kid "key-dr-2026-01" \
    --wal-archive-dir "/var/backups/privguard/wal"
```

The script outputs:
1. `data/base.tar.gz`: Compressed database cluster.
2. `manifest.json`: Canonical RFC 8785 JSON manifest with SHA-256 hashes, security epoch, migration revision, and Ed25519 signature.

---

## 3. Point-in-Time Recovery (PITR) Workflow

To restore PostgreSQL to a specific recovery point:

1. **Verify Backup Manifest Signature**:
   Confirm that the backup archive has not been modified or corrupted:
   ```bash
   python scripts/recovery/restore_postgres.py \
       --backup-dir "/var/backups/privguard/postgres/pg_backup_20261108" \
       --trusted-key "/etc/privguard/keys/backup_signing_public.pem" \
       --env staging \
       --target-dir "/var/lib/postgresql/data"
   ```

2. **Replay Continuous WAL Segments**:
   ```bash
   python scripts/recovery/pitr_replay.py \
       --wal-dir "/var/backups/privguard/wal" \
       --target-time "2026-11-08T14:30:00Z"
   ```

3. **Execute Post-Recovery Reconciliation**:
   Immediately run state reconciliation to enforce zero revocation loss and anti-resurrection:
   ```bash
   python scripts/recovery/reconcile_recovery.py --env staging
   ```

