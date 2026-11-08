# PRIVGUARD AI — Development SQLite Backup & Recovery Guide

Organization: Moon Sanctum Labs  
Motto: *Decode. Build. Evolve.*  
Date: November 2026

---

## 1. Segregation & Safety Scope

> [!WARNING]
> SQLite is strictly restricted to local development and ephemeral unit testing environments.
> Production PRIVGUARD deployments use PostgreSQL 16+.

The SQLite backup and restore tooling (`scripts/recovery/backup_sqlite_dev.py` and `scripts/recovery/restore_sqlite_dev.py`) provides local developer parity without compromising production controls.

---

## 2. Developer Backup Workflow

To capture a consistent snapshot of a local development database:

```bash
# Backup local sqlite database with atomic copy and manifest
python scripts/recovery/backup_sqlite_dev.py \
    --db-path "data/privguard.db" \
    --output-dir "data/backups/sqlite"
```

The script:
1. Opens an atomic SQLite backup connection (`sqlite3.backup`).
2. Computes the SHA-256 hash of the created snapshot.
3. Generates a signed development manifest.

---

## 3. Developer Restore Workflow

To restore a local development database snapshot:

```bash
# Restore local sqlite database
python scripts/recovery/restore_sqlite_dev.py \
    --backup-file "data/backups/sqlite/privguard_snapshot_20261108.db" \
    --target-db "data/privguard.db"
```

