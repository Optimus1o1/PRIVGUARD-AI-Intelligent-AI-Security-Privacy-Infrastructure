"""SQLite Development & Local Test Backup Automation.

Moon Sanctum Labs - Decode. Build. Evolve.

Provides fast, transaction-consistent SQLite database snapshots for development
and testing environments using sqlite3 online backup API.
This tool is strictly segregated from production PostgreSQL physical base backups.
"""

import argparse
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("privguard.recovery.backup_sqlite_dev")


def backup_sqlite_database(
    source_db_path: Path,
    output_dir: Path,
) -> Path:
    """Takes a transaction-consistent online backup of an SQLite database file.

    Args:
        source_db_path: Path to the active sqlite3 .db file.
        output_dir: Output directory for the backup snapshot.

    Returns:
        Path to the generated backup file.
    """
    if not source_db_path.exists():
        raise FileNotFoundError(f"Source SQLite database not found: {source_db_path}")

    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    dest_path = output_dir / f"{source_db_path.stem}_dev_snapshot_{timestamp}.db"

    logger.info("Starting SQLite online backup from %s to %s", source_db_path, dest_path)

    # Use native SQLite online backup API
    src_conn = sqlite3.connect(str(source_db_path))
    dest_conn = sqlite3.connect(str(dest_path))

    try:
        # Checkpoint WAL if present
        src_conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
        with dest_conn:
            src_conn.backup(dest_conn, pages=100)
        logger.info("SQLite backup completed successfully: %s (size=%d bytes)", dest_path, dest_path.stat().st_size)
    finally:
        dest_conn.close()
        src_conn.close()

    return dest_path


def main():
    parser = argparse.ArgumentParser(description="PRIVGUARD SQLite Dev Backup Tool")
    parser.add_argument("--source", type=Path, default=Path("privguard.db"), help="Source SQLite DB")
    parser.add_argument("--output", type=Path, default=Path("var/backups/sqlite_dev"), help="Output directory")
    args = parser.parse_args()

    backup_sqlite_database(args.source, args.output)


if __name__ == "__main__":
    main()

