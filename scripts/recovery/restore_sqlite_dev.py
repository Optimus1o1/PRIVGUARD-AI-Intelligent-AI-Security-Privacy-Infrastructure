"""SQLite Development & Local Test Restore Tool.

Moon Sanctum Labs - Decode. Build. Evolve.

Restores SQLite database snapshots for local development, unit tests, and debugging.
Operates exclusively on SQLite files and never targets production environments.
"""

import argparse
import logging
import shutil
import sqlite3
import sys
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("privguard.recovery.restore_sqlite_dev")


def restore_sqlite_database(
    backup_file: Path,
    target_db_path: Path,
) -> bool:
    """Restores an SQLite backup snapshot to a target database file."""
    if not backup_file.exists():
        logger.error("Backup file does not exist: %s", backup_file)
        return False

    # Quick integrity check on backup SQLite file
    try:
        conn = sqlite3.connect(str(backup_file))
        cursor = conn.cursor()
        cursor.execute("PRAGMA integrity_check;")
        result = cursor.fetchone()
        conn.close()
        if not result or result[0] != "ok":
            logger.error("SQLite backup file failed integrity check: %s", result)
            return False
    except Exception as exc:
        logger.error("Failed to inspect SQLite backup file: %s", exc)
        return False

    target_db_path.parent.mkdir(parents=True, exist_ok=True)

    # If target exists, create a safety copy before overwriting
    if target_db_path.exists():
        safety_copy = target_db_path.with_suffix(".pre_restore.bak")
        shutil.copy2(target_db_path, safety_copy)
        logger.info("Saved pre-restore safety copy to: %s", safety_copy)

    shutil.copy2(backup_file, target_db_path)
    logger.info("SQLite database restored successfully to: %s", target_db_path)
    return True


def main():
    parser = argparse.ArgumentParser(description="PRIVGUARD SQLite Dev Restore Tool")
    parser.add_argument("--backup", type=Path, required=True, help="Backup file (.db) to restore")
    parser.add_argument("--target", type=Path, default=Path("privguard.db"), help="Target DB path to overwrite")
    args = parser.parse_args()

    success = restore_sqlite_database(args.backup, args.target)
    if not success:
        sys.exit(1)


if __name__ == "__main__":
    main()
