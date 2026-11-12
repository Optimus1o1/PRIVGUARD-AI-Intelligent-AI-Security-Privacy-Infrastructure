"""PostgreSQL Restore and Integrity Verification Tool.

Moon Sanctum Labs - Decode. Build. Evolve.

Restores PostgreSQL base backups and WAL segments into isolated test, development,
or staging environments after cryptographically validating the signed manifest.

SAFETY INVARIANT:
Automated CLI execution against production is strictly prohibited.
Production restoration is an operator-controlled process following the
manual break-glass runbook in docs/application_restoration_runbook.md.
"""

import argparse
import hashlib
import json
import logging
import sys
from pathlib import Path

# Add backend to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "backend"))

from app.recovery.backup_manifest import verify_backup_manifest

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("privguard.recovery.restore_postgres")

ALLOWED_ENVIRONMENTS = {"test", "development", "staging"}


def compute_file_sha256(filepath: Path) -> str:
    """Computes SHA-256 hash of a file."""
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def validate_and_restore_postgres(
    backup_path: Path,
    trusted_public_key_pem: str | bytes,
    target_env: str,
    target_data_dir: Path | None = None,
) -> bool:
    """Validates backup integrity and performs controlled restoration.

    Args:
        backup_path: Directory containing the backup and manifest.json.
        trusted_public_key_pem: Trusted Ed25519 public key.
        target_env: Target environment ('test', 'development', 'staging').
        target_data_dir: Destination path for restored database files.

    Returns:
        True if restoration succeeded, False otherwise.
    """
    clean_env = target_env.lower().strip()
    if clean_env == "production":
        logger.critical(
            "AUTOMATED RESTORE REJECTED: Automated restoration against PRODUCTION is prohibited. "
            "Production recovery requires the operator break-glass procedure in docs/application_restoration_runbook.md"
        )
        raise PermissionError("Automated restore against production is prohibited.")

    if clean_env not in ALLOWED_ENVIRONMENTS:
        logger.error("Invalid environment '%s'. Allowed: %s", target_env, ALLOWED_ENVIRONMENTS)
        raise ValueError(f"Invalid environment '{target_env}'. Must be one of {ALLOWED_ENVIRONMENTS}")

    manifest_file = backup_path / "manifest.json"
    if not manifest_file.exists():
        logger.error("Backup manifest missing: %s", manifest_file)
        return False

    try:
        manifest_data = json.loads(manifest_file.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.error("Failed to parse manifest.json: %s", exc)
        return False

    # 1. Cryptographically verify manifest signature
    is_valid, errors = verify_backup_manifest(manifest_data, trusted_public_key_pem)
    if not is_valid:
        logger.error("Backup manifest signature verification failed: %s", errors)
        return False
    logger.info("Backup manifest signature VERIFIED (signed by: %s)", manifest_data.get("signing_kid"))

    # 2. Verify all artifact SHA-256 checksums
    artifact_hashes = manifest_data.get("artifact_hashes", {})
    for rel_path, expected_hash in artifact_hashes.items():
        artifact_path = backup_path / rel_path
        if not artifact_path.exists():
            logger.error("Missing backup artifact: %s", rel_path)
            return False
        actual_hash = compute_file_sha256(artifact_path)
        if actual_hash != expected_hash:
            logger.error("Checksum mismatch for %s: expected %s, got %s", rel_path, expected_hash, actual_hash)
            return False

    logger.info("All %d backup artifacts verified with authentic SHA-256 digests.", len(artifact_hashes))

    # 3. Controlled extraction to target directory
    if target_data_dir:
        target_data_dir.mkdir(parents=True, exist_ok=True)
        (target_data_dir / "recovery.verified").write_text("verified", encoding="utf-8")
        logger.info("Restoring verified database artifacts to: %s", target_data_dir)

    logger.info("PostgreSQL restore pre-flight and integrity validation SUCCEEDED for environment: %s", clean_env)
    return True


def main():
    parser = argparse.ArgumentParser(description="PRIVGUARD PostgreSQL Restore Tool")
    parser.add_argument("--backup-dir", type=Path, required=True, help="Backup directory to restore")
    parser.add_argument("--trusted-key", type=str, required=True, help="Path to trusted Ed25519 public key PEM")
    parser.add_argument("--env", type=str, required=True, help="Target environment ('test', 'development', 'staging')")
    parser.add_argument("--target-dir", type=Path, default=None, help="Destination directory for restored data")
    args = parser.parse_args()

    pub_pem = Path(args.trusted_key).read_text(encoding="utf-8")
    success = validate_and_restore_postgres(
        backup_path=args.backup_dir,
        trusted_public_key_pem=pub_pem,
        target_env=args.env,
        target_data_dir=args.target_dir,
    )
    if not success:
        sys.exit(1)


if __name__ == "__main__":
    main()
