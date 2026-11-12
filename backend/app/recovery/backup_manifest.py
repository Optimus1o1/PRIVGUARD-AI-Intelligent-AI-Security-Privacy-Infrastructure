"""Cryptographic Backup Manifest Generation, Signing, and Verification.

Moon Sanctum Labs - Decode. Build. Evolve.

Provides tamper-evident metadata manifests for physical PostgreSQL base backups,
continuous WAL segments, and development snapshots. Manifests are signed using
dedicated KeyPurpose.BACKUP_SIGNING Ed25519 keys, ensuring that corrupted,
tampered, or untrusted backup archives are rejected before restoration.
"""

import copy
import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from app.recovery.security_epoch import get_current_security_epoch

logger = logging.getLogger("privguard.recovery.backup_manifest")


def canonical_json_bytes(obj: Any) -> bytes:
    """Serializes a Python object to canonical JSON bytes according to RFC 8785."""
    serialized = json.dumps(
        obj,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return serialized.encode("utf-8")


def create_backup_manifest(
    backup_id: str,
    database_engine: str,
    backup_type: str,
    artifact_hashes: dict[str, str],
    migration_revision: str,
    git_commit_sha: str,
    encryption_algorithm: str = "AES_256_GCM",
    wal_start_lsn: Optional[str] = None,
    wal_end_lsn: Optional[str] = None,
    metadata: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Creates an unsigned backup manifest dictionary."""
    manifest = {
        "manifest_version": "1.0",
        "backup_id": backup_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "database_engine": database_engine.lower(),
        "backup_type": backup_type,
        "security_epoch": get_current_security_epoch(),
        "migration_revision": migration_revision,
        "git_commit_sha": git_commit_sha,
        "encryption_algorithm": encryption_algorithm,
        "wal_start_lsn": wal_start_lsn,
        "wal_end_lsn": wal_end_lsn,
        "artifact_hashes": artifact_hashes,
        "metadata": metadata or {},
    }
    return manifest


def sign_backup_manifest(
    manifest: dict[str, Any],
    signing_key_pem_or_bytes: str | bytes,
    signing_kid: str,
) -> dict[str, Any]:
    """Signs a backup manifest using a dedicated BACKUP_SIGNING Ed25519 private key.

    Args:
        manifest: Unsigned manifest dictionary.
        signing_key_pem_or_bytes: Private key in PEM, raw, or hex format.
        signing_kid: Key identifier for the backup signing key.

    Returns:
        New manifest dictionary with 'signing_kid' and 'signature' fields.
    """
    signed_manifest = copy.deepcopy(manifest)
    signed_manifest["signing_kid"] = signing_kid
    signed_manifest.pop("signature", None)

    # Load private key
    if isinstance(signing_key_pem_or_bytes, str):
        key_bytes = signing_key_pem_or_bytes.encode("utf-8")
    else:
        key_bytes = signing_key_pem_or_bytes

    try:
        priv_obj = serialization.load_pem_private_key(key_bytes, password=None)
    except Exception:
        priv_obj = ed25519.Ed25519PrivateKey.from_private_bytes(key_bytes)

    if not isinstance(priv_obj, ed25519.Ed25519PrivateKey):
        raise ValueError("Backup signing key must be an Ed25519 private key.")

    canonical_bytes = canonical_json_bytes(signed_manifest)
    sig_bytes = priv_obj.sign(canonical_bytes)
    signed_manifest["signature"] = sig_bytes.hex()

    return signed_manifest


def verify_backup_manifest(
    manifest: dict[str, Any],
    trusted_public_key_pem_or_bytes: str | bytes,
) -> tuple[bool, list[str]]:
    """Cryptographically verifies a backup manifest against a trusted public key.

    Args:
        manifest: Manifest dictionary with 'signature' and 'signing_kid'.
        trusted_public_key_pem_or_bytes: Trusted Ed25519 public key.

    Returns:
        (is_valid, errors_list)
    """
    errors: list[str] = []
    signature_hex = manifest.get("signature")
    if not signature_hex:
        return False, ["Manifest is missing required 'signature' field."]

    # Load public key
    if isinstance(trusted_public_key_pem_or_bytes, str):
        key_bytes = trusted_public_key_pem_or_bytes.encode("utf-8")
    else:
        key_bytes = trusted_public_key_pem_or_bytes

    try:
        pub_obj = serialization.load_pem_public_key(key_bytes)
    except Exception:
        pub_obj = ed25519.Ed25519PublicKey.from_public_bytes(key_bytes)

    if not isinstance(pub_obj, ed25519.Ed25519PublicKey):
        return False, ["Trusted key is not an Ed25519 public key."]

    # Reconstruct signable manifest without signature
    signable = copy.deepcopy(manifest)
    signable.pop("signature", None)
    canonical_bytes = canonical_json_bytes(signable)

    try:
        sig_bytes = bytes.fromhex(signature_hex)
        pub_obj.verify(sig_bytes, canonical_bytes)
    except Exception as exc:
        errors.append(f"Ed25519 signature verification failed: {exc}")
        return False, errors

    return True, []
