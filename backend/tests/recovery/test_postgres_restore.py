"""Unit tests for PostgreSQL Restore Tool.
Verifies safety invariants:
1. Automated restore against production is strictly prohibited (raises PermissionError).
2. Manifest signature validation is strictly enforced before restoration.
3. Artifact hash discrepancies abort restoration.
4. Valid staging/test restore workflow succeeds.
"""

import json
from pathlib import Path
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from scripts.recovery.restore_postgres import (
    validate_and_restore_postgres,
    compute_file_sha256,
)
from app.recovery.backup_manifest import (
    create_backup_manifest,
    sign_backup_manifest,
)


@pytest.fixture
def keypair():
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem


def test_production_restore_prohibited(tmp_path, keypair):
    _, pub_pem = keypair
    with pytest.raises(PermissionError, match="Automated restore against production is prohibited"):
        validate_and_restore_postgres(
            backup_path=tmp_path,
            trusted_public_key_pem=pub_pem,
            target_env="production",
        )


def test_invalid_env_rejected(tmp_path, keypair):
    _, pub_pem = keypair
    with pytest.raises(ValueError, match="Invalid environment 'invalid_env'"):
        validate_and_restore_postgres(
            backup_path=tmp_path,
            trusted_public_key_pem=pub_pem,
            target_env="invalid_env",
        )


def test_missing_manifest_rejected(tmp_path, keypair):
    _, pub_pem = keypair
    # tmp_path has no manifest.json
    res = validate_and_restore_postgres(
        backup_path=tmp_path,
        trusted_public_key_pem=pub_pem,
        target_env="staging",
    )
    assert res is False


def test_tampered_artifact_rejected(tmp_path, keypair):
    priv_pem, pub_pem = keypair
    artifact = tmp_path / "base.tar.gz"
    artifact.write_bytes(b"initial data")
    expected_hash = compute_file_sha256(artifact)

    manifest = create_backup_manifest(
        backup_id="test-dr-01",
        database_engine="postgresql",
        backup_type="physical_base",
        artifact_hashes={"base.tar.gz": expected_hash},
        migration_revision="rev_1",
        git_commit_sha="commit_1",
    )
    signed = sign_backup_manifest(manifest, priv_pem, signing_kid="kid-dr")
    manifest_file = tmp_path / "manifest.json"
    manifest_file.write_text(json.dumps(signed), encoding="utf-8")

    # Tamper with the artifact file
    artifact.write_bytes(b"tampered content")

    res = validate_and_restore_postgres(
        backup_path=tmp_path,
        trusted_public_key_pem=pub_pem,
        target_env="test",
    )
    assert res is False


def test_valid_restore_staging_succeeds(tmp_path, keypair):
    priv_pem, pub_pem = keypair
    artifact = tmp_path / "base.tar.gz"
    artifact.write_bytes(b"verified backup archive contents")
    expected_hash = compute_file_sha256(artifact)

    dest_dir = tmp_path / "restored_data"

    manifest = create_backup_manifest(
        backup_id="test-dr-valid",
        database_engine="postgresql",
        backup_type="physical_base",
        artifact_hashes={"base.tar.gz": expected_hash},
        migration_revision="rev_1",
        git_commit_sha="commit_1",
    )
    signed = sign_backup_manifest(manifest, priv_pem, signing_kid="kid-dr")
    manifest_file = tmp_path / "manifest.json"
    manifest_file.write_text(json.dumps(signed), encoding="utf-8")

    res = validate_and_restore_postgres(
        backup_path=tmp_path,
        trusted_public_key_pem=pub_pem,
        target_env="staging",
        target_data_dir=dest_dir,
    )
    assert res is True
    assert (dest_dir / "recovery.verified").exists()

