"""Unit tests for Cryptographic Backup Manifest Signing and Verification.
Verifies RFC 8785 canonical serialization, Ed25519 signing, tampering rejection,
and public key mismatch detection.
"""

import copy
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from app.recovery.backup_manifest import (
    canonical_json_bytes,
    create_backup_manifest,
    sign_backup_manifest,
    verify_backup_manifest,
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


def test_manifest_creation_and_canonical_bytes():
    manifest = create_backup_manifest(
        backup_id="test-backup-001",
        database_engine="postgresql",
        backup_type="physical_base",
        artifact_hashes={"base.tar.gz": "abc123def456"},
        migration_revision="head_rev_10",
        git_commit_sha="16c0ed5",
        wal_start_lsn="0/16000028",
        wal_end_lsn="0/16000100",
    )
    assert manifest["backup_id"] == "test-backup-001"
    assert manifest["database_engine"] == "postgresql"
    assert manifest["migration_revision"] == "head_rev_10"
    assert "created_at" in manifest

    # Deterministic JSON canonicalization test
    c1 = canonical_json_bytes({"b": 2, "a": 1})
    c2 = canonical_json_bytes({"a": 1, "b": 2})
    assert c1 == c2 == b'{"a":1,"b":2}'


def test_manifest_signing_and_verification(keypair):
    priv_pem, pub_pem = keypair
    unsigned = create_backup_manifest(
        backup_id="test-backup-002",
        database_engine="postgresql",
        backup_type="physical_base",
        artifact_hashes={"base.tar.gz": "sha256_mock_hash"},
        migration_revision="rev_1",
        git_commit_sha="git_sha_1",
    )
    signed = sign_backup_manifest(unsigned, priv_pem, signing_kid="key-dr-01")

    assert signed["signing_kid"] == "key-dr-01"
    assert "signature" in signed

    is_valid, errors = verify_backup_manifest(signed, pub_pem)
    assert is_valid is True
    assert len(errors) == 0


def test_tampered_manifest_rejected(keypair):
    priv_pem, pub_pem = keypair
    unsigned = create_backup_manifest(
        backup_id="test-backup-003",
        database_engine="postgresql",
        backup_type="physical_base",
        artifact_hashes={"base.tar.gz": "original_hash"},
        migration_revision="rev_1",
        git_commit_sha="git_sha_1",
    )
    signed = sign_backup_manifest(unsigned, priv_pem, signing_kid="key-dr-01")

    # Tamper with an artifact hash
    tampered = copy.deepcopy(signed)
    tampered["artifact_hashes"]["base.tar.gz"] = "corrupted_hash"
    is_valid, errors = verify_backup_manifest(tampered, pub_pem)
    assert is_valid is False
    assert any("signature verification failed" in err.lower() for err in errors)

    # Tamper with security epoch
    tampered_epoch = copy.deepcopy(signed)
    tampered_epoch["security_epoch"] = tampered_epoch["security_epoch"] + 999
    is_valid, errors = verify_backup_manifest(tampered_epoch, pub_pem)
    assert is_valid is False

    # Tamper with signature directly
    tampered_sig = copy.deepcopy(signed)
    sig_bytes = bytearray(bytes.fromhex(tampered_sig["signature"]))
    sig_bytes[0] ^= 0xFF
    tampered_sig["signature"] = sig_bytes.hex()
    is_valid, errors = verify_backup_manifest(tampered_sig, pub_pem)
    assert is_valid is False


def test_wrong_key_verification_fails(keypair):
    priv_pem, _ = keypair
    # Generate another distinct keypair
    other_priv = ed25519.Ed25519PrivateKey.generate()
    other_pub_pem = other_priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    unsigned = create_backup_manifest(
        backup_id="test-backup-004",
        database_engine="postgresql",
        backup_type="physical_base",
        artifact_hashes={"base.tar.gz": "sha256_mock_hash"},
        migration_revision="rev_1",
        git_commit_sha="git_sha_1",
    )
    signed = sign_backup_manifest(unsigned, priv_pem, signing_kid="key-dr-01")

    is_valid, errors = verify_backup_manifest(signed, other_pub_pem)
    assert is_valid is False
    assert len(errors) > 0


def test_missing_signature_fails(keypair):
    _, pub_pem = keypair
    manifest = {
        "manifest_version": "1.0",
        "backup_id": "unsigned-backup",
    }
    is_valid, errors = verify_backup_manifest(manifest, pub_pem)
    assert is_valid is False
    assert any("missing required 'signature'" in err for err in errors)

