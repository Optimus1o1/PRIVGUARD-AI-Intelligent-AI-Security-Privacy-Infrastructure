"""Unit tests for Cryptographic Evidence Integrity, Canonical JSON, and Ed25519 Signing."""

import pytest

from app.compliance.evidence_integrity import evidence_integrity_service
from app.key_management.signing import signing_key_manager


def test_rfc8785_canonical_json_hashing_determinism():
    """Verifies that dictionaries with different key orders produce identical SHA-256 hashes."""
    dict1 = {"b": 2, "a": 1, "c": {"y": "val", "x": 10}}
    dict2 = {"a": 1, "c": {"x": 10, "y": "val"}, "b": 2}

    hash1 = evidence_integrity_service.hash_structured_payload(dict1)
    hash2 = evidence_integrity_service.hash_structured_payload(dict2)

    assert hash1 == hash2
    assert len(hash1) == 64


def test_dedicated_evidence_signing_key_and_manifest_verification():
    """Verifies manifest signing and independent verification using Ed25519."""
    manifest = {
        "tenant_id": "test_tenant",
        "product_version": "0.1.0",
        "artifact_hashes": {
            "artifacts/test.json": "abc123def456",
        },
    }

    # Sign manifest
    signed_manifest, sig_hex, kid = evidence_integrity_service.sign_manifest(manifest)
    assert signed_manifest["signature"] == sig_hex
    assert signed_manifest["signing_kid"] == kid
    assert len(sig_hex) == 128  # 64-byte Ed25519 signature in hex

    # Export public verification key
    pub_key_meta = evidence_integrity_service.get_public_verification_key(kid)
    assert pub_key_meta["kid"] == kid
    assert pub_key_meta["algorithm"] == "ED25519"
    assert "BEGIN PUBLIC KEY" in pub_key_meta["public_key_pem"]

    # Verify signature
    is_valid = evidence_integrity_service.verify_manifest(
        signed_manifest, pub_key_meta["public_key_hex"]
    )
    assert is_valid is True


def test_tamper_detection_in_manifest_fails_verification():
    """Verifies that altering a single field in the signed manifest invalidates verification."""
    manifest = {
        "tenant_id": "test_tenant",
        "artifact_hashes": {"test.json": "hash_original"},
    }

    signed_manifest, sig_hex, kid = evidence_integrity_service.sign_manifest(manifest)
    pub_key_meta = evidence_integrity_service.get_public_verification_key(kid)

    # Tamper with tenant_id
    tampered_manifest = dict(signed_manifest)
    tampered_manifest["tenant_id"] = "malicious_injected_tenant"

    is_valid = evidence_integrity_service.verify_manifest(
        tampered_manifest, pub_key_meta["public_key_hex"]
    )
    assert is_valid is False

