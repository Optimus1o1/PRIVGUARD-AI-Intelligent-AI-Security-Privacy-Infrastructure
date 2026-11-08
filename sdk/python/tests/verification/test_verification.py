"""Tests for the offline cryptographic compliance verification engine."""

import hashlib
import io
import json
import zipfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from privguard_sdk.verification.evidence import verify_export_package
from privguard_sdk.verification.manifests import canonical_json_bytes


def create_test_audit_zip() -> tuple[bytes, ed25519.Ed25519PrivateKey, str]:
    """Generates an authentic, signed in-memory ZIP package for testing."""
    # 1. Generate Ed25519 key pair
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    # 2. Artifacts
    artifact_1_bytes = b'{"collector": "canary", "passed": true}'
    artifact_2_bytes = b'{"collector": "kms", "status": "active"}'
    hash_1 = hashlib.sha256(artifact_1_bytes).hexdigest()
    hash_2 = hashlib.sha256(artifact_2_bytes).hexdigest()

    manifest_dict = {
        "export_id": "exp_test_001",
        "created_at": "2026-11-08T00:00:00Z",
        "signing_kid": "kid_ed25519_2026",
        "artifact_hashes": {
            "artifacts/canary.json": hash_1,
            "artifacts/kms.json": hash_2,
        },
    }

    # 3. Sign canonical manifest
    canonical_bytes = canonical_json_bytes(manifest_dict)
    sig_bytes = private_key.sign(canonical_bytes)
    manifest_dict["signature"] = sig_bytes.hex()

    # 4. Pack into ZIP
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zf:
        zf.writestr("manifest.json", json.dumps(manifest_dict, indent=2))
        zf.writestr("public_key.pem", pub_pem)
        zf.writestr("artifacts/canary.json", artifact_1_bytes)
        zf.writestr("artifacts/kms.json", artifact_2_bytes)

    return zip_buffer.getvalue(), private_key, pub_pem


def test_authentic_package_verification():
    zip_bytes, _, pub_pem = create_test_audit_zip()

    # Verify with trusted public key
    result = verify_export_package(zip_bytes, trusted_public_key=pub_pem)
    assert result.is_valid is True
    assert result.manifest_valid is True
    assert result.signature_valid is True
    assert result.artifacts_verified == 2
    assert result.total_artifacts == 2
    assert result.signing_kid == "kid_ed25519_2026"
    assert len(result.errors) == 0


def test_embedded_key_warning():
    zip_bytes, _, _ = create_test_audit_zip()

    # Disallow embedded key by default -> must fail
    res_default = verify_export_package(zip_bytes, allow_embedded_key=False)
    assert res_default.is_valid is False
    assert any("No trusted_public_key provided" in e for e in res_default.errors)

    # Allow embedded key -> succeeds with warning
    res_allow = verify_export_package(zip_bytes, allow_embedded_key=True)
    assert res_allow.is_valid is True
    assert len(res_allow.warnings) > 0
    assert any("loaded from archive" in w for w in res_allow.warnings)


def test_tampered_artifact_fails_verification():
    zip_bytes, _, pub_pem = create_test_audit_zip()

    # Unpack and tamper 1 byte in canary.json
    zf_in = zipfile.ZipFile(io.BytesIO(zip_bytes))
    tampered_buffer = io.BytesIO()
    with zipfile.ZipFile(tampered_buffer, "w") as zf_out:
        for item in zf_in.namelist():
            data = zf_in.read(item)
            if item == "artifacts/canary.json":
                data = b'{"collector": "canary", "passed": false}'  # Tampered!
            zf_out.writestr(item, data)

    tampered_bytes = tampered_buffer.getvalue()
    result = verify_export_package(tampered_bytes, trusted_public_key=pub_pem)
    assert result.is_valid is False
    assert result.artifacts_verified == 1  # only kms.json passed
    assert any("Checksum mismatch" in e for e in result.errors)


def test_tampered_manifest_fails_signature():
    zip_bytes, _, pub_pem = create_test_audit_zip()

    # Tamper manifest metadata without updating signature
    zf_in = zipfile.ZipFile(io.BytesIO(zip_bytes))
    tampered_buffer = io.BytesIO()
    with zipfile.ZipFile(tampered_buffer, "w") as zf_out:
        for item in zf_in.namelist():
            data = zf_in.read(item)
            if item == "manifest.json":
                m = json.loads(data.decode("utf-8"))
                m["export_id"] = "tampered_id"  # Tampered field!
                data = json.dumps(m).encode("utf-8")
            zf_out.writestr(item, data)

    tampered_bytes = tampered_buffer.getvalue()
    result = verify_export_package(tampered_bytes, trusted_public_key=pub_pem)
    assert result.is_valid is False
    assert result.signature_valid is False
    assert any("signature verification failed" in e for e in result.errors)


def test_untrusted_public_key_fails_signature():
    zip_bytes, _, _ = create_test_audit_zip()

    # Generate a different key
    other_key = ed25519.Ed25519PrivateKey.generate().public_key()
    other_pem = other_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    result = verify_export_package(zip_bytes, trusted_public_key=other_pem)
    assert result.is_valid is False
    assert result.signature_valid is False
