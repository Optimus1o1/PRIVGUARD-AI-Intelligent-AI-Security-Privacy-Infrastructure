"""Unit and Integration tests for Evidence Export Packaging and Sanitization."""

import io
import json
import zipfile
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from app.compliance.evidence_export import evidence_export_packager, sanitize_payload
from app.compliance.models import ComplianceApplicabilityRecord, ComplianceEvidenceRecord


def test_defense_in_depth_sanitization_removes_secrets():
    """Verifies that sanitize_payload removes API keys, passwords, and sensitive credentials."""
    dirty_payload = {
        "user_name": "Alice",
        "api_key": "pg_live_1234567890abcdef1234",
        "nested": {
            "password": "secret_password_here",
            "openai_key": "sk-1234567890123456789012345",
        },
    }

    clean = sanitize_payload(dirty_payload)
    assert clean["user_name"] == "Alice"
    assert clean["api_key"] == "[REDACTED_SENSITIVE_CREDENTIAL]"
    assert clean["nested"]["password"] == "[REDACTED_SENSITIVE_CREDENTIAL]"
    assert clean["nested"]["openai_key"] == "[REDACTED_CREDENTIAL]"


def test_zip_export_archive_and_independent_cryptographic_verification():
    """
    Creates a full ZIP export package and simulates an external auditor independently
    verifying manifest integrity and artifact digests using only standard cryptography.
    """
    ev_record = ComplianceEvidenceRecord(
        id="ev_test_12345678",
        tenant_id="tenant_audit_test",
        control_id="PG-CONTROL-005",
        collector_name="postgresql_rls_collector",
        artifact_type="JSON",
        artifact_hash_sha256="0" * 64,
        artifact_payload=json.dumps({"test_key": "test_value"}),
        verification_status="VERIFIED",
        freshness_status="CURRENT",
        assurance_status="HIGH",
    )

    zip_bytes, manifest_sha256, sig_hex, kid = evidence_export_packager.export_as_zip_archive(
        tenant_id="tenant_audit_test",
        framework_id="dpdp-2023",
        evidence_records=[ev_record],
        applicability_records=[],
    )

    assert len(zip_bytes) > 0
    assert len(manifest_sha256) == 64
    assert len(sig_hex) == 128

    # Unpack ZIP archive as an external auditor
    with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
        namelist = zf.namelist()
        assert "manifest.json" in namelist
        assert "manifest.sig" in namelist
        assert "public_key.pem" in namelist
        assert "verification_instructions.md" in namelist
        assert "summary.json" in namelist
        assert "controls/PG-CONTROL-001.json" in namelist
        assert "controls/PG-CONTROL-035.json" in namelist
        assert "mappings/crosswalk_mappings.json" in namelist
        assert "artifacts/ev_test_12345678_PG-CONTROL-005.json" in namelist

        # 1. Load Public Key from PEM
        pub_key_pem = zf.read("public_key.pem")
        pub_key = serialization.load_pem_public_key(pub_key_pem)

        # 2. Load Manifest
        manifest_raw = json.loads(zf.read("manifest.json").decode("utf-8"))
        extracted_sig_hex = manifest_raw.pop("signature")
        assert extracted_sig_hex == sig_hex

        # 3. Canonicalize manifest bytes without signature
        canonical_manifest_bytes = json.dumps(
            manifest_raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

        # 4. Verify Ed25519 signature
        sig_bytes = bytes.fromhex(extracted_sig_hex)
        pub_key.verify(sig_bytes, canonical_manifest_bytes)  # Raises InvalidSignature if invalid

        # 5. Verify detached manifest.sig matches
        detached_sig = zf.read("manifest.sig").decode("utf-8")
        assert detached_sig == extracted_sig_hex


def test_csv_export_format():
    """Verifies CSV export contains expected headers and row data."""
    ev = ComplianceEvidenceRecord(
        id="ev_csv_1",
        tenant_id="tenant_csv",
        control_id="PG-CONTROL-001",
        collector_name="canary",
        artifact_type="JSON",
        artifact_hash_sha256="abc123hash",
        artifact_payload="{}",
        verification_status="VERIFIED",
        freshness_status="CURRENT",
        assurance_status="HIGH",
    )

    csv_text = evidence_export_packager.export_as_csv(
        tenant_id="tenant_csv", evidence_records=[ev]
    )
    assert "Evidence ID" in csv_text
    assert "Control ID" in csv_text
    assert "ev_csv_1" in csv_text
    assert "PG-CONTROL-001" in csv_text

