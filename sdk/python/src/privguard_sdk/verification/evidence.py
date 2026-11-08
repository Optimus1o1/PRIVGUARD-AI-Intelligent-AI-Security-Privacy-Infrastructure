"""Offline verification engine for PRIVGUARD exported audit ZIP packages.

Moon Sanctum Labs - Decode. Build. Evolve.
"""

import copy
import hashlib
import io
import json
import zipfile
from dataclasses import dataclass, field

from privguard_sdk.verification.manifests import (
    canonical_json_bytes,
    load_ed25519_public_key,
    verify_ed25519_signature,
)


@dataclass
class VerificationResult:
    """Detailed cryptographic verification result for an audit package."""

    is_valid: bool
    manifest_valid: bool
    signature_valid: bool
    artifacts_verified: int
    total_artifacts: int
    signing_kid: str | None = None
    public_key_fingerprint: str | None = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        status_str = "VALID" if self.is_valid else "INVALID"
        lines = [
            f"PRIVGUARD Audit Package Verification: {status_str}",
            f"  Artifacts Verified: {self.artifacts_verified}/{self.total_artifacts}",
            f"  Manifest Format: {'VALID' if self.manifest_valid else 'INVALID'}",
            f"  Signature Valid: {'VALID' if self.signature_valid else 'INVALID'}",
        ]
        if self.signing_kid:
            lines.append(f"  Signing Key ID: {self.signing_kid}")
        if self.public_key_fingerprint:
            lines.append(f"  Key Fingerprint: {self.public_key_fingerprint}")
        if self.warnings:
            lines.append("  Warnings:")
            for w in self.warnings:
                lines.append(f"    - {w}")
        if self.errors:
            lines.append("  Errors:")
            for e in self.errors:
                lines.append(f"    - {e}")
        return "\n".join(lines)


def verify_export_package(
    zip_path_or_bytes: str | bytes,
    trusted_public_key: str | bytes | None = None,
    allow_embedded_key: bool = False,
) -> VerificationResult:
    """Independently verifies a PRIVGUARD compliance export ZIP package.

    Verification Steps:
    1. Inspects archive contents and parses manifest.json.
    2. Validates SHA-256 digests of all bundled artifacts against manifest.artifact_hashes.
    3. Canonicalizes manifest.json using RFC 8785 JSON Canonicalization Scheme (JCS).
    4. Resolves the Ed25519 public verification key (trusted key or embedded public_key.pem).
    5. Cryptographically verifies the Ed25519 digital signature over canonical manifest bytes.

    Args:
        zip_path_or_bytes: Path to .zip file or raw bytes of ZIP archive.
        trusted_public_key: PEM string, hex string, or raw bytes of trusted public key.
        allow_embedded_key: If True, uses the embedded public_key.pem if trusted_public_key is not supplied.

    Returns:
        VerificationResult with detailed cryptographic validation breakdown.
    """
    errors: list[str] = []
    warnings: list[str] = []
    artifacts_verified = 0
    total_artifacts = 0
    manifest_valid = False
    signature_valid = False
    signing_kid: str | None = None
    pub_key_fingerprint: str | None = None

    try:
        file_source = io.BytesIO(zip_path_or_bytes) if isinstance(zip_path_or_bytes, bytes) else zip_path_or_bytes
        zf = zipfile.ZipFile(file_source)
    except Exception as exc:
        return VerificationResult(
            is_valid=False,
            manifest_valid=False,
            signature_valid=False,
            artifacts_verified=0,
            total_artifacts=0,
            errors=[f"Failed to open ZIP archive: {exc}"],
        )

    with zf:
        namelist = set(zf.namelist())

        # 1. Locate manifest.json
        manifest_filename = None
        for name in namelist:
            if name.endswith("manifest.json"):
                manifest_filename = name
                break

        if not manifest_filename:
            return VerificationResult(
                is_valid=False,
                manifest_valid=False,
                signature_valid=False,
                artifacts_verified=0,
                total_artifacts=0,
                errors=["Archive missing manifest.json."],
            )

        try:
            manifest_bytes = zf.read(manifest_filename)
            manifest = json.loads(manifest_bytes.decode("utf-8"))
            manifest_valid = True
        except Exception as exc:
            return VerificationResult(
                is_valid=False,
                manifest_valid=False,
                signature_valid=False,
                artifacts_verified=0,
                total_artifacts=0,
                errors=[f"Failed to parse manifest.json: {exc}"],
            )

        signing_kid = manifest.get("signing_kid")
        signature_hex = manifest.get("signature")
        artifact_hashes: dict[str, str] = manifest.get("artifact_hashes", {})
        total_artifacts = len(artifact_hashes)

        # 2. Verify all artifact SHA-256 digests
        base_dir = manifest_filename[:-13]  # prefix if inside a folder
        for relative_path, expected_hash in artifact_hashes.items():
            archive_path = f"{base_dir}{relative_path}" if base_dir else relative_path
            if archive_path not in namelist:
                errors.append(f"Missing artifact referenced in manifest: '{relative_path}'")
                continue

            try:
                artifact_content = zf.read(archive_path)
                actual_hash = hashlib.sha256(artifact_content).hexdigest()
                if actual_hash == expected_hash:
                    artifacts_verified += 1
                else:
                    errors.append(
                        f"Checksum mismatch for '{relative_path}': expected {expected_hash}, got {actual_hash}"
                    )
            except Exception as exc:
                errors.append(f"Failed to read artifact '{relative_path}': {exc}")

        # 3. Resolve Public Key
        resolved_key = trusted_public_key
        if not resolved_key:
            if allow_embedded_key:
                # Find embedded public_key.pem
                pk_filename = None
                for name in namelist:
                    if name.endswith("public_key.pem"):
                        pk_filename = name
                        break
                if pk_filename:
                    resolved_key = zf.read(pk_filename).decode("utf-8")
                    warnings.append(
                        "Public key was loaded from archive (unverified network origin). "
                        "For high assurance, pass an independently trusted public key."
                    )
                else:
                    errors.append("No trusted public key provided, and archive has no embedded public_key.pem.")
            else:
                errors.append(
                    "No trusted_public_key provided. To verify with embedded key, set allow_embedded_key=True."
                )

        # 4. Verify Ed25519 signature
        if resolved_key and signature_hex:
            try:
                pub_obj = load_ed25519_public_key(resolved_key)
                raw_pub_bytes = pub_obj.public_bytes_raw()
                pub_key_fingerprint = hashlib.sha256(raw_pub_bytes).hexdigest()[:16]

                signable_manifest = copy.deepcopy(manifest)
                signable_manifest.pop("signature", None)

                canonical_bytes = canonical_json_bytes(signable_manifest)
                sig_valid = verify_ed25519_signature(canonical_bytes, signature_hex, pub_obj)
                if sig_valid:
                    signature_valid = True
                else:
                    errors.append("Ed25519 signature verification failed over canonical manifest.")
            except Exception as exc:
                errors.append(f"Cryptographic verification error: {exc}")
        elif not signature_hex:
            errors.append("Manifest does not contain a signature field.")

    is_valid = manifest_valid and signature_valid and (artifacts_verified == total_artifacts) and (len(errors) == 0)

    return VerificationResult(
        is_valid=is_valid,
        manifest_valid=manifest_valid,
        signature_valid=signature_valid,
        artifacts_verified=artifacts_verified,
        total_artifacts=total_artifacts,
        signing_kid=signing_kid,
        public_key_fingerprint=pub_key_fingerprint,
        errors=errors,
        warnings=warnings,
    )
