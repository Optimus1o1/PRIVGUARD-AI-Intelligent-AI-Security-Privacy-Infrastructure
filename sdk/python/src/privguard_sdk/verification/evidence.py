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

# Safety thresholds for archive inspection (decompression bomb protection)
MAX_TOTAL_UNCOMPRESSED_BYTES = 100 * 1024 * 1024  # 100 MB
MAX_SINGLE_FILE_UNCOMPRESSED_BYTES = 50 * 1024 * 1024  # 50 MB
MAX_COMPRESSION_RATIO = 100.0


@dataclass
class VerificationResult:
    """Detailed cryptographic verification result for an audit package."""

    is_valid: bool
    manifest_valid: bool
    signature_valid: bool
    trust_verified: bool
    artifacts_verified: int
    total_artifacts: int
    signing_kid: str | None = None
    public_key_fingerprint: str | None = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        if self.is_valid:
            status_str = "VALID (TRUSTED & VERIFIED)"
        elif self.signature_valid and not self.trust_verified:
            status_str = "INVALID (SELF-CONSISTENT BUT UNTRUSTED IDENTITY)"
        else:
            status_str = "INVALID"

        lines = [
            f"PRIVGUARD Audit Package Verification: {status_str}",
            f"  Trust Verified: {'YES (Explicit Trusted Key)' if self.trust_verified else 'NO (Untrusted Identity)'}",
            f"  Signature Valid: {'VALID' if self.signature_valid else 'INVALID'}",
            f"  Manifest Format: {'VALID' if self.manifest_valid else 'INVALID'}",
            f"  Artifacts Verified: {self.artifacts_verified}/{self.total_artifacts}",
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

    Security & Trust Invariant:
    - An embedded public key inside an untrusted ZIP archive proves only self-consistency;
      it CANNOT prove authenticity or identity trust.
    - An archive is considered `is_valid=True` ONLY when verified against an explicit
      `trusted_public_key`. Using an embedded key sets `trust_verified=False` and `is_valid=False`.

    Verification Steps:
    1. Pre-flight archive security audit: checks duplicate names, path traversal,
       decompression bomb ratios, and size quotas.
    2. Locates and parses manifest.json.
    3. Closed-world check: verifies that no unmanifested extraneous artifacts exist.
    4. Validates SHA-256 digests of all bundled artifacts against manifest.artifact_hashes.
    5. Canonicalizes manifest.json using RFC 8785 JSON Canonicalization Scheme (JCS).
    6. Resolves public key, verifies mathematical Ed25519 signature, and checks identity trust.

    Args:
        zip_path_or_bytes: Path to .zip file or raw bytes of ZIP archive.
        trusted_public_key: PEM string, hex string, or raw bytes of trusted public key.
        allow_embedded_key: If True, evaluates mathematical signature with embedded key
                            for self-consistency check, but marks identity as untrusted.

    Returns:
        VerificationResult with detailed cryptographic validation breakdown.
    """
    errors: list[str] = []
    warnings: list[str] = []
    artifacts_verified = 0
    total_artifacts = 0
    manifest_valid = False
    signature_valid = False
    trust_verified = False
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
            trust_verified=False,
            artifacts_verified=0,
            total_artifacts=0,
            errors=[f"Failed to open ZIP archive: {exc}"],
        )

    with zf:
        raw_names = zf.namelist()
        # 1. Check for duplicate filenames in archive header
        if len(raw_names) != len(set(raw_names)):
            return VerificationResult(
                is_valid=False,
                manifest_valid=False,
                signature_valid=False,
                trust_verified=False,
                artifacts_verified=0,
                total_artifacts=0,
                errors=["Malicious archive: duplicate filename entries detected in ZIP header."],
            )

        # 2. Inspect archive entries for path traversal and decompression bombs
        total_uncompressed = 0
        for info in zf.infolist():
            filename = info.filename

            # Path traversal check
            normalized = filename.replace("\\", "/")
            if ".." in normalized.split("/"):
                return VerificationResult(
                    is_valid=False,
                    manifest_valid=False,
                    signature_valid=False,
                    trust_verified=False,
                    artifacts_verified=0,
                    total_artifacts=0,
                    errors=[f"Malicious archive: path traversal sequence detected in '{filename}'."],
                )
            if normalized.startswith("/") or (len(normalized) > 1 and normalized[1] == ":"):
                return VerificationResult(
                    is_valid=False,
                    manifest_valid=False,
                    signature_valid=False,
                    trust_verified=False,
                    artifacts_verified=0,
                    total_artifacts=0,
                    errors=[f"Malicious archive: absolute path detected in '{filename}'."],
                )

            # Decompression bomb checks
            total_uncompressed += info.file_size
            if info.file_size > MAX_SINGLE_FILE_UNCOMPRESSED_BYTES:
                return VerificationResult(
                    is_valid=False,
                    manifest_valid=False,
                    signature_valid=False,
                    trust_verified=False,
                    artifacts_verified=0,
                    total_artifacts=0,
                    errors=[
                        f"Malicious archive: file '{filename}' size ({info.file_size} bytes) exceeds limit ({MAX_SINGLE_FILE_UNCOMPRESSED_BYTES} bytes)."
                    ],
                )

            if info.compress_size > 0:
                ratio = info.file_size / info.compress_size
                if ratio > MAX_COMPRESSION_RATIO:
                    return VerificationResult(
                        is_valid=False,
                        manifest_valid=False,
                        signature_valid=False,
                        trust_verified=False,
                        artifacts_verified=0,
                        total_artifacts=0,
                        errors=[
                            f"Malicious archive: decompression bomb detected in '{filename}' (compression ratio {ratio:.1f}:1 exceeds {MAX_COMPRESSION_RATIO}:1 limit)."
                        ],
                    )

        if total_uncompressed > MAX_TOTAL_UNCOMPRESSED_BYTES:
            return VerificationResult(
                is_valid=False,
                manifest_valid=False,
                signature_valid=False,
                trust_verified=False,
                artifacts_verified=0,
                total_artifacts=0,
                errors=[
                    f"Malicious archive: total uncompressed size ({total_uncompressed} bytes) exceeds limit ({MAX_TOTAL_UNCOMPRESSED_BYTES} bytes)."
                ],
            )

        namelist = set(raw_names)

        # 3. Locate manifest.json
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
                trust_verified=False,
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
                trust_verified=False,
                artifacts_verified=0,
                total_artifacts=0,
                errors=[f"Failed to parse manifest.json: {exc}"],
            )

        signing_kid = manifest.get("signing_kid")
        signature_hex = manifest.get("signature")
        artifact_hashes: dict[str, str] = manifest.get("artifact_hashes", {})
        total_artifacts = len(artifact_hashes)

        base_dir = manifest_filename[:-13]  # prefix if inside a folder

        # 4. Closed-world check: reject unmanifested extraneous artifacts
        allowed_archive_files = {manifest_filename}
        for rel_path in artifact_hashes:
            allowed_archive_files.add(f"{base_dir}{rel_path}" if base_dir else rel_path)

        # Check for embedded public key filename
        for name in namelist:
            if name.endswith("public_key.pem"):
                allowed_archive_files.add(name)

        unmanifested_files = [f for f in namelist if f not in allowed_archive_files and not f.endswith("/")]
        if unmanifested_files:
            errors.append(f"Unmanifested extraneous artifact(s) detected in archive: {unmanifested_files}")

        # 5. Verify all artifact SHA-256 digests
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

        # 6. Resolve Public Key & Enforce Identity Trust
        resolved_key = None
        if trusted_public_key:
            resolved_key = trusted_public_key
            trust_verified = True
        elif allow_embedded_key:
            # Find embedded public_key.pem for self-consistency only
            pk_filename = None
            for name in namelist:
                if name.endswith("public_key.pem"):
                    pk_filename = name
                    break
            if pk_filename:
                resolved_key = zf.read(pk_filename).decode("utf-8")
                trust_verified = False
                errors.append(
                    "Identity is UNTRUSTED: Package was verified using an embedded public key from an untrusted archive. "
                    "An explicit trusted_public_key is required for valid verification."
                )
            else:
                errors.append("No trusted public key provided, and archive has no embedded public_key.pem.")
        else:
            errors.append(
                "No trusted_public_key provided. To inspect mathematical self-consistency with embedded key, pass allow_embedded_key=True."
            )

        # 7. Cryptographically verify Ed25519 signature
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

    # Package is valid ONLY if all digests match, signature is valid, AND identity trust is explicitly verified
    is_valid = (
        manifest_valid
        and signature_valid
        and trust_verified
        and (artifacts_verified == total_artifacts)
        and (len(errors) == 0)
    )

    return VerificationResult(
        is_valid=is_valid,
        manifest_valid=manifest_valid,
        signature_valid=signature_valid,
        trust_verified=trust_verified,
        artifacts_verified=artifacts_verified,
        total_artifacts=total_artifacts,
        signing_kid=signing_kid,
        public_key_fingerprint=pub_key_fingerprint,
        errors=errors,
        warnings=warnings,
    )
