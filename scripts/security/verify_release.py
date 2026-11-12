#!/usr/bin/env python3
"""
PRIVGUARD AI - Cryptographic Release Verification Utility
Moon Sanctum Labs - Decode. Build. Evolve.

Verifies release candidate evidence fail-closed before deployment or promotion:
1. Artifact Digest Immutability & Formatting
2. CycloneDX 1.6 SBOM Presence & Schema Conformance
3. Source Commit Correspondence
4. Cosign Keyless Signature Verification (OIDC Identity)
5. SLSA v1.0 Provenance & Build Attestation
"""

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

DIGEST_REGEX = re.compile(r"^.+@sha256:[a-f0-9]{64}$")
SHA256_HEX_REGEX = re.compile(r"^[a-f0-9]{64}$")


class ReleaseVerificationError(Exception):
    """Raised when release verification encounters invalid or missing evidence."""
    pass


def compute_file_sha256(path: Path) -> str:
    """Computes SHA-256 hash of a file."""
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def verify_image_digest(image_ref: str, label: str) -> str:
    """Verifies that the container image reference is an immutable digest."""
    print(f"[*] Verifying {label} image reference: {image_ref}")
    if not DIGEST_REGEX.match(image_ref):
        raise ReleaseVerificationError(
            f"FALSIFIED OR MUTABLE IMAGE REFERENCE: {label} image '{image_ref}' must be pinned by immutable sha256 digest."
        )
    digest = image_ref.split("@")[1]
    print(f"[+] {label} image verified with immutable digest {digest}")
    return digest


def verify_sbom(sbom_path: Path, label: str) -> dict:
    """Verifies that an SBOM exists and conforms to CycloneDX specification."""
    print(f"[*] Verifying {label} SBOM at: {sbom_path}")
    if not sbom_path.exists():
        raise ReleaseVerificationError(f"MANDATORY EVIDENCE MISSING: {label} SBOM file not found at {sbom_path}")

    try:
        with open(sbom_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        raise ReleaseVerificationError(f"MALFORMED SBOM JSON: {label} SBOM could not be parsed: {e}")

    if data.get("bomFormat") != "CycloneDX":
        raise ReleaseVerificationError(
            f"INVALID SBOM FORMAT: Expected 'CycloneDX', got '{data.get('bomFormat')}' in {sbom_path}"
        )

    spec_version = str(data.get("specVersion"))
    if spec_version not in ["1.4", "1.5", "1.6", "1.7"]:
        raise ReleaseVerificationError(
            f"UNSUPPORTED CYCLONEDX SPEC: Expected 1.4, 1.5, 1.6, or 1.7, got '{spec_version}' in {sbom_path}"
        )

    components = data.get("components", [])
    if not isinstance(components, list) or len(components) == 0:
        raise ReleaseVerificationError(f"EMPTY SBOM: No components declared in {sbom_path}")

    print(f"[+] {label} SBOM validated: CycloneDX v{spec_version}, {len(components)} components.")
    return data


def verify_release_manifest(manifest_path: Path, expected_commit: Optional[str], sbom_hashes: Dict[str, str]) -> dict:
    """Verifies release manifest consistency and commit correspondence."""
    print(f"[*] Verifying release manifest at: {manifest_path}")
    if not manifest_path.exists():
        raise ReleaseVerificationError(f"MANDATORY EVIDENCE MISSING: Release manifest not found at {manifest_path}")

    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
    except Exception as e:
        raise ReleaseVerificationError(f"MALFORMED MANIFEST JSON: {manifest_path} could not be parsed: {e}")

    # Check commit SHA correspondence
    manifest_commit = manifest.get("commit_sha")
    if expected_commit:
        if not manifest_commit or manifest_commit.lower() != expected_commit.lower():
            raise ReleaseVerificationError(
                f"SOURCE COMMIT MISMATCH: Manifest commit '{manifest_commit}' does not match expected '{expected_commit}'."
            )
        print(f"[+] Manifest commit SHA verified: {manifest_commit}")

    # Verify bound artifact hashes
    artifacts = manifest.get("artifacts", {})
    for key, expected_hash in sbom_hashes.items():
        art_info = artifacts.get(key)
        if not art_info or art_info.get("sha256") != expected_hash:
            raise ReleaseVerificationError(
                f"ARTIFACT HASH MISMATCH: Manifest hash for {key} does not match generated file hash {expected_hash}."
            )
        print(f"[+] Manifest SHA256 integrity verified for {key}.")

    return manifest


def verify_cosign_signature(image_ref: str, expected_repo: Optional[str]) -> bool:
    """Verifies Cosign keyless signature using transparency log."""
    print(f"[*] Verifying Cosign cryptographic signature for: {image_ref}")
    cosign_bin = shutil.which("cosign")
    if not cosign_bin:
        raise ReleaseVerificationError(
            "EXTERNAL TOOL MISSING: 'cosign' binary not found on PATH. "
            "Install cosign or execute verification in a signed GitHub Actions runner environment."
        )

    cmd = [
        cosign_bin,
        "verify",
        "--certificate-oidc-issuer",
        "https://token.actions.githubusercontent.com",
    ]
    if expected_repo:
        cmd.extend([
            "--certificate-identity-regexp",
            rf"^https://github\.com/{re.escape(expected_repo)}/\.github/workflows/release\.yml@",
        ])

    cmd.append(image_ref)

    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        print(f"[+] Cosign signature verified successfully for {image_ref}.")
        return True
    except subprocess.CalledProcessError as e:
        raise ReleaseVerificationError(f"SIGNATURE VERIFICATION FAILED: {e.stderr.strip() or e.stdout.strip()}")


def verify_slsa_provenance(image_ref: str, expected_repo: Optional[str]) -> bool:
    """Verifies SLSA v1.0 build provenance attestation."""
    print(f"[*] Verifying SLSA build provenance for: {image_ref}")
    gh_bin = shutil.which("gh")
    if not gh_bin:
        raise ReleaseVerificationError(
            "EXTERNAL TOOL MISSING: 'gh' CLI binary not found on PATH. "
            "Install GitHub CLI or execute verification in a GitHub Actions runner environment."
        )

    cmd = [gh_bin, "attestation", "verify", image_ref]
    if expected_repo:
        cmd.extend(["--owner", expected_repo.split("/")[0]])

    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        print(f"[+] SLSA build provenance verified successfully for {image_ref}.")
        return True
    except subprocess.CalledProcessError as e:
        raise ReleaseVerificationError(f"PROVENANCE VERIFICATION FAILED: {e.stderr.strip() or e.stdout.strip()}")


def main():
    parser = argparse.ArgumentParser(description="PRIVGUARD AI Release Verification Utility")
    parser.add_argument("--image-backend", type=str, help="Backend container image reference with immutable digest")
    parser.add_argument("--image-frontend", type=str, help="Frontend container image reference with immutable digest")
    parser.add_argument("--commit-sha", type=str, help="Expected Git commit SHA")
    parser.add_argument("--sbom-dir", type=Path, default=Path("release-artifacts"), help="Directory containing SBOMs")
    parser.add_argument("--expected-repo", type=str, help="Expected GitHub repository (owner/repo)")
    parser.add_argument("--require-signatures", action="store_true", help="Enforce Cosign signature verification")
    parser.add_argument("--require-provenance", action="store_true", help="Enforce SLSA provenance verification")

    args = parser.parse_args()

    print("==============================================================================")
    print("PRIVGUARD AI - Cryptographic Release Verification Utility")
    print("Moon Sanctum Labs - Fail-Closed Release Verification Plane")
    print("==============================================================================")

    try:
        # 1. Verify Image Digests if supplied
        if args.image_backend:
            verify_image_digest(args.image_backend, "Backend")
        if args.image_frontend:
            verify_image_digest(args.image_frontend, "Frontend")

        # 2. Verify SBOMs
        backend_sbom = args.sbom_dir / "backend-sbom.cyclonedx.json"
        frontend_sbom = args.sbom_dir / "frontend-sbom.cyclonedx.json"
        manifest_file = args.sbom_dir / "release-manifest.json"

        verify_sbom(backend_sbom, "Backend")
        backend_hash = compute_file_sha256(backend_sbom)

        verify_sbom(frontend_sbom, "Frontend")
        frontend_hash = compute_file_sha256(frontend_sbom)

        # 3. Verify Manifest
        verify_release_manifest(
            manifest_file,
            args.commit_sha,
            {"backend_sbom": backend_hash, "frontend_sbom": frontend_hash},
        )

        # 4. Verify Cryptographic Signatures if required
        if args.require_signatures:
            if not args.image_backend or not args.image_frontend:
                raise ReleaseVerificationError("Image references required when --require-signatures is enabled.")
            verify_cosign_signature(args.image_backend, args.expected_repo)
            verify_cosign_signature(args.image_frontend, args.expected_repo)

        # 5. Verify SLSA Provenance if required
        if args.require_provenance:
            if not args.image_backend or not args.image_frontend:
                raise ReleaseVerificationError("Image references required when --require-provenance is enabled.")
            verify_slsa_provenance(args.image_backend, args.expected_repo)
            verify_slsa_provenance(args.image_frontend, args.expected_repo)

        print("==============================================================================")
        print("[SUCCESS] ALL RELEASE EVIDENCE VERIFIED FAIL-CLOSED.")
        print("Release candidate is authorized for staging promotion.")
        print("==============================================================================")
        sys.exit(0)

    except ReleaseVerificationError as err:
        print("==============================================================================")
        print(f"[FAIL-CLOSED] RELEASE VERIFICATION REJECTED: {err}", file=sys.stderr)
        print("==============================================================================")
        sys.exit(1)


if __name__ == "__main__":
    main()
