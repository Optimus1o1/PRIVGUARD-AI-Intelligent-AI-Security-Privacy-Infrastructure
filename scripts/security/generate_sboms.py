#!/usr/bin/env python3
"""
PRIVGUARD AI - Software Bill of Materials (SBOM) Generator
Moon Sanctum Labs - Decode. Build. Evolve.

Generates CycloneDX 1.6 compliant Software Bills of Materials (SBOMs) for:
1. Python Backend Dependencies
2. Node.js Frontend Dependencies
3. Release Manifest binding SBOM hashes to source commit SHA
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def compute_sha256(file_path: Path) -> str:
    """Computes SHA-256 cryptographic digest of a file."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def get_git_commit(repo_root: Path) -> str:
    """Retrieves current Git commit SHA."""
    try:
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=True,
        )
        return res.stdout.strip()
    except Exception:
        return "UNKNOWN_COMMIT"


def generate_backend_sbom(output_path: Path, repo_root: Path) -> dict:
    """Generates CycloneDX 1.6 SBOM for the Python backend."""
    print(f"[*] Generating Python Backend SBOM at {output_path}...")
    
    # Try cyclonedx-py in current python environment
    cmd = [
        sys.executable,
        "-m",
        "cyclonedx_py",
        "environment",
        "-o",
        str(output_path),
        "--output-format",
        "json",
    ]
    
    res = subprocess.run(cmd, cwd=repo_root, capture_output=True, text=True)
    if res.returncode != 0:
        # Fallback to requirements mode if environment scan encounters issues
        print(f"[-] Environment scan failed: {res.stderr.strip()}. Falling back to requirements mode...")
        req_file = repo_root / "backend" / "requirements.txt"
        fallback_cmd = [
            sys.executable,
            "-m",
            "cyclonedx_py",
            "requirements",
            str(req_file),
            "-o",
            str(output_path),
            "--output-format",
            "json",
        ]
        fallback_res = subprocess.run(fallback_cmd, cwd=repo_root, capture_output=True, text=True, check=True)

    with open(output_path, "r", encoding="utf-8") as f:
        sbom_data = json.load(f)

    if sbom_data.get("bomFormat") != "CycloneDX":
        raise ValueError(f"Invalid SBOM format: {sbom_data.get('bomFormat')}")

    print(f"[+] Backend SBOM generated successfully: {len(sbom_data.get('components', []))} components.")
    return sbom_data


def generate_frontend_sbom(output_path: Path, repo_root: Path) -> dict:
    """Generates CycloneDX 1.6 SBOM for the Node.js frontend."""
    frontend_dir = repo_root / "frontend"
    print(f"[*] Generating Frontend SBOM at {output_path}...")

    # Run cyclonedx-npm via npx in frontend directory
    # On Windows, npx must be run with shell=True
    cmd = f'npx --yes @cyclonedx/cyclonedx-npm --spec-version 1.6 --package-lock-only -o "{output_path.resolve()}"'
    res = subprocess.run(cmd, cwd=frontend_dir, shell=True, capture_output=True, text=True)
    
    if res.returncode != 0:
        raise RuntimeError(f"cyclonedx-npm failed: {res.stderr.strip() or res.stdout.strip()}")

    with open(output_path, "r", encoding="utf-8") as f:
        sbom_data = json.load(f)

    if sbom_data.get("bomFormat") != "CycloneDX":
        raise ValueError(f"Invalid SBOM format: {sbom_data.get('bomFormat')}")

    print(f"[+] Frontend SBOM generated successfully: {len(sbom_data.get('components', []))} components.")
    return sbom_data


def main():
    parser = argparse.ArgumentParser(description="PRIVGUARD AI CycloneDX 1.6 SBOM Generator")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("release-artifacts"),
        help="Directory to place generated SBOM files and release manifest",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent.parent
    output_dir = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    backend_sbom_file = output_dir / "backend-sbom.cyclonedx.json"
    frontend_sbom_file = output_dir / "frontend-sbom.cyclonedx.json"
    manifest_file = output_dir / "release-manifest.json"

    print("==============================================================================")
    print("PRIVGUARD AI - Software Bill of Materials (SBOM) Generation Engine")
    print(f"Moon Sanctum Labs - Target Directory: {output_dir.resolve()}")
    print("==============================================================================")

    # 1. Generate Backend SBOM
    backend_data = generate_backend_sbom(backend_sbom_file, repo_root)
    backend_hash = compute_sha256(backend_sbom_file)

    # 2. Generate Frontend SBOM
    frontend_data = generate_frontend_sbom(frontend_sbom_file, repo_root)
    frontend_hash = compute_sha256(frontend_sbom_file)

    # 3. Create Release Manifest
    commit_sha = get_git_commit(repo_root)
    timestamp = datetime.now(timezone.utc).isoformat()

    manifest = {
        "schema_version": "1.0.0",
        "product": "PRIVGUARD AI",
        "organization": "Moon Sanctum Labs",
        "generated_at": timestamp,
        "commit_sha": commit_sha,
        "artifacts": {
            "backend_sbom": {
                "file": backend_sbom_file.name,
                "format": backend_data.get("bomFormat"),
                "spec_version": backend_data.get("specVersion"),
                "components_count": len(backend_data.get("components", [])),
                "sha256": backend_hash,
            },
            "frontend_sbom": {
                "file": frontend_sbom_file.name,
                "format": frontend_data.get("bomFormat"),
                "spec_version": frontend_data.get("specVersion"),
                "components_count": len(frontend_data.get("components", [])),
                "sha256": frontend_hash,
            },
        },
    }

    with open(manifest_file, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print(f"[+] Release manifest generated at {manifest_file}")
    print("==============================================================================")
    print("SBOM GENERATION COMPLETE")
    print(f"Backend SBOM SHA256:  {backend_hash}")
    print(f"Frontend SBOM SHA256: {frontend_hash}")
    print("==============================================================================")


if __name__ == "__main__":
    main()

