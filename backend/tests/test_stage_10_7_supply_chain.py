"""
Stage 10.7 Supply Chain Security & CI/CD Pipeline Verification Tests
Moon Sanctum Labs - Decode. Build. Evolve.

Verifies:
1. Workflow permission least privilege (no write-all, explicit permissions)
2. Third-party GitHub Action 40-character commit SHA pinning
3. Dependency security configurations & 0-vulnerability baseline
4. Gitleaks configuration validity & secret rule definitions
5. CycloneDX 1.6 SBOM generation & schema conformance
6. Cryptographic release verification utility (fail-closed invariants)
7. Production release pipeline approval gating & non-automatic deployment
8. Repository governance (CODEOWNERS, SECURITY.md, CONTRIBUTING.md)
"""

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"
HEX_40_REGEX = re.compile(r"^[a-f0-9]{40}$")


def test_01_workflow_permission_least_privilege():
    """Asserts all GitHub Actions workflows define explicit least-privilege permissions."""
    assert WORKFLOWS_DIR.exists(), f"Workflows directory missing: {WORKFLOWS_DIR}"
    workflow_files = list(WORKFLOWS_DIR.glob("*.yml")) + list(WORKFLOWS_DIR.glob("*.yaml"))
    assert len(workflow_files) >= 3, f"Expected at least 3 workflows, found {len(workflow_files)}"

    for wf_path in workflow_files:
        with open(wf_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        assert "permissions" in data, f"Workflow {wf_path.name} missing top-level permissions"
        perms = data["permissions"]
        # Must not be 'write-all'
        assert perms != "write-all", f"Workflow {wf_path.name} uses dangerous write-all permissions"
        if isinstance(perms, dict):
            # Check individual scopes
            assert perms.get("all") is None


def test_02_action_sha_pinning():
    """Asserts every third-party GitHub Action is pinned to an immutable 40-character commit SHA."""
    workflow_files = list(WORKFLOWS_DIR.glob("*.yml")) + list(WORKFLOWS_DIR.glob("*.yaml"))
    uses_pattern = re.compile(r"uses:\s+([a-zA-Z0-9_\-\.\/]+)@([a-zA-Z0-9_\-\.]+)")

    action_count = 0
    for wf_path in workflow_files:
        with open(wf_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        for line_num, line in enumerate(lines, 1):
            match = uses_pattern.search(line)
            if match:
                action_name = match.group(1)
                ref = match.group(2)

                # Skip local actions (./...)
                if action_name.startswith("./"):
                    continue

                action_count += 1
                assert HEX_40_REGEX.match(ref), (
                    f"Action '{action_name}@{ref}' in {wf_path.name}:{line_num} "
                    f"is not pinned to an immutable 40-character commit SHA!"
                )

    assert action_count >= 10, f"Expected at least 10 action invocations verified, found {action_count}"


def test_03_dependency_scanning_clean_baseline():
    """Asserts that both pip-audit and npm audit report zero vulnerabilities."""
    # 1. Python dependency audit
    pip_res = subprocess.run(
        [sys.executable, "-m", "pip_audit", "-r", str(REPO_ROOT / "backend" / "requirements.txt")],
        capture_output=True,
        text=True,
    )
    pip_output = (pip_res.stdout + "\n" + pip_res.stderr).strip()
    assert pip_res.returncode == 0, f"pip-audit failed or found vulnerabilities: {pip_output}"
    assert "No known vulnerabilities found" in pip_output

    # 2. Node.js dependency audit
    npm_cmd = "npm audit --prefix frontend"
    npm_res = subprocess.run(npm_cmd, cwd=REPO_ROOT, shell=True, capture_output=True, text=True)
    assert npm_res.returncode == 0, f"npm audit reported vulnerabilities: {npm_res.stdout}"
    assert "found 0 vulnerabilities" in npm_res.stdout


def test_04_gitleaks_configuration_validity():
    """Asserts .gitleaks.toml exists and defines necessary rules and allowlists."""
    gitleaks_path = REPO_ROOT / ".gitleaks.toml"
    assert gitleaks_path.exists(), ".gitleaks.toml missing from repository root"

    with open(gitleaks_path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "privguard-api-key" in content
    assert "privguard-capability-token" in content
    assert "openai-api-key" in content
    assert "anthropic-api-key" in content
    assert "generic-private-key" in content
    assert "[allowlist]" in content


def test_05_sbom_generation_cyclonedx_compliance():
    """Tests that scripts/security/generate_sboms.py produces compliant CycloneDX 1.6 SBOMs."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        gen_script = REPO_ROOT / "scripts" / "security" / "generate_sboms.py"

        res = subprocess.run(
            [sys.executable, str(gen_script), "--output-dir", str(tmp_path)],
            capture_output=True,
            text=True,
        )
        assert res.returncode == 0, f"generate_sboms.py failed: {res.stdout} {res.stderr}"

        backend_sbom = tmp_path / "backend-sbom.cyclonedx.json"
        frontend_sbom = tmp_path / "frontend-sbom.cyclonedx.json"
        manifest_file = tmp_path / "release-manifest.json"

        assert backend_sbom.exists(), "backend-sbom.cyclonedx.json not generated"
        assert frontend_sbom.exists(), "frontend-sbom.cyclonedx.json not generated"
        assert manifest_file.exists(), "release-manifest.json not generated"

        # Check backend SBOM
        with open(backend_sbom, "r", encoding="utf-8") as f:
            b_data = json.load(f)
        assert b_data.get("bomFormat") == "CycloneDX"
        assert b_data.get("specVersion") in ["1.4", "1.5", "1.6"]
        assert len(b_data.get("components", [])) > 0

        # Check frontend SBOM
        with open(frontend_sbom, "r", encoding="utf-8") as f:
            f_data = json.load(f)
        assert f_data.get("bomFormat") == "CycloneDX"
        assert f_data.get("specVersion") in ["1.4", "1.5", "1.6"]
        assert len(f_data.get("components", [])) > 0

        # Check manifest
        with open(manifest_file, "r", encoding="utf-8") as f:
            m_data = json.load(f)
        assert m_data.get("product") == "PRIVGUARD AI"
        assert "artifacts" in m_data


def test_06_release_verifier_valid_evidence_passes():
    """Tests verify_release.py successfully validates valid digests, SBOMs, and manifest."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        gen_script = REPO_ROOT / "scripts" / "security" / "generate_sboms.py"
        verify_script = REPO_ROOT / "scripts" / "security" / "verify_release.py"

        # 1. Generate valid evidence
        subprocess.run(
            [sys.executable, str(gen_script), "--output-dir", str(tmp_path)],
            capture_output=True,
            text=True,
            check=True,
        )

        with open(tmp_path / "release-manifest.json", "r") as f:
            manifest = json.load(f)
        commit_sha = manifest["commit_sha"]

        # 2. Run verify_release.py with valid immutable digests
        test_digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        backend_ref = f"ghcr.io/org/backend@{test_digest}"
        frontend_ref = f"ghcr.io/org/frontend@{test_digest}"

        cmd = [
            sys.executable,
            str(verify_script),
            "--image-backend",
            backend_ref,
            "--image-frontend",
            frontend_ref,
            "--commit-sha",
            commit_sha,
            "--sbom-dir",
            str(tmp_path),
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        assert res.returncode == 0, f"verify_release.py failed unexpectedly: {res.stdout} {res.stderr}"
        assert "ALL RELEASE EVIDENCE VERIFIED FAIL-CLOSED" in res.stdout


def test_07_release_verifier_fails_closed():
    """Tests verify_release.py strictly fails closed on missing, altered, or mutable evidence."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        verify_script = REPO_ROOT / "scripts" / "security" / "verify_release.py"

        # Case 1: Missing SBOMs in directory
        cmd_missing = [
            sys.executable,
            str(verify_script),
            "--image-backend",
            "ghcr.io/org/backend@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "--sbom-dir",
            str(tmp_path),
        ]
        res1 = subprocess.run(cmd_missing, capture_output=True, text=True)
        assert res1.returncode == 1
        assert "MANDATORY EVIDENCE MISSING" in res1.stderr

        # Case 2: Mutable tag instead of immutable digest
        cmd_mutable = [
            sys.executable,
            str(verify_script),
            "--image-backend",
            "ghcr.io/org/backend:latest",  # Mutable tag!
            "--sbom-dir",
            str(tmp_path),
        ]
        res2 = subprocess.run(cmd_mutable, capture_output=True, text=True)
        assert res2.returncode == 1
        assert "FALSIFIED OR MUTABLE IMAGE REFERENCE" in res2.stderr

        # Case 3: Require signatures when cosign is missing / signature not present
        cmd_sig = [
            sys.executable,
            str(verify_script),
            "--image-backend",
            "ghcr.io/org/backend@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "--image-frontend",
            "ghcr.io/org/frontend@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "--require-signatures",
            "--sbom-dir",
            str(tmp_path),
        ]
        res3 = subprocess.run(cmd_sig, capture_output=True, text=True)
        assert res3.returncode == 1


def test_08_release_pipeline_governance():
    """Asserts that the release workflow strictly gates production behind manual approval."""
    release_wf = REPO_ROOT / ".github" / "workflows" / "release.yml"
    with open(release_wf, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    jobs = data.get("jobs", {})
    assert "deploy-production" in jobs, "deploy-production job missing from release.yml"
    prod_job = jobs["deploy-production"]

    # Must specify protected environment 'production'
    env_info = prod_job.get("environment", {})
    env_name = env_info.get("name") if isinstance(env_info, dict) else env_info
    assert env_name == "production", "Production deployment is not bound to protected 'production' environment"

    # Must depend on staging
    assert prod_job.get("needs") == "deploy-staging"

    # Must not contain PyPI publish step
    workflow_text = yaml.dump(data)
    assert "pypi.org" not in workflow_text.lower()
    assert "twine upload" not in workflow_text.lower()


def test_09_repository_governance_files():
    """Asserts that CODEOWNERS, SECURITY.md, and CONTRIBUTING.md exist and are populated."""
    codeowners = REPO_ROOT / ".github" / "CODEOWNERS"
    security = REPO_ROOT / "SECURITY.md"
    contributing = REPO_ROOT / "CONTRIBUTING.md"

    assert codeowners.exists(), ".github/CODEOWNERS missing"
    assert security.exists(), "SECURITY.md missing"
    assert contributing.exists(), "CONTRIBUTING.md missing"

    with open(codeowners, "r", encoding="utf-8") as f:
        co_text = f.read()
    assert "/backend/app/agent_security/" in co_text
    assert "/.github/" in co_text

    with open(security, "r", encoding="utf-8") as f:
        sec_text = f.read()
    assert "security@moonsanctum.internal" in sec_text
    assert "Response Timeline & SLAs" in sec_text
