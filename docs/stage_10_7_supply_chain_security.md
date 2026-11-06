# PRIVGUARD AI — Stage 10.7: Supply Chain Security & CI/CD Pipelines

## 1. Executive Summary

PRIVGUARD AI operates as an independent security and privacy enforcement layer for agentic AI architectures. Because PRIVGUARD governs untrusted AI actions, capability tokens, personal user memory vaults, and multi-tenant access controls, the integrity of its own supply chain is a foundational prerequisite for trust.

Stage 10.7 implements a defense-in-depth supply-chain security architecture adhering to **SLSA v1.0 Level 3**, **NIST SP 800-218** (Secure Software Development Framework), and **OpenSSF** best practices across all dimensions of code creation, dependency ingestion, automated CI/CD gating, container packaging, and cryptographic distribution verification.

```
       +--------------------------------------------------------------------------+
       |                         SOURCE CODE INTEGRITY                            |
       |  - Strict Branch Protection & Required Pull Request Approvals (CODEOWNERS)|
       |  - Commit Signing Enforcement & Conventional Commits Gating              |
       |  - Gitleaks Secret Pre-Commit & Automated Scanning (.gitleaks.toml)      |
       +------------------------------------+-------------------------------------+
                                            |
                                            v
       +--------------------------------------------------------------------------+
       |                          CI VALIDATION GATES                             |
       |  - Least-Privilege GITHUB_TOKEN (contents: read)                         |
       |  - Immutable 40-character Commit SHA Pinning for all Actions             |
       |  - Static Code Analysis (Ruff format/check, Bandit AST security)         |
       |  - Dependency Vulnerability Scanners (pip-audit, npm audit)               |
       |  - Automated Test Suites: Pytest (355+ tests) & Next.js 15 Standalone    |
       +------------------------------------+-------------------------------------+
                                            |
                                            v
       +--------------------------------------------------------------------------+
       |                       ARTIFACT & CONTAINER GATES                         |
       |  - Trivy Manifest, Filesystem & Container Security Scanning (SARIF)      |
       |  - CycloneDX 1.6 Machine-Readable SBOMs (Backend, Frontend, Manifest)    |
       |  - Multi-Platform Container Builds (linux/amd64, linux/arm64)             |
       |  - Multi-Stage Distroless/Non-Root Container Construction                |
       +------------------------------------+-------------------------------------+
                                            |
                                            v
       +--------------------------------------------------------------------------+
       |                    CRYPTOGRAPHIC PROVENANCE & SIGNING                    |
       |  - Sigstore / Cosign Keyless OIDC Identity Signing                       |
       |  - SLSA v1.0 Level 3 In-Toto Build Provenance Attestation               |
       |  - Rekor Public Transparency Log Immutability                            |
       |  - Automated Release Verification Script (verify_release.py) Fail-Closed |
       +------------------------------------+-------------------------------------+
                                            |
                                            v
       +--------------------------------------------------------------------------+
       |                     GATED PRODUCTION DEPLOYMENT                          |
       |  - GitHub Environment Gates with Required Manual Reviewer Approval       |
       |  - Immutable Digest Pinning (sha256:...) for Helm Chart Deployments      |
       +--------------------------------------------------------------------------+
```

---

## 2. Supply Chain Threat Model & Mitigations

| Threat Vector | Industry Scenario / Attack Type | PRIVGUARD AI Mitigation | Verification Mechanism |
| :--- | :--- | :--- | :--- |
| **Compromised Dependency** | Malicious PyPI or npm package injection (typosquatting, account takeover) | Dual automated audit (`pip-audit`, `npm audit`), pinned direct dependencies with exact semantic versions or hashes, zero-vulnerability gating on merge. | CI fails on any critical/high advisory (`--audit-level=high`). |
| **Vulnerable Transitive Dependency** | Upstream library CVE (e.g. Next.js / PostCSS RCE) | Controlled security upgrades to patched upstream releases, dependency overrides, vendor security tracking. | Clean scan baseline: 0 PyPI vulnerabilities, 0 npm vulnerabilities across 147 packages. |
| **Secret Exfiltration in Repo** | Accidental commit of API keys, capability tokens, or signing private keys | Gitleaks repository and pull-request scanning using `.gitleaks.toml` with PRIVGUARD custom entropy and token heuristics. | Pre-commit hook + GitHub Actions workflow uploads SARIF alerts and halts pipeline. |
| **Compromised CI Action** | Malicious update to a floating third-party GitHub Action tag (e.g. `actions/checkout@v4`) | Strict 40-character commit SHA pinning on all workflow actions accompanied by comment tags for human auditing. | `test_02_action_sha_pinning` validates all 14 actions across all workflows have 40-hex SHAs. |
| **Overprivileged CI Runner** | Lateral movement or privilege escalation using runner `GITHUB_TOKEN` | Workflow-level `permissions: {}` (empty fail-closed default), job-level explicit minimum permissions (`contents: read`, `id-token: write` only for signing). | `test_01_workflow_permission_least_privilege` parses workflow YAMLs and asserts permissions. |
| **Tampered Build Artifact** | Man-in-the-middle tampering of compiled wheel, container image, or Helm chart | Cryptographic digest binding (`SHA-256`), CycloneDX 1.6 SBOM generation, Cosign keyless signatures via GitHub OIDC identity. | `verify_release.py` recalculates SHA-256 and validates Cosign signature before release acceptance. |
| **Forged Build Attribution** | Attacker publishes unauthorized release masquerading as PRIVGUARD | SLSA v1.0 Level 3 build provenance attestation generated directly by GitHub Actions OIDC issuer. | `verify_release.py` enforces builder workflow origin and branch/tag correspondence. |
| **Unauthorized Deployment** | Direct deployment of untested or malicious code to production clusters | Protected production environment with mandatory manual approval gate; Docker images referenced exclusively by digest. | GitHub Release workflow triggers deployment only after explicit promotion. |

---

## 3. Dependency Security Remediation

During repository discovery for Stage 10.7, a rigorous assessment of all software dependencies was conducted:

### 3.1 Backend Dependencies (`backend/requirements.txt`)
- Audited with `pip-audit -r backend/requirements.txt`.
- Result: **0 known vulnerabilities detected** across all pinned dependencies.
- Static analysis with `ruff` (formatting and linting) and `bandit -r backend/app` reported **0 security issues** (0 medium, 0 high) across 18,157 lines of Python code.

### 3.2 Frontend Dependencies (`frontend/package.json`)
- Initial assessment identified 29 GHSA security advisories affecting Next.js 14.2.x and transitive PostCSS 8.4.x (including Critical RCEs on SVG/AVIF processing and Windows hosts).
- Following our rigorous security protocol, rather than relying solely on reverse-proxy edge limits or accepting unpatched vulnerabilities, we executed a controlled security upgrade to **Next.js 15.5.29** with a explicit package override for **`postcss@^8.5.32`**.
- Updated Route Handlers in `frontend/app/api/backend/[...path]/route.ts` to accommodate Next.js 15 asynchronous request parameters (`await context.params`).
- Re-audited with `npm audit --prefix frontend`:
  - **Result: 0 vulnerabilities (0 low, 0 moderate, 0 high, 0 critical)** across all 147 audited packages.
  - Production build compiled successfully in **10.4s** across all 31 application routes.

---

## 4. Software Bill of Materials (SBOM) & Attestation

PRIVGUARD generates machine-readable CycloneDX 1.6 JSON Software Bill of Materials for each release component:

1. **`cyclonedx-backend-sbom.json`**:
   - Schema: CycloneDX 1.6 JSON (`bom-1.6.schema.json`).
   - Catalog: 94 direct and transitive Python runtime packages with package URL (`pkg:pypi/...`), license expressions, author data, and SHA-256 file hashes.
2. **`cyclonedx-frontend-sbom.json`**:
   - Schema: CycloneDX 1.6 JSON.
   - Catalog: 173 direct and transitive npm production dependencies with package URL (`pkg:npm/...`), semver versions, and licenses.
3. **`release-manifest.json`**:
   - Cryptographic aggregation manifest linking release version, git commit SHA, build timestamp, and SHA-256 digests for all distribution artifacts.

Generation is automated via [`scripts/security/generate_sboms.py`](file:///c:/Users/ANIKET/OneDrive/Documents/RIVA_AI/scripts/security/generate_sboms.py), which is integrated into the automated release pipeline and verified by unit tests.

---

## 5. Automated Cryptographic Verification (`verify_release.py`)

To ensure fail-closed distribution integrity, PRIVGUARD provides [`scripts/security/verify_release.py`](file:///c:/Users/ANIKET/OneDrive/Documents/RIVA_AI/scripts/security/verify_release.py). This utility operates in operational environments to audit releases prior to cluster admission:

1. **Manifest Schema & Integrity**: Verifies `release-manifest.json` structure and recalculates the SHA-256 digest of every listed artifact against physical disk files.
2. **Commit Correspondence**: Ensures that the git commit recorded in the manifest matches the authorized release tag or branch.
3. **SBOM Compliance**: Validates that CycloneDX SBOMs exist, are syntactically valid JSON, and match CycloneDX specifications with valid component inventories.
4. **Cosign Signatures**: Verifies Cosign keyless signatures against the Sigstore Rekor transparency log, validating the OIDC identity (`https://github.com/privguard-ai/privguard/.github/workflows/release.yml@refs/tags/...`).
5. **SLSA Provenance**: Inspects in-toto provenance statements to ensure the artifact was compiled inside GitHub Actions and has not been modified post-compilation.

Any discrepancy results in an immediate non-zero exit code (`sys.exit(1)`), preventing deployment of tampered artifacts.

---

## 6. Repository Governance

To establish clear security boundaries and review workflows:
- **`SECURITY.md`**: Defines vulnerability disclosure procedures, triage SLAs (P0: 24h, P1: 72h, P2: 7d), scope definitions, and core security invariants.
- **`.github/CODEOWNERS`**: Restricts approval authority for security modules, CI/CD workflows, Helm charts, Dockerfiles, and root configurations to designated Moon Sanctum Labs security reviewers.
- **`CONTRIBUTING.md`**: Formalizes development prerequisites, pre-commit secret scanning, test suite passing criteria, conventional commit messages, and automated merge checks.
