# PRIVGUARD AI — CI/CD Pipeline Architecture

## 1. Overview

PRIVGUARD AI's continuous integration and continuous delivery (CI/CD) pipelines are designed to enforce deterministic, repeatable, and tamper-resistant verification of all source code, dependencies, containers, and deployment manifests.

The system uses three dedicated GitHub Actions workflows:

1. **Pull Request & Push Validation (`ci.yml`)**: Continuous integration gating on every branch and PR.
2. **Security & Vulnerability Scanning (`security-scan.yml`)**: Daily scheduled and push-triggered deep analysis.
3. **Protected Release & Distribution (`release.yml`)**: Tag-driven, cryptographically signed release pipeline with manual deployment gates.

---

## 2. Workflow Permissions Matrix

In accordance with the principle of least privilege, all workflows define a root-level empty permission block:
```yaml
permissions: {}
```
Individual jobs declare only the exact permissions strictly required for their operational steps.

| Workflow | Job | Permissions | Justification |
| :--- | :--- | :--- | :--- |
| **`ci.yml`** | `backend` | `contents: read` | Checkout code and run local linters/tests. |
| | `frontend` | `contents: read` | Checkout code and compile Next.js application. |
| | `infrastructure` | `contents: read` | Lint Helm charts, dockerfiles, and compose configurations. |
| **`security-scan.yml`** | `gitleaks` | `contents: read`, `security-events: write` | Scan repository history and upload SARIF results to GitHub Security tab. |
| | `trivy` | `contents: read`, `security-events: write` | Scan filesystem/dependencies and upload SARIF results. |
| **`release.yml`** | `pre-release-check` | `contents: read` | Validate tests and linter baseline on tag. |
| | `build-and-sign` | `contents: read`, `packages: write`, `id-token: write` | Publish container images to GHCR and request ephemeral OIDC token for Cosign keyless signing. |
| | `generate-sbom-provenance` | `contents: read`, `actions: read`, `id-token: write` | Generate CycloneDX SBOMs and SLSA v1.0 Level 3 provenance attestation. |
| | `deploy-production` | `contents: read` | Execute gated deployment to production Kubernetes cluster. |

---

## 3. Immutable Action Pinning

Floating tags (e.g. `@v4`, `@main`) represent significant supply chain attack surfaces, as a compromised upstream action repository can immediately execute arbitrary code inside PRIVGUARD's CI runners.

PRIVGUARD requires **all third-party actions to be pinned to immutable 40-character commit SHAs**. For readability and auditing, the human-readable semver version is preserved as an inline comment:

```yaml
# Example: Pinned GitHub Action
- name: Checkout repository
  uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
  with:
    fetch-depth: 0
```

All 14 external action invocations across `.github/workflows/` are verified for SHA-40 compliance by automated unit test `test_02_action_sha_pinning`.

---

## 4. Pipeline Topology & Concurrency Controls

```
               [ Pull Request / Commit Push ]
                             |
         +-------------------+-------------------+
         |                   |                   |
         v                   v                   v
+-----------------+ +-----------------+ +-----------------+
|   Job: backend  | |  Job: frontend  | | Job: infra      |
|                 | |                 | |                 |
| - Ruff check    | | - npm audit     | | - Docker lint   |
| - Ruff format   | | - npm test      | | - Compose check |
| - Bandit AST    | | - Next.js build | | - Helm lint     |
| - pip-audit     | | (31 routes)     | +-----------------+
| - Pytest (355+) | +-----------------+
+-----------------+
         |                   |                   |
         +-------------------+-------------------+
                             |
                             v
                 [ Merge Gate: All Pass ]
```

### Concurrency Grouping
To conserve runner capacity and prevent race conditions, all workflows define cancellation groups:
```yaml
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true
```
This ensures that pushes to active pull requests immediately cancel stale, in-flight CI runs.

---

## 5. Security Scanning Workflow (`security-scan.yml`)

The security workflow runs daily at `02:00 UTC` and upon pushes to `main`:
- **Gitleaks Job**: Scans repository history using `.gitleaks.toml`. Produces both human-readable stdout summary and SARIF report.
- **Trivy Job**: Scans repository root filesystem, package manifests, and dependency trees using `.trivyignore`.
- **SARIF Integration**: Automatically pushes findings to GitHub Advanced Security Code Scanning alert board.

---

## 6. Release & Production Gating (`release.yml`)

When a semantic version tag (`v*.*.*`) is pushed:
1. **Pre-Release Check**: Executes full backend and frontend regression test suites.
2. **Build and Multi-Arch Packaging**: Builds container images (`backend`, `frontend`, `event-worker`) for `linux/amd64` and `linux/arm64`.
3. **Cosign Keyless Signing**: Uses GitHub Actions OIDC (`id-token: write`) to sign container images with Sigstore. Records cryptographic transparency log entry in Rekor.
4. **SBOM & Provenance**: Runs `scripts/security/generate_sboms.py` to produce CycloneDX 1.6 SBOMs for all runtimes and packages SLSA v1.0 build provenance.
5. **Gated Production Deployment**: Deploys to `production` environment, requiring explicit approval from authorized Moon Sanctum Labs reviewers. Images are admitted exclusively by cryptographic digest (`image@sha256:...`).

