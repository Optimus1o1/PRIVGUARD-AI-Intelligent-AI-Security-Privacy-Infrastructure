# PRIVGUARD AI — Release Management & Promotion

## 1. Release Lifecycle Overview

PRIVGUARD AI release engineering follows a strict semantic versioning and environment promotion model:

```
[ Feature Branches / PRs ]
           |
           v (Merge after all CI checks pass)
       [ main ]
           |
           v (Tag: git tag -s vX.Y.Z -m "Release vX.Y.Z")
    [ Release Tag ]
           |
           v (Automated GitHub Actions release.yml)
[ Build, Multi-Arch, Sign, SBOM & Provenance ]
           |
           v (Automatic deployment)
    [ Staging Cluster ]
           |
           v (Automated & Manual E2E Validation)
[ Moon Sanctum Labs Production Gate (Manual Approval) ]
           |
           v (Promote via Digest Binding)
  [ Production Cluster ]
```

---

## 2. Release Prerequisites & Checklist

Before cutting a new release tag:
1. **Branch Health**: All PR checks on `main` must be green.
2. **Audit Cleanliness**:
   - `pip-audit -r backend/requirements.txt`: 0 vulnerabilities.
   - `npm audit --prefix frontend`: 0 vulnerabilities.
   - `ruff check backend/app` and `bandit -r backend/app`: 0 issues.
3. **Secret Scan**: Gitleaks reports 0 secret leaks.
4. **Documentation**: Release notes and changelog updated in `docs/` and `CHANGELOG.md`.

---

## 3. Creating a Release

1. Ensure your local branch is synchronized with upstream `main`:
   ```bash
   git checkout main
   git pull origin main
   ```
2. Create and sign the semantic version tag:
   ```bash
   git tag -s v1.0.0 -m "Release v1.0.0: Enterprise Security & Privacy Enforcement"
   git push origin v1.0.0
   ```
3. Monitor `.github/workflows/release.yml`:
   - Verify `pre-release-check` passes.
   - Verify `build-and-sign` pushes images to GHCR and generates Cosign signatures in Rekor.
   - Verify `generate-sbom-provenance` creates CycloneDX 1.6 SBOMs and SLSA provenance.

---

## 4. Production Environment Gate

PRIVGUARD enforces a protected GitHub Environment named `production`:
- **Required Reviewers**: Authorized security reviewers (Moon Sanctum Labs leads) must approve the promotion in the GitHub Actions UI.
- **Wait Timer / Soak Period**: Configurable 15-minute observation window following staging deployment.
- **Immutable Digest Admission**: Helm charts deployed to production reference container images exclusively by their immutable SHA-256 digest (`image: ghcr.io/privguard-ai/privguard-backend@sha256:...`), guaranteeing that staging-tested artifacts are bit-for-bit identical to production code.

