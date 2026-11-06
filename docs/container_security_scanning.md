# PRIVGUARD AI — Container & Filesystem Security Scanning

## 1. Overview

PRIVGUARD AI employs **Aqua Security Trivy** as its primary container image, filesystem, and configuration security scanner.

Trivy is integrated across the deployment pipeline to evaluate:
1. **Container Base Images**: Distroless and Alpine/Debian minimal runtimes.
2. **Filesystem Package Manifests**: Python PyPI requirements, Node.js npm packages, and Helm charts.
3. **Misconfigurations**: Dockerfile security anti-patterns and Kubernetes manifest compliance.

---

## 2. Scanning Integration (`security-scan.yml`)

The security workflow runs Trivy on daily schedules and on pushes to `main`:
```yaml
- name: Run Trivy vulnerability scanner
  uses: aquasecurity/trivy-action@18f2510ee396bbf400402947b394f2dd8c87dbb0 # v0.29.0
  with:
    scan-type: 'fs'
    ignore-unfixed: false
    severity: 'CRITICAL,HIGH'
    format: 'sarif'
    output: 'trivy-results.sarif'
```

Findings are compiled into standardized **SARIF 2.1.0** reports and uploaded directly to GitHub Advanced Security.

---

## 3. Suppression Management (`.trivyignore`)

All suppressions must be declared in [`.trivyignore`](file:///c:/Users/ANIKET/OneDrive/Documents/RIVA_AI/.trivyignore) at repository root.

### Mandatory Suppression Format
```
# Format:
# CVE-YYYY-NNNNN  # Package: <name>@<ver> | Severity: <SEV> | Reason: <architectural justification> | Compensating Control: <control> | Expires: YYYY-MM-DD | Approver: <lead>
```

### Suppression Criteria
Suppressions are only accepted if:
- The vulnerability is in an uncalled code path or build-time dev dependency.
- Upstream vendor has not released a patch.
- Active compensating controls (e.g. non-root execution, Caddy body limits, read-only root filesystems) fully mitigate exploitability.
- An expiration date within 30 days is recorded.

*Current Baseline*: **Zero active suppressions.**

---

## 4. Multi-Stage Container Hardening

PRIVGUARD's `Dockerfile` and `Dockerfile.frontend` implement multi-stage builds adhering to container security best practices:
- **Non-Root Execution**: Runs as unprivileged user `privguard:privguard` (UID 10001).
- **Read-Only Root Filesystem**: Write access restricted to ephemeral `/tmp` volumes.
- **No Package Managers in Final Stage**: Build tools (`gcc`, `pip`, `npm`) are discarded after compilation stages.
- **No Embedded Secrets**: Credentials and tokens are injected exclusively at runtime via Kubernetes Secrets or environment variables.

