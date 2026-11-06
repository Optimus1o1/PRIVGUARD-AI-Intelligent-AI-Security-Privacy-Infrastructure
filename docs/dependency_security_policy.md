# PRIVGUARD AI — Dependency Security Policy

## 1. Purpose & Scope

This policy governs the acquisition, auditing, upgrading, and suppression of all external software dependencies across PRIVGUARD AI:
- Python runtime libraries (`backend/requirements.txt`)
- Node.js runtime and build packages (`frontend/package.json`)
- Base container images (`Dockerfile`, `Dockerfile.frontend`)
- Helm dependencies and sub-charts

PRIVGUARD AI adheres to a **zero-tolerance baseline for unmitigated Critical and High vulnerabilities** in production artifacts.

---

## 2. Dependency Audit Invariants

1. **Automated CI Enforcement**:
   - Every Pull Request runs `pip-audit` against `backend/requirements.txt` and `npm audit --audit-level=high` against `frontend/package.json`.
   - Any unsuppressed Critical or High vulnerability immediately halts the build with exit code 1.
2. **Pinned Versions**:
   - Python dependencies must be explicitly pinned to exact or minimum compatible versions with proven security fixes.
   - Node.js dependencies must maintain an up-to-date `package-lock.json` with integrity hashes (`sha512`).
3. **No Unreviewed Force Upgrades**:
   - Automated `npm audit fix --force` is strictly prohibited on production codebases because it risks introducing breaking major version transitions without backward compatibility verification.
   - Upgrades must be tested against application routes and functional test suites.

---

## 3. Vulnerability Remediation Protocol

When a security vulnerability is identified in an external dependency:

```
[ Vulnerability Detected ]
           |
           v
+------------------------------------+
| 1. Assess CVSS & Exploitability    |
|    - Is vulnerable code reachable? |
|    - What is attack vector?        |
+------------------+-----------------+
                   |
                   v
+------------------------------------+
| 2. Check for In-Line Vendor Patch  |
|    - Patch available in current    |
|      minor/patch release stream?   |
+------------------+-----------------+
        /                    \
     [Yes]                  [No]
      /                        \
     v                          v
+-----------------------+ +-----------------------------------+
| 3. Apply Patch Update | | 4. Controlled Major Upgrade or    |
|    - Bump version     | |    Transitive Dependency Override |
|    - Run test suite   | |    - e.g. overrides in npm        |
|    - Verify fix       | |    - Regression test application  |
+-----------------------+ +-----------------+-----------------+
                                            |
                                            v
                                [ If No Upstream Patch Exists ]
                                            |
                                            v
                                +-----------------------------------+
                                | 5. Formal Exception Request       |
                                |    - Compensating defense-in-depth|
                                |    - Time-bounded expiry (max 30d)|
                                |    - Sign-off in .trivyignore     |
                                +-----------------------------------+
```

---

## 4. Remediation SLAs

| Severity | CVSS v3/v4 Score | Triage SLA | Remediation / Patch SLA |
| :--- | :--- | :--- | :--- |
| **Critical** | 9.0 – 10.0 | ≤ 4 hours | ≤ 24 hours |
| **High** | 7.0 – 8.9 | ≤ 12 hours | ≤ 72 hours |
| **Medium** | 4.0 – 6.9 | ≤ 48 hours | ≤ 14 days |
| **Low** | 0.1 – 3.9 | ≤ 7 days | Next planned release cycle |

---

## 5. Formal Suppression Guidelines

Suppressions in `.trivyignore` or audit exclusion files are treated as formal security risks and require:
1. **Vulnerability ID** (CVE or GHSA).
2. **Component & Version** affected.
3. **Technical Rationale**: Architectural evidence why the vulnerable code path is unreachable in PRIVGUARD's deployment environment.
4. **Compensating Controls**: Active security mechanisms that neutralize the risk (e.g. Caddy request body limits, network policy isolation, non-root execution).
5. **Expiration Date**: Maximum 30 calendar days from registration.
6. **Approver**: Moon Sanctum Labs Security Lead sign-off.

*Current Status*: **Zero (0) active suppressions.** Both Python and Node.js environments maintain a clean vulnerability baseline without exceptions.
