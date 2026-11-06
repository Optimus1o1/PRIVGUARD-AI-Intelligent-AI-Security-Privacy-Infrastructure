# PRIVGUARD AI — Secret Scanning & Management Policy

## 1. Overview

PRIVGUARD AI handles high-entropy cryptographic material, capability tokens, personal AI memory keys, and external model provider API credentials. Preventing secret leaks into source control is a foundational security control.

PRIVGUARD deploys **Gitleaks** as both:
1. A **local developer pre-commit hook** to intercept leaks before staging/committing.
2. An **automated CI workflow** (`.github/workflows/security-scan.yml`) scanning full git history and PR commits.

---

## 2. Gitleaks Configuration (`.gitleaks.toml`)

PRIVGUARD maintains a custom configuration file at the repository root ([`.gitleaks.toml`](file:///c:/Users/ANIKET/OneDrive/Documents/RIVA_AI/.gitleaks.toml)). In addition to standard high-entropy generic secret rules, it enforces domain-specific detection rules tailored to PRIVGUARD AI:

| Rule ID | Description | Match Pattern / Format |
| :--- | :--- | :--- |
| `privguard-api-key` | PRIVGUARD API Key | `pgk_(live|test)_[a-zA-Z0-9]{32,64}` |
| `privguard-capability-token` | PRIVGUARD Capability Token | `pgt_(live|test)_[a-zA-Z0-9_\-]{32,64}` |
| `openai-api-key` | OpenAI Model API Key | `sk-(proj-)?[a-zA-Z0-9_\-]{32,64}` |
| `anthropic-api-key` | Anthropic Model API Key | `sk-ant-[a-zA-Z0-9_\-]{32,64}` |
| `generic-private-key` | Unencrypted Private Keys | `BEGIN (RSA\|EC\|OPENSSH\|PGP) PRIVATE KEY` |

---

## 3. Allowlist Policy & Scope

True positives must never be whitelisted. Allowlist entries in `.gitleaks.toml` are strictly restricted to:
1. **Mock Test Fixtures**: Deterministic synthetic keys used exclusively in automated test suites (e.g. `test_*.py`).
2. **Path Exemptions**: Specific test directories where dummy strings are generated (`tests/`, `__snapshots__/`, `.venv/`, `.git/`, `.next/`).
3. **Template Environment Files**: Placeholder tokens in `.env.example`.

Any addition to the `[allowlist]` requires security review and justification under `.github/CODEOWNERS`.

---

## 4. Secret Leak Response & Revocation Runbook

If a genuine secret is detected in git history or CI output:

```
[ Step 1: Containment ]
    Immediately invalidate/rotate the compromised secret at the provider 
    (do NOT wait for commit rewriting).

[ Step 2: Audit Scope ]
    Inspect provider logs (e.g. OpenAI dashboard, AWS CloudTrail, Supabase)
    for unauthorized access during the exposure window.

[ Step 3: Git History Purge ]
    Use `git-filter-repo` or BFG Repo-Cleaner to permanently scrub the secret
    from repository history. Force push to all remote branches.

[ Step 4: Incident Post-Mortem ]
    Log incident in security audit trail, determine why pre-commit hooks were
    bypassed, and update detection rules or entropy thresholds accordingly.
```

