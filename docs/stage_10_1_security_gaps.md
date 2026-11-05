# PRIVGUARD AI — Stage 10.1: Security Gaps & Hardening Remediation Plan

**Moon Sanctum Labs** — *Decode. Build. Evolve.*  
**Author**: [ANIKET NANDI] ([KOLKATA], [IST])  
**Baseline Git Commit**: `a1f6ae8`  
**Date**: November 2026  

---

## 1. Executive Summary

Stages 1 through 9 built an advanced defense-in-depth security architecture. However, during the production readiness audit, **eight security and hardening deficits** were identified that must be remediated prior to public or enterprise production deployment.

This document analyzes each vulnerability, details its exploitability and impact, and provides a **prioritized remediation plan** mapped across the remaining Stage 10 milestones.

---

## 2. In-Depth Security Deficit Analysis

### Deficit 1: Permissive CORS Configuration
- **Location**: [`backend/app/main.py`](file:///C:/Users/ANIKET/OneDrive/Documents/RIVA_AI/backend/app/main.py#L40-L46)
- **Vulnerability**:
  ```python
  app.add_middleware(
      CORSMiddleware,
      allow_origins=["*"],
      allow_credentials=True,
      allow_methods=["*"],
      allow_headers=["*"],
  )
  ```
- **Risk Analysis**: In modern browsers, combining `allow_origins=["*"]` with `allow_credentials=True` violates the Fetch and CORS specifications, causing browser rejection or creating cross-origin data exposure vectors if misconfigured proxies reflect arbitrary `Origin` headers.
- **Remediation**:
  - Replace wildcard origins with an environment-configured whitelist (`ALLOWED_ORIGINS: List[str]`).
  - Restrict allowed methods and headers to only what the frontend dashboard and API clients require.

### Deficit 2: Master Development Key Fallback in Authentication Handler
- **Location**: [`backend/app/core/authentication.py`](file:///C:/Users/ANIKET/OneDrive/Documents/RIVA_AI/backend/app/core/authentication.py#L30-L38)
- **Vulnerability**:
  ```python
  if settings.DEBUG and api_key == settings.PRIVGUARD_MASTER_KEY:
      return Application(
          id="app_master_admin",
          name="Master Admin App (Dev)",
          api_key_hash=hash_api_key(api_key),
          is_active=True,
      )
  ```
- **Risk Analysis**: If a production deployment accidentally leaves `DEBUG=true` in its environment, any attacker who presents the default `PRIVGUARD_MASTER_KEY` immediately acquires an active, unauthenticated root admin context, bypassing all tenant boundaries and database checks.
- **Remediation**:
  - Remove transient root admin bypass entirely.
  - Require all API keys, including administrative tokens, to exist in the database with explicit tenant and RBAC role assignments.
  - Enforce fail-closed crash during startup if `DEBUG=True` and `ENVIRONMENT == "production"`.

### Deficit 3: Incomplete Next.js BFF Proxy Allowlist
- **Location**: [`frontend/app/api/backend/[...path]/route.ts`](file:///C:/Users/ANIKET/OneDrive/Documents/RIVA_AI/frontend/app/api/backend/[...path]/route.ts#L6-L19)
- **Vulnerability**:
  ```typescript
  const ALLOWED_ROUTE_PREFIXES = new Set([
    "dashboard", "threats", "agents", "tasks", "capabilities",
    "approvals", "audit", "privacy", "chat", "tools", "memory", "mcp"
  ]);
  ```
- **Risk Analysis**: The BFF route handler omits `"organizations"` and `"scim"` from its allowed prefixes. Any browser request attempting to fetch enterprise workspaces, fleet status, or policies via `/api/backend/organizations/...` is rejected with HTTP 403 `ROUTE_NOT_PERMITTED`.
- **Remediation**: Add `"organizations"` and `"scim"` to `ALLOWED_ROUTE_PREFIXES`.

### Deficit 4: Master Key Validation & Rotation Procedures
- **Location**: [`backend/app/core/config.py`](file:///C:/Users/ANIKET/OneDrive/Documents/RIVA_AI/backend/app/core/config.py#L18)
- **Vulnerability**: `PRIVGUARD_MASTER_KEY` defaults to `"change-me-in-production-min-32-chars-long-secret"` without validation.
- **Risk Analysis**: Inexperienced operators deploying PRIVGUARD may fail to override this variable, allowing attackers to forge HMAC API key hashes and decrypt database integration credentials.
- **Remediation**:
  - Add Pydantic validator on `Settings` that raises a fatal `ValueError` if `ENVIRONMENT == "production"` and the key matches default or has $< 32$ bytes entropy.
  - Implement automated master key rotation procedures in Stage 10.5.

### Deficit 5: Process Confinement for Stdio MCP Subprocesses
- **Location**: [`backend/app/mcp/stdio_sandbox.py`](file:///C:/Users/ANIKET/OneDrive/Documents/RIVA_AI/backend/app/mcp/stdio_sandbox.py)
- **Vulnerability**: While the sandbox strips environment variables and verifies command names against an allowlist, the subprocess executes inside the same container/OS environment as the FastAPI gateway process.
- **Risk Analysis**: In a multi-tenant environment, a compromised stdio tool could attempt to exhaust host CPU/RAM or probe `/proc` file systems.
- **Remediation**:
  - In containerized deployments, execute stdio tools within dedicated ephemeral sidecar containers with explicit cgroup resource limits and read-only root filesystems, or mandate `streamable_http` transports for untrusted servers.

### Deficit 6: Missing Distributed Rate Limiting & Account Lockout
- **Location**: Gateway endpoints (`/v1/chat/completions`, `/v1/auth`, `/v1/mcp`)
- **Vulnerability**: Rate limiting and capability checks are currently performed in-memory or via SQL queries without IP-based brute-force tracking.
- **Risk Analysis**: Attackers could launch distributed credential stuffing attacks against API key endpoints or flood the LLM gateway, exhausting upstream API quotas and causing denial of service.
- **Remediation**: Implement a Redis-backed Sliding Window or Token Bucket rate limiter in Stage 10.3 with automated IP bans for repeated 401/403 responses.

### Deficit 7: Frontend Dependencies Vulnerabilities (GHSA Advisories)
- **Location**: `frontend/package.json`
- **Vulnerability**:
  - `next`: Current `14.2.35` subject to critical security advisories (DoS in Server Components/Image Optimization, Server Actions SSRF).
  - `postcss`: Current `<=8.5.2` subject to high security advisories (XSS via unescaped `</style>`, arbitrary file read in source maps).
- **Remediation**: Update dependencies in `frontend/` to patched releases during Stage 10.2 / 10.7.

### Deficit 8: OpenTelemetry & Structured Telemetry Security
- **Location**: System Logging
- **Vulnerability**: Logging currently writes unstructured text to standard output without trace IDs or sanitization markers.
- **Risk Analysis**: Log injection attacks could forge log entries. Lack of correlation IDs impedes incident response during active attacks.
- **Remediation**: Implement structured JSON logging with cryptographically random `trace_id` and strict redaction filters in Stage 10.6.

---

## 3. Prioritized Remediation Roadmap

```
+-----------------------------------------------------------------------------------+
|                        STAGE 10 REMEDIATION TIMELINE                              |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  [Stage 10.2] CONTAINERIZATION & COMPOSE PACKAGING (Immediate)                    |
|   ├── Multi-stage non-root Dockerfiles for backend and frontend                   |
|   ├── CORS configuration hardening (replace wildcard with explicit whitelist)     |
|   ├── Remove DEBUG root admin authentication backdoor                             |
|   ├── Add "organizations" and "scim" to Next.js BFF proxy allowlist               |
|   └── Pydantic production master key entropy validator                            |
|                                                                                   |
|  [Stage 10.3] POSTGRESQL HA, ALEMBIC & DISTRIBUTED REDIS STATE                    |
|   ├── Initialize Alembic async migration suite for 25 tables                      |
|   ├── Integrate Redis 7.x for distributed rate limiting and token buckets         |
|   ├── Redis Pub/Sub for fleet policy sync and authoritative revocation            |
|   └── Verify PostgreSQL RLS under distributed connection pooling                  |
|                                                                                   |
|  [Stage 10.4] KUBERNETES & HELM DEPLOYMENT PACKAGING                              |
|   ├── Production Helm chart with configurable values.yaml                         |
|   ├── Horizontal Pod Autoscalers (HPA) and NetworkPolicies                        |
|   └── Ephemeral sidecar container runner for stdio MCP tools                      |
|                                                                                   |
|  [Stage 10.5] SECRETS & ENCRYPTION KEY MANAGEMENT                                 |
|   ├── HashiCorp Vault / Cloud KMS envelope encryption provider                    |
|   └── Automated Master Key rotation procedure                                     |
|                                                                                   |
|  [Stage 10.6] OBSERVABILITY, LOGGING & METRICS                                    |
|   ├── Structured JSON logging with trace_id / correlation headers                 |
|   ├── Prometheus /metrics endpoint (latency, RPS, error rates, threat blocks)     |
|   └── OpenTelemetry distributed tracing spans                                     |
|                                                                                   |
|  [Stage 10.7] SUPPLY-CHAIN SECURITY & AUTOMATED CI/CD                             |
|   ├── GitHub Actions CI pipeline (lint, typecheck, test, coverage)                |
|   ├── Upgrade frontend Next.js and PostCSS packages to patch GHSA advisories      |
|   └── Container image vulnerability scanning (Trivy) and Cosign signing           |
|                                                                                   |
|  [Stage 10.8] COMPLIANCE READINESS & EVIDENCE ENGINE                              |
|   ├── SOC 2 Type II, ISO/IEC 42001, and HIPAA automated audit evidence            |
|   └── Continuous compliance reporting dashboard                                   |
|                                                                                   |
|  [Stage 10.9] PYTHON SDK PACKAGING & DISTRIBUTION                                 |
|   ├── Standalone `privguard` client package with pyproject.toml                   |
|   └── Async & synchronous client bindings with connection pooling                 |
|                                                                                   |
|  [Stage 10.10] DISASTER RECOVERY & PRODUCTION VALIDATION                          |
|   ├── Automated backup and Point-In-Time Recovery (PITR) procedures               |
|   └── Full chaos engineering & disaster recovery rehearsal                       |
+-----------------------------------------------------------------------------------+
```

---

## 4. Conclusion

All eight security deficits are actionable and have direct, scoped engineering solutions assigned to subsequent Stage 10 substages. With Stage 10.1 complete, PRIVGUARD AI is prepared to execute **Stage 10.2: Docker Containerization and Production Compose**.
