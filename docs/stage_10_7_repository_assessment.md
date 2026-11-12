# PRIVGUARD AI — Stage 10.7 Repository Discovery & Security Assessment
## Supply Chain, Dependencies, Build Environments & CI/CD Readiness

Organization: **Moon Sanctum Labs**  
Slogan: **Decode. Build. Evolve.**  
System: **PRIVGUARD AI — Independent Security & Privacy Enforcement Layer for Agentic AI**  
Author: Lead Full-Stack Developer & Designer ([ANIKET NANDI], Kolkata, IST)  
Baseline Git Commit: **`ab1660d`**  
Date: November 2026  

---

## 1. Executive Summary & Assessment Scope

Before introducing supply chain security controls, GitHub Actions workflows, or automated release pipelines, a thorough discovery of the repository was conducted. This assessment establishes the empirical baseline for:
- Programming languages, runtime versions, and package managers.
- Existing test runners and execution profiles.
- Container image architectures and multi-stage build topologies.
- Rigorous dependency vulnerability assessments (Python and Node.js ecosystems).
- Advisory-by-advisory vulnerability analysis and controlled security upgrades.
- Secret management and environment variable handling.
- Gap analysis against SLSA (Supply-chain Levels for Software Artifacts) v1.0 and NIST SP 800-218 (SSDF).

---

## 2. Environment & Dependency Inventory

### 2.1 Backend (Python Ecosystem)
- **Language / Runtime**: Python `3.12.10` (development), target Docker runtime `python:3.12-slim-bookworm`.
- **Package Manager**: `pip` (v25.0.1) using `backend/requirements.txt`.
- **Testing Framework**: `pytest` (v9.2.0), `pytest-asyncio` (v1.4.1.post1), `pytest-cov` (v7.1.0).
- **Core Frameworks**:
  - `fastapi` (`0.110.0+`), `uvicorn[standard]` (`0.28.0+`), `pydantic` (`2.6.0+`), `pydantic-settings` (`2.2.0+`).
  - `sqlalchemy` (`2.0.28+`), `asyncpg` (`0.29.0+`), `alembic` (`1.13.0+`), `redis` (`5.0.0+`).
  - `cryptography` (`42.0.0+`), `opentelemetry-api` / `sdk` (`1.24.0+`), `prometheus-client` (`0.20.0+`).
- **Dependency Vulnerability Assessment (`pip-audit`)**:
  - Executed: `pip-audit -r backend/requirements.txt`
  - Result: **0 known vulnerabilities found**. Clean bill of health across all direct and transitive requirements.

### 2.2 Frontend (Node.js & React Ecosystem)
- **Language / Runtime**: Node.js `v24.14.1` (development), target Docker runtime `node:20-alpine`.
- **Package Manager**: `npm` (v11.11.0) with strict `package-lock.json` present.
- **Core Frameworks**:
  - Next.js: upgraded from legacy `14.2.24` to patched `15.5.29`.
  - React `18.3.1`, Tailwind CSS `3.4.17`, PostCSS `8.5.32` (overridden), Lucide React `0.475.0`, Recharts `2.15.1`.

---

## 3. Advisory-by-Advisory Analysis & Security Upgrades

Rather than prematurely accepting vulnerabilities via policy exceptions or jumping to a breaking Next.js 16 major upgrade, an advisory-by-advisory investigation was executed:

| Advisory / CVE ID | Package & Version Range | Severity | Vulnerability Description | Patched Version | Remediated in PRIVGUARD? |
| :--- | :--- | :--- | :--- | :--- | :---: |
| **GHSA-9g9p-9gw9-jx7f** | `next >=10.0.0 <15.5.10` | Moderate | Image Optimizer remotePatterns DoS | `>=15.5.10` | **Yes (`next@15.5.29`)** |
| **GHSA-h25m-26qc-wcjf** | `next >=13.0.0 <15.0.8` | High | Insecure React Server Components Deserialization DoS | `>=15.0.8` | **Yes (`next@15.5.29`)** |
| **GHSA-ggv3-7p47-pfv8** | `next >=9.5.0 <15.5.13` | Moderate | HTTP request smuggling in rewrites | `>=15.5.13` | **Yes (`next@15.5.29`)** |
| **GHSA-3x4c-7xq6-9pq8** | `next >=10.0.0 <15.5.14` | Moderate | Unbounded next/image disk cache growth | `>=15.5.14` | **Yes (`next@15.5.29`)** |
| **GHSA-q4gf-8mx6-v5v3** | `next >=13.0.0 <15.5.15` | High | Denial of Service with Server Components | `>=15.5.15` | **Yes (`next@15.5.29`)** |
| **GHSA-8h8q-6873-q5fj** | `next >=13.0.0 <15.5.16` | High | Denial of Service with Server Components | `>=15.5.16` | **Yes (`next@15.5.29`)** |
| **GHSA-3g8h-86w9-wvmq** | `next >=12.2.0 <15.5.16` | Low | Middleware / Proxy redirect cache poisoning | `>=15.5.16` | **Yes (`next@15.5.29`)** |
| **GHSA-ffhc-5mcf-pf4q** | `next >=13.4.0 <15.5.16` | Moderate | XSS in App Router using CSP nonces | `>=15.5.16` | **Yes (`next@15.5.29`)** |
| **GHSA-vfv6-92ff-j949** | `next >=13.4.6 <15.5.16` | Low | Cache poisoning via collisions in RSC cache-busting | `>=15.5.16` | **Yes (`next@15.5.29`)** |
| **GHSA-gx5p-jg67-6x7h** | `next >=13.0.0 <15.5.16` | Moderate | XSS in beforeInteractive scripts with untrusted input | `>=15.5.16` | **Yes (`next@15.5.29`)** |
| **GHSA-h64f-5h5j-jqjh** | `next >=10.0.0 <15.5.16` | Moderate | Denial of Service in Image Optimization API | `>=15.5.16` | **Yes (`next@15.5.29`)** |
| **GHSA-c4j6-fc7j-m34r** | `next >=13.4.13 <15.5.16` | High | SSRF in applications using WebSocket upgrades | `>=15.5.16` | **Yes (`next@15.5.29`)** |
| **GHSA-wfc6-r584-vfw7** | `next >=14.2.0 <15.5.16` | Moderate | Cache poisoning in React Server Component responses | `>=15.5.16` | **Yes (`next@15.5.29`)** |
| **GHSA-36qx-fr4f-26g5** | `next >=12.2.0 <15.5.16` | High | Middleware / Proxy bypass in Pages Router i18n | `>=15.5.16` | **Yes (`next@15.5.29`)** |
| **GHSA-m99w-x7hq-7vfj** | `next >=13.0.0 <15.5.21` | High | Denial of Service in App Router using Server Actions | `>=15.5.21` | **Yes (`next@15.5.29`)** |
| **GHSA-89xv-2m56-2m9x** | `next >=14.1.1 <15.5.21` | High | SSRF in Server Actions on custom servers | `>=15.5.21` | **Yes (`next@15.5.29`)** |
| **GHSA-68g3-v927-f742** | `next >=13.0.0 <15.5.21` | Moderate | Cache confusion of response bodies for requests with bodies | `>=15.5.21` | **Yes (`next@15.5.29`)** |
| **GHSA-4633-3j49-mh5q** | `next >=13.0.0 <15.5.21` | Moderate | Cache confusion of response bodies with invalid UTF-8 | `>=15.5.21` | **Yes (`next@15.5.29`)** |
| **GHSA-4c39-4ccg-62r3** | `next >=13.0.0 <15.5.21` | Moderate | Unbounded Server Action payload in Edge runtime | `>=15.5.21` | **Yes (`next@15.5.29`)** |
| **GHSA-p9j2-gv94-2wf4** | `next >=12.0.0 <15.5.21` | High | SSRF in rewrites via attacker-controlled hostname | `>=15.5.21` | **Yes (`next@15.5.29`)** |
| **GHSA-955p-x3mx-jcvp** | `next >=13.0.0 <15.5.21` | Moderate | Unauthenticated disclosure of internal Server Functions | `>=15.5.21` | **Yes (`next@15.5.29`)** |
| **GHSA-p293-qw3h-jr36** | `next >=13.4.0 <15.5.24` | Critical | Unauthenticated Remote Code Execution on Windows | `>=15.5.24` | **Yes (`next@15.5.29`)** |
| **GHSA-2xp9-vwfh-vxw4** | `next >=10.0.0 <15.5.24` | Critical | Unauthenticated RCE in Image Optimization API (AVIF) | `>=15.5.24` | **Yes (`next@15.5.29`)** |
| **GHSA-2464-fhr4-w9xw** | `next >=10.0.0 <=15.5.27` | Critical | Unauthenticated RCE in Image Optimization API (SVG) | `>15.5.27` | **Yes (`next@15.5.29`)** |
| **GHSA-p3m5-59mp-jv5r** | `next >=13.0.0 <=15.5.27` | High | Denial of Service in App Router using Server Actions | `>15.5.27` | **Yes (`next@15.5.29`)** |
| **GHSA-qx2v-qp2m-jg93** | `postcss <=8.5.22` | Moderate | PostCSS XSS via Unescaped `</style>` in CSS Stringify | `8.5.32` | **Yes (`postcss@8.5.32`)** |
| **GHSA-6g55-p6wh-862q** | `postcss <=8.5.22` | High | Arbitrary file read via attacker sourceMappingURL | `8.5.32` | **Yes (`postcss@8.5.32`)** |
| **GHSA-fxqj-rqcc-2cmp** | `postcss <=8.5.22` | High | Incomplete fix: sourceMappingURL arbitrary map read | `8.5.32` | **Yes (`postcss@8.5.32`)** |
| **GHSA-r28c-9q8g-f849** | `postcss <=8.5.22` | High | Path Traversal in Previous Source Map Auto-Loading | `8.5.32` | **Yes (`postcss@8.5.32`)** |

### 3.1 Outcome of Controlled Security Upgrade
By upgrading to `next@15.5.29` with `postcss@8.5.32` (via package overrides):
- **npm audit outcome**: `found 0 vulnerabilities` across all 147 audited packages.
- **Standalone architecture**: 100% preserved.
- **Production Build**: Successfully compiled all 31 static and dynamic routes.
- **Zero Security Exceptions Needed**: All identified vulnerabilities were eliminated via vendor security patches.

---

## 4. Defense-in-Depth Principle

As affirmed by Moon Sanctum Labs engineering policy:
> **Network isolation, reverse proxy filters, and request size boundaries serve as essential defense-in-depth, but NEVER as substitutes for available vendor security patches.**

The runtime protections (Caddy TLS reverse proxy, 10 MB body limits, non-root `nextjs:1001` container user, and private Docker network segmentation) remain actively configured to provide defense-in-depth against zero-day threats, while framework patches remediate known CVEs at the source code level.

---

## 5. Existing CI/CD & Governance Readiness

| Component | Status | Target Implementation |
| :--- | :--- | :--- |
| **Pull Request CI** | Not Present | `.github/workflows/ci.yml` (pinned action SHAs, least privilege) |
| **Security Scanning CI** | Not Present | `.github/workflows/security-scan.yml` (Gitleaks, Trivy SARIF) |
| **Release Pipeline** | Not Present | `.github/workflows/release.yml` (SLSA provenance, Cosign signing) |
| **Release Verifier** | Not Present | `scripts/security/verify_release.py` (fail-closed evidence checker) |
| **SBOM Generation** | Verified Locally | `scripts/security/generate_sboms.py` (CycloneDX 1.6) |
| **Governance Files** | Missing | `CODEOWNERS`, `SECURITY.md`, `CONTRIBUTING.md` |
