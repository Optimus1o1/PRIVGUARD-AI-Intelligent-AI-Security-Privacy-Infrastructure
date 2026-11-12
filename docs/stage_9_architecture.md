# Stage 9 Architecture — Enterprise Governance, Multi-Tenancy & Fleet Policy Management

> **PRIVGUARD AI** — *Independent Security & Privacy Infrastructure for Agentic AI*  
> **Agency Identity**: Moon Sanctum Labs — *Decode. Build. Evolve.*  
> **Status**: Implemented & Verified (Stage 9)

---

## 1. System Overview

Stage 9 transforms PRIVGUARD into a multi-tenant enterprise control plane. It enables multi-department enterprises to manage scores of autonomous AI agents, dozens of Model Context Protocol (MCP) tool integrations, and sensitive data streams with cryptographic policy enforcement, zero cross-tenant leakage, and centralized governance.

```
+-----------------------------------------------------------------------------------+
|                        ENTERPRISE CONTROL PLANE (NEXT.JS 14)                      |
|                                                                                   |
|  /organization        /organization/members       /organization/workspaces       |
|  /organization/fleet  /organization/policies      /organization/audit             |
+-----------------------------------------+-----------------------------------------+
                                          | Authenticated REST / SCIM
                                          v
+-----------------------------------------------------------------------------------+
|                           PRIVGUARD ENTERPRISE API CORE                           |
|                                                                                   |
|  +-----------------------+  +-----------------------+  +-----------------------+  |
|  | Enterprise SSO & SCIM |  | Central Policy Engine |  | Fleet Inventory &     |  |
|  | (OIDC / SAML2 / SCIM2)|  | (Ed25519 Signed Bund) |  | Drift Reconciliation  |  |
|  +-----------+-----------+  +-----------+-----------+  +-----------+-----------+  |
|              |                          |                          |              |
+--------------+--------------------------+--------------------------+--------------+
|                                TENANT CONTEXT BUS                                 |
|             (Server-Side Verified `tenant_id`, `workspace_id`, and `role`)         |
+--------------+--------------------------+--------------------------+--------------+
|              v                          v                          v              |
|  +-----------------------+  +-----------------------+  +-----------------------+  |
|  | Enterprise RBAC / ABAC|  | Agent Security Broker |  | Protected MCP Gateway |  |
|  | (8 Built-in Roles)    |  | (Central Revocation)  |  | (SSRF & Tool Sandbox) |  |
|  +-----------------------+  +-----------------------+  +-----------------------+  |
|                                                                                   |
|  +-----------------------------------------------------------------------------+  |
|  |                  DEFENSE-IN-DEPTH MULTI-TENANT DATA LAYER                   |  |
|  |  * Application-Level Scoping (`WHERE tenant_id = :current_tenant_id`)       |  |
|  |  * PostgreSQL Row-Level Security (`FORCE ROW LEVEL SECURITY`)              |  |
|  |  * Tamper-Evident SHA-256 Hash-Chained Audit Ledger & SIEM Telemetry        |  |
|  +-----------------------------------------------------------------------------+  |
+-----------------------------------------------------------------------------------+
```

---

## 2. Core Subsystems

### 2.1 Multi-Tenant Data Layer & RLS
- **Dual Boundary Defense**: All tenant-owned database tables include a mandatory `tenant_id` column.
- **PostgreSQL Row-Level Security (RLS)**: Policies are generated with `FORCE ROW LEVEL SECURITY` ensuring even superusers and application roles cannot execute queries outside the active `app.current_tenant_id` session setting.
- **Zero-Trust Client Inputs**: `tenant_id` in request bodies, query strings, or headers is strictly untrusted unless validated against the caller's server-side session membership.

### 2.2 Enterprise Identity & SCIM 2.0
- **SSO Provider Abstraction**: Validates OIDC / SAML 2.0 claims (issuer, audience, signature, expiration, nonce, and verified domains).
- **SCIM 2.0 Provisioning**: Implements `/v1/scim/v2/Users` with automated provisioning and immediate deprovisioning revocation.
- **Domain Verification**: Enforces cryptographically verified DNS TXT or meta-tokens before routing users via enterprise SSO.

### 2.3 Enterprise RBAC & Workspace Isolation
- **8 Built-in Roles**: `ORGANIZATION_OWNER`, `SECURITY_ADMIN`, `POLICY_ADMIN`, `FLEET_ADMIN`, `DEVELOPER`, `AGENT_OPERATOR`, `AUDITOR`, `VIEWER`.
- **Separation of Duties**: Developers cannot deploy security policies; Auditors cannot execute tools; Organization Owners cannot bypass immutable platform guardrails.
- **Departmental Workspaces**: Compartmentalizes agents, tasks, and memory vaults into isolated departmental boundaries (Engineering, Research, Security).

### 2.4 Cryptographically Signed Central Policies
- **Ed25519 Digital Signatures**: Policies are compiled into canonical JSON bundles (RFC 8785) and signed with asymmetric Ed25519 keys.
- **Deterministic 5-Layer Hierarchy**: `Platform Guardrails > Org Baseline > Workspace > App > Agent`.
- **Anti-Downgrade & Anti-Replay**: Reject lower policy versions and maintain immutable version lineage with instant, audited rollbacks.

### 2.5 Fleet Management & Centralized Revocation
- **Authoritative Broker Revocation**: Disabling an agent or revoking capabilities at the central control plane immediately causes the security broker to drop subsequent operations fail-closed.
- **Drift Detection**: Compares reported agent policy hashes against target bundle digests; detects and isolates disconnected or drifted resources.

### 2.6 Tamper-Evident SIEM Audit Ledger
- **SHA-256 Hash Chain**: Every audit event links to the previous event hash: `event_hash = SHA256(prev_hash + canonical_event)`. Any unauthorized alteration breaks verification.
- **Asynchronous SIEM Exporter**: Securely delivers audit telemetry to external SIEM collectors with SSRF destination validation.
