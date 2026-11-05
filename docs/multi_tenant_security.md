# Multi-Tenant Security & Isolation Model

> **PRIVGUARD AI** — *Enterprise Data Isolation & Governance*  
> **Target Version**: Stage 9

---

## 1. Tenancy Boundary Principle

In PRIVGUARD AI, each Organization constitutes an independent, impermeable security boundary. One organization must **never** be capable of observing, querying, modifying, or deleting resources belonging to another organization through any direct, indirect, cached, or side-channel path.

---

## 2. Dual-Layer Defense Architecture

```
User Request
     |
     v
[1. Server-Side Context Resolution]
     | Validates API Key / Session Token against OrganizationMembership
     | Rejects untrusted client X-Tenant-ID headers with 403 Forbidden
     v
[2. Application Query Layer]
     | Strict ORM scoping: WHERE tenant_id = :authenticated_tenant_id
     v
[3. PostgreSQL Database Engine Layer]
     | Transaction local: SET LOCAL app.current_tenant_id = :tenant_id
     | PostgreSQL Row-Level Security (RLS) enforcement: FORCE ROW LEVEL SECURITY
     v
[Protected Tenant Data]
```

### 2.1 Server-Side Context Resolution
- The client identity is resolved through `resolve_tenant_context` in [`backend/app/core/tenant.py`](file:///C:/Users/ANIKET/OneDrive/Documents/RIVA_AI/backend/app/core/tenant.py).
- Client-provided `tenant_id` query parameters or JSON body fields are never used for access authorization.
- If a client provides an explicit `X-Tenant-ID` header, it is checked against the authenticated user's active `OrganizationMembership`. If the user is not an active member of that tenant, the request fails with `HTTP 403 Forbidden`.

### 2.2 PostgreSQL Row-Level Security (RLS) Engine
Every tenant-owned table is configured with restrictive RLS policies generated via [`backend/app/database/rls.py`](file:///C:/Users/ANIKET/OneDrive/Documents/RIVA_AI/backend/app/database/rls.py):

```sql
ALTER TABLE agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE agents FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_agents ON agents
    AS RESTRICTIVE
    FOR ALL
    TO privguard_app
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), ''))
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), ''));
```

### 2.3 Tables Under Strict Multi-Tenant Enforcement
1. `applications`
2. `agents`
3. `agent_tasks`
4. `policy_rules`
5. `capability_grants`
6. `approval_requests`
7. `tool_execution_records`
8. `audit_events`
9. `threat_events`
10. `memory_records`
11. `memory_proposals`
12. `memory_permissions`
13. `memory_versions`
14. `memory_deletion_jobs`
15. `memory_audit_events`
16. `mcp_servers`
17. `mcp_tool_definitions`
18. `mcp_resource_definitions`
19. `mcp_audit_events`
20. `workspaces`
21. `policy_bundles`
22. `fleet_resources`
23. `integration_credentials`
24. `enterprise_audit_events`
25. `audit_export_jobs`
