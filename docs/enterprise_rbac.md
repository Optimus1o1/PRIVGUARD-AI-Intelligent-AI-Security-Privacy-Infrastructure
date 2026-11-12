# Enterprise Role-Based & Attribute-Based Access Control (RBAC/ABAC)

> **PRIVGUARD AI** — *Enterprise Authorization Matrix & Governance*  
> **Target Version**: Stage 9

---

## 1. The 8 Built-in Roles

PRIVGUARD defines eight enterprise roles providing least-privilege access:

| Role | Responsibilities | Key Permissions |
| :--- | :--- | :--- |
| **ORGANIZATION_OWNER** | Full administrative control, billing, SSO configuration, emergency lockout. | `*` (All organization-scoped permissions) |
| **SECURITY_ADMIN** | Threat triage, incident containment, audit review, security exceptions. | `threat:read`, `threat:respond`, `fleet:revoke`, `audit:read`, `audit:export` |
| **POLICY_ADMIN** | Author, validate, cryptographically sign, and deploy security policies. | `policy:draft`, `policy:validate`, `policy:approve`, `policy:deploy`, `policy:read` |
| **FLEET_ADMIN** | Inventory management, agent and MCP server registration, drift monitoring. | `fleet:register`, `fleet:revoke`, `fleet:sync`, `fleet:read` |
| **DEVELOPER** | Register applications, configure tasks, execute sandbox tools. | `agent:run`, `tool:execute`, `policy:read`, `fleet:read` |
| **AGENT_OPERATOR** | Monitor active agent runs, decide on pending human-in-the-loop approvals. | `agent:run`, `approval:decide`, `fleet:read` |
| **AUDITOR** | Read-only compliance inspection of hash-chained audit trails and reports. | `audit:read`, `audit:export`, `threat:read`, `policy:read` |
| **VIEWER** | Read-only dashboard visibility without administrative or operational authority. | `org:read`, `workspace:read`, `policy:read`, `fleet:read` |

---

## 2. Separation of Duties Invariants

1. **Developers Cannot Deploy Policies**: A developer cannot unilaterally approve or deploy policies that govern their own applications.
2. **Auditors Cannot Execute Tools**: Auditors have strict read-only access to audit ledgers and telemetry.
3. **Viewers Cannot Mutate State**: Viewers cannot create resources, invite users, or execute tools.
4. **Bounded Administrator Authority**: Even an `ORGANIZATION_OWNER` or `SECURITY_ADMIN` cannot disable or weaken immutable platform guardrails.

---

## 3. Attribute-Based Access Control (ABAC) & Workspaces

In addition to role checks, resource access evaluates contextual attributes:
- **Workspace Scoping**: Agents registered in `Workspace A` cannot access tools or memories in `Workspace B` unless explicitly authorized.
- **Resource Sensitivity**: Access to memories tagged `RESTRICTED` or tools categorized `CRITICAL` requires explicit elevated capability grants.
