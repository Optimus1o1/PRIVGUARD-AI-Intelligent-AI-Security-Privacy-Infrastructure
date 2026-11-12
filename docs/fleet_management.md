# Enterprise AI Fleet Management & Authoritative Revocation

> **PRIVGUARD AI** — *Agent Inventory & Centralized Execution Control*  
> **Target Version**: Stage 9

---

## 1. Central Fleet Inventory

PRIVGUARD tracks all AI entities across the enterprise:
- **AI Agents**: Autonomous systems executing multi-step tasks.
- **MCP Servers**: Upstream tool providers connected via HTTP or stdio.
- **Security Gateways**: Intermediary PRIVGUARD proxy instances.
- **SDK Clients**: Integrated applications utilizing the PRIVGUARD SDK.

Each resource records:
- `resource_id`: Globally unique identifier.
- `tenant_id` & `workspace_id`: Organizational compartment.
- `status`: `ACTIVE`, `DISABLED`, `QUARANTINED`, `REVOKED`.
- `active_policy_version` & `active_policy_hash`: Currently loaded policy state.
- `drift_status`: `SYNCED`, `DRIFTED`, `DISCONNECTED`.
- `last_heartbeat_at`: Live freshness timestamp.

---

## 2. Authoritative Broker-Side Central Revocation

A critical vulnerability in distributed AI systems is relying on remote agents to honor revocation commands. If an agent is offline, compromised, or ignores fleet sync, it might continue executing sensitive actions.

### PRIVGUARD Central Revocation Guarantee
When an administrator disables or revokes an agent:
1. `FleetResource.status` is set to `REVOKED`.
2. The underlying `Agent.status` is set to `REVOKED`.
3. All active `CapabilityGrant` records for that agent are marked `is_revoked = True`.
4. Any subsequent attempt by that agent to execute tools via `ToolBroker.execute` or `MCPProxy.execute_mcp_tool` is **immediately rejected fail-closed** at the gateway, returning `HTTP 403 Forbidden`.
5. Remote agent connectivity is **not required** to enforce revocation.
