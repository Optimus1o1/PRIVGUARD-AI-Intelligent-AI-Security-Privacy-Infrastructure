# PRIVGUARD AI — Agent Permissions & Least Privilege Model

**Moon Sanctum Labs** — *Decode. Build. Evolve.*

## 1. Least Privilege Authorization

PRIVGUARD AI enforces a strict **Default DENY** policy for autonomous AI agent actions.

* An agent possesses NO implicit permissions.
* The presence of an LLM completion directing the agent to take an action has **zero authority**.
* Every execution requires:
  1. An **Active Agent Record** belonging to the caller application context.
  2. The target tool explicitly listed in the agent's `allowed_tools` profile.
  3. An unexpired, unrevoked **Capability Grant** matching the exact tool, task, and resource scope.
  4. Explicit **Human Approval** if the tool is classified as high-risk.

## 2. Risk Classification Matrix

| Tool | Risk Level | Default Treatment | Scope / Constraints |
|---|---|---|---|
| `read_file` | `LOW` | `ALLOW` | Jailed strictly inside `./sandbox/`; path traversal rejected. |
| `search_web` | `LOW` | `ALLOW` | Domain-restricted search adapter. |
| `send_email` | `HIGH` | `REQUIRE_APPROVAL` | Quarantine dispatch; requires human approval bound to recipient and body. |
| `delete_file` | `HIGH` | `REQUIRE_APPROVAL` | Jailed strictly inside `./sandbox/`; requires human approval. |
| `execute_code` | `CRITICAL` | `BLOCK` | Disabled in v0.1 pending containerized gVisor isolation. |

