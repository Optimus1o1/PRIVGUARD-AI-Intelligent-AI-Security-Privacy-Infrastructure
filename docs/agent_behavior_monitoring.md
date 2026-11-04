# Agent Behavior Monitoring & Runaway Loop Defense

**Moon Sanctum Labs** — *Decode. Build. Evolve.*  
**Lead Engineer:** [ANIKET NANDI] ([KOLKATA], [IST])  
**Product:** PRIVGUARD AI  

---

## 1. The Challenge of Autonomous Agent Behavior

Autonomous agents operate through iterative perception-action loops. While individual tool calls (such as reading a file or making an HTTP request) may appear benign in isolation, **sequences of tool calls can constitute severe security incidents**:
- Multi-step exfiltration chains (reading confidential documents, then transmitting over HTTP).
- Infinite recursive execution loops due to faulty LLM outputs.
- Brute-force tool probing and capability exhaustion attacks.

---

## 2. Sliding-Window Architecture

PRIVGUARD maintains an in-memory chronological event window per task:
- **Window Size:** Default 20 events.
- **Event Metadata:** `(agent_id, task_id, tool_name, target_resource, status, timestamp, parameters_fingerprint)`.
- **Zero Raw Payloads:** Parameter fingerprints are SHA-256 digests.

```
Task Execution Stream:
[Event 1] -> [Event 2] -> [Event 3] -> ... -> [Event N]
  |
  v
Sliding Window Evaluator (Last 20 Events):
  - Check 1: Total call count <= 50 (Runaway limit)
  - Check 2: Repetition check (Recent 3 calls identical?)
  - Check 3: Multi-step chain (Sensitive read -> Outbound sink)
  - Check 4: Error thrashing (>= 4 failures in window)
```

---

## 3. Behavioral Anomaly Signatures

### 3.1 Multi-Step Exfiltration Chain
- **Signature:** Any tool from `SENSITIVE_READ_TOOLS` (`read_file`, `query_database`, `get_secret`) accessing a confidential resource, followed within the window by any tool from `OUTBOUND_SINK_TOOLS` (`send_email`, `http_request`, `post_webhook`).
- **Action:** `ThreatAction.BLOCK` (`CRITICAL` severity).

### 3.2 Recursive Looping
- **Signature:** 3 consecutive tool calls invoking the identical tool with identical parameter fingerprints.
- **Action:** `ThreatAction.REQUIRE_APPROVAL` (`HIGH` severity).

### 3.3 Error & Denial Thrashing
- **Signature:** $\ge 4$ failed or denied tool executions within the sliding window. Indicates brute-force fuzzing or privilege escalation attempts.
- **Action:** `ThreatAction.REQUIRE_APPROVAL` (`HIGH` severity).

### 3.4 Hard Execution Bounds
- **Signature:** Total tool calls for a task exceeding `max_tool_calls_per_task` (default 50).
- **Action:** `ThreatAction.TERMINATE_TASK` (`CRITICAL` severity) — cancels the task in the database and invalidates all associated capabilities.
