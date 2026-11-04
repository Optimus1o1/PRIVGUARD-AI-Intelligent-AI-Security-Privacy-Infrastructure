# PRIVGUARD AI — Tamper-Proof Human Approval Workflow

**Moon Sanctum Labs** — *Decode. Build. Evolve.*

## 1. The Need for Action-Binding

In conventional agent architectures, an agent requests "permission to send an email". Once approved, the agent might send an email to a completely different recipient with sensitive data.

PRIVGUARD solves this with **Cryptographic Action-Binding**:
$$\text{action\_hash} = \text{SHA256}(\text{canonical\_json}(\text{tool\_name}, \text{target\_resource}, \text{parameters}))$$

## 2. Approval Lifecycle

```
[Agent attempts tool execution]
          |
    (Tool requires approval)
          v
[ApprovalRequest created (Status: PENDING)]
          |
          v
[Operator inspects pending requests: GET /v1/approvals/pending]
          |
    +-----+-----+
    |           |
 (Approve)   (Reject)
    |           |
    v           v
[APPROVED]   [REJECTED]
    |           |
    |        (Permanently blocked)
    v
[Agent re-submits execution with approval_id]
    |
    +--> Verify action_hash == SHA256(current_parameters)
    |       |
    |    (Hash matches exactly)
    v       v
[Status -> CONSUMED]
    |
    v
[Tool executed in Sandbox]
```

## 3. Guarantees

* **Tamper Prevention:** Any modification of tool parameters between approval and execution triggers `APPROVAL_TAMPERING_DETECTED` (403).
* **Anti-Replay Protection:** Once transitioned to `CONSUMED`, an approval cannot be reused; subsequent calls trigger `APPROVAL_ALREADY_CONSUMED` (403).
* **Time Expiration:** Approvals expire after a configurable TTL (default 300s). Expired approvals cannot be executed.
