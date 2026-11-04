# PRIVGUARD AI — System Architecture (v0.1)

**Moon Sanctum Labs** — *Decode. Build. Evolve.*

## 1. High-Level Overview

PRIVGUARD AI serves as an independent security and privacy enforcement layer positioned between AI applications, untrusted data sources, external foundation models, and agent execution tools.

```
USER / DEVELOPER
      |
 AI APPLICATION / AGENT
      |
 PRIVGUARD SDK / OpenAI-Compatible Interface
      v
+-------------------------------------------------------+
| PRIVGUARD GATEWAY (app/api/gateway.py)                |
| - Application Authentication (app/core/auth.py)       |
| - Request Inspection Pipeline                         |
| - Fail-Closed Security Perimeter                      |
+---------------------------+---------------------------+
                            |
           +----------------+----------------+
           |                                 |
           v                                 v
+----------------------+           +--------------------+
| PRIVACY ENGINE       |           | THREAT DETECTOR    |
| - Secret Scanner     |           | - Prompt Injection |
| - PII Detector       |           | - Risk Analysis    |
| - Reversible Redactor|           | - Anomaly Signals  |
+----------+-----------+           +---------+----------+
           |                                 |
           +----------------+----------------+
                            |
                            v
+-------------------------------------------------------+
| POLICY ENGINE (app/policies/engine.py)                |
| - Deterministic Rules: ALLOW | REDACT | BLOCK         |
+---------------------------+---------------------------+
                            |
           +----------------+----------------+
           |                                 |
           v                                 v
+----------------------+           +--------------------+
| MODEL GATEWAY        |           | AGENT BROKER       |
| - OpenAI Proxy       |           | - Tool Validation  |
| - Minimized Context  |           | - Task Grants      |
| - De-redaction Return|           | - Human Approval   |
+----------+-----------+           +---------+----------+
           |                                 |
           v                                 v
  EXTERNAL / LOCAL LLM              AUTHORIZED TOOLS
           |                                 |
           +----------------+----------------+
                            |
                            v
+-------------------------------------------------------+
| CONTENT-FREE AUDIT & MONITORING                       |
| - Zero prompt/response storage                        |
| - Cryptographic metadata & entity hashes              |
+-------------------------------------------------------+
```

## 2. Security Boundaries & Invariants

1. **Two Core Security Boundaries:**
   - **Boundary A: Model Ingress/Egress Gateway.** Sanitizes context before upstream delivery; blocks credentials from entering model context.
   - **Boundary B: Agent Broker Tool Execution.** Mediates every tool execution through task-scoped capability tokens. Prompt injection defense is secondary to Broker authorization.
2. **Fail-Closed Default:** Unrecognized data categories or subsystem failures trigger immediate execution denial.
3. **Zero Content Retention:** Audit logs store entity categories, action codes, risk levels, and SHA-256 content fingerprints. Raw prompts and completions are never written to disk.
