# PRIVGUARD AI — Threat Model & Security Controls

**Moon Sanctum Labs** — *Decode. Build. Evolve.*

## Threat Matrix

| Security Threat | PRIVGUARD Component | Initial Protection Mechanism |
|---|---|---|
| **Sensitive Data Leakage** | Privacy Protection Engine | Multi-regex & NLP PII detection; deterministic token substitution (`<EMAIL_1>`, `<PHONE_1>`). |
| **Credential & Key Exposure** | Secret Scanner | High-entropy regex and pattern scanners for API keys (OpenAI, Anthropic, AWS, GitHub, Slack), private keys, and DB credentials; hard fail-closed block. |
| **Prompt Injection & Hijacking** | Threat Analyzer & Agent Broker | Capability grants isolate execution; LLM cannot self-authorize tool calls; injection detected via heuristic signals. |
| **Excessive Agent Permissions** | Agent Broker | Least privilege; task-specific capabilities with strict timeout and invocation limits. |
| **Data Exfiltration via Tools** | Agent Broker | Outbound tools (email, HTTP post) require explicit human approval by default. |
| **Insecure Audit Logging** | Audit Logger | Zero-content storage invariant: logs only contain metadata, category counts, and SHA-256 fingerprints. |

## Defense-in-Depth Principle

No machine learning classifier can guarantee 100% detection of adversarial prompt injection. Therefore:
1. Threat detection provides early warning.
2. The **Agent Broker** and **Capability-Based Access Control** provide the true enforcement boundary. Even if an agent follows an injected instruction, the underlying operation fails closed without an active, signed capability grant.
