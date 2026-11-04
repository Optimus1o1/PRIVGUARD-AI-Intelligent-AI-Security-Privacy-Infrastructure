# Stage 4 Architecture: Advanced AI Threat Detection & Defense

**Moon Sanctum Labs** — *Decode. Build. Evolve.*  
**Lead Engineer:** [ANIKET NANDI] ([KOLKATA], [IST])  
**Product:** PRIVGUARD AI — Runtime Defense and Security Enforcement  

---

## 1. System Overview

Stage 4 extends PRIVGUARD AI from access control into continuous real-time threat intelligence and agent behavior defense. It specifically counters emerging threats codified in the **OWASP 2026 LLM Top 10** (LLM01 Prompt Injection, LLM03 Data Poisoning, LLM05 Supply Chain/Context Poisoning, LLM07 Sensitive Disclosure, LLM08 Excessive Agency) and **MITRE ATT&CK T1700** (AI-Enabled Data Exfiltration).

```
                    +------------------------------------+
                    |  Inbound Request / Agent Tool Call  |
                    +-----------------+------------------+
                                      |
                                      v
                    +------------------------------------+
                    |         PRIVGUARD GATEWAY          |
                    +-----------------+------------------+
                                      |
        +-----------------------------+-----------------------------+
        |                             |                             |
        v                             v                             v
+---------------+             +---------------+             +---------------+
| PROMPT        |             | CONTENT       |             | BEHAVIOR      |
| INJECTION     |             | PROVENANCE    |             | SLIDING       |
| DETECTOR      |             | ENVELOPES     |             | WINDOW        |
+-------+-------+             +-------+-------+             +-------+-------+
        |                             |                             |
        |                             v                             |
        |                     +---------------+                     |
        |                     | TAINT         |                     |
        |                     | TRACKER       |                     |
        |                     | (MITRE T1700) |                     |
        |                     +-------+-------+                     |
        |                             |                             |
        +-----------------------------+-----------------------------+
                                      |
                                      v
                    +------------------------------------+
                    |    THREAT RESPONSE COORDINATOR     |
                    | (Signal Correlation & Audit Trail) |
                    +-----------------+------------------+
                                      |
                     Decision / Action Dispatch
                                      |
        +-----------------------------+-----------------------------+
        |                             |                             |
        v                             v                             v
   [ALLOW/FLAG]               [QUARANTINE/BLOCK]          [TERMINATE/REVOKE]
   Safe Execution             Context Wrapped /           Task Cancelled /
   & Telemetry                Policy Exception            Capabilities Killed
```

---

## 2. Core Architectural Components

### 2.1 Prompt Injection Detector ([injection_detector.py](file:///C:/Users/ANIKET/OneDrive/Documents/RIVA_AI/backend/app/threat_detection/injection_detector.py))
- **Normalization:** Unicode NFKC normalization, invisible character stripping (`\u200b`, `\u200c`, `\ufeff`), and bidirectional character elimination (`\u202a`–`\u202e`).
- **Heuristic & Signature Engine:** Deterministic regex scans across instruction override, system extraction, jailbreak personas, and delimiter hijacking.
- **Base64 Payload Unpacking:** Automatically identifies, decodes, and recursively scans embedded base64 content.
- **Canary Tokens:** Generates random, high-entropy tokens inserted into system prompts; intercepts upstream model responses if canary tokens are leaked.

### 2.2 Content Analyzer & Provenance ([content_analyzer.py](file:///C:/Users/ANIKET/OneDrive/Documents/RIVA_AI/backend/app/threat_detection/content_analyzer.py))
- **Provenance Envelopes:** Wraps all inbound data into `ContentEnvelope` objects carrying `SourceType` and `TrustLevel` (`TRUSTED`, `UNTRUSTED`, `QUARANTINED`).
- **Active Sanitization:** Neutralizes `<script>` tags, inline JavaScript handlers (`onload`, `onerror`), and hidden CSS blocks (`display: none;`).
- **Quarantine Boundaries:** Injects defensive context tags to ensure downstream LLMs treat quarantined data strictly as inert text.

### 2.3 Agent Behavior Analyzer ([behavior_analyzer.py](file:///C:/Users/ANIKET/OneDrive/Documents/RIVA_AI/backend/app/threat_detection/behavior_analyzer.py))
- **Sliding-Window Buffer:** Tracks the last $N=20$ tool events per active task.
- **Exfiltration Chain Detection:** Flags patterns where a sensitive read tool precedes an outbound sink within the window.
- **Recursive Loop Interception:** Detects 3 or more consecutive identical calls.
- **Error Thrashing Defense:** Flags probing when $\ge 4$ failures or denials occur in the window.
- **Resource Limits:** Enforces hard caps on tool executions per task (default 50 calls).

### 2.4 Exfiltration Detector & Taint Tracking ([exfiltration_detector.py](file:///C:/Users/ANIKET/OneDrive/Documents/RIVA_AI/backend/app/threat_detection/exfiltration_detector.py))
- **Taint Propagation:** Reading confidential resources automatically marks the active task context as tainted.
- **Outbound Sink Mediation:** Outbound tools (`send_email`, `http_request`, `post_webhook`) check destination allowlists; non-allowlisted outbound transfers by tainted tasks are blocked.
- **Payload Secret Scanning:** Enforces zero secret leakage in tool arguments.

### 2.5 Guarded Memory & Retrieval Security
- **Memory Analyzer ([memory_analyzer.py](file:///C:/Users/ANIKET/OneDrive/Documents/RIVA_AI/backend/app/threat_detection/memory_analyzer.py)):** Intercepts instruction smuggling into long-term memory.
- **Retrieval Validator ([retrieval_security.py](file:///C:/Users/ANIKET/OneDrive/Documents/RIVA_AI/backend/app/threat_detection/retrieval_security.py)):** Validates RAG chunk tenant boundaries and verifies cryptographic SHA-256 integrity.

---

## 3. Separation of Concerns: Detection vs. Enforcement

A fundamental invariant of PRIVGUARD AI is that **detection modules never directly execute business logic or bypass authorization gates**:
- Detectors emit `ThreatAssessment` structures containing confidence-weighted `ThreatSignal` items.
- The [PolicyEngine](file:///C:/Users/ANIKET/OneDrive/Documents/RIVA_AI/backend/app/policies/engine.py) and [ToolBroker](file:///C:/Users/ANIKET/OneDrive/Documents/RIVA_AI/backend/app/agent_security/tool_broker.py) consume these assessments and enforce appropriate controls (`ALLOW`, `FLAG`, `QUARANTINE`, `BLOCK`, `TERMINATE_TASK`).
- Even if an adversarial prompt evades injection rules, least-privilege tool allowlists and capability token verifications still enforce authorization.
