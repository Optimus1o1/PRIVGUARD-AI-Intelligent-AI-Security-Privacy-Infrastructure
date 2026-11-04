# Data Exfiltration Detection & Taint Tracking (MITRE ATT&CK T1700)

**Moon Sanctum Labs** — *Decode. Build. Evolve.*  
**Lead Engineer:** [ANIKET NANDI] ([KOLKATA], [IST])  
**Product:** PRIVGUARD AI  

---

## 1. Threat Overview: MITRE ATT&CK T1700

**Technique T1700 (AI-Enabled Data Exfiltration):**  
Adversaries use autonomous agents or compromised LLMs with network access to read confidential internal data and exfiltrate it via legitimate tools (web search, webhooks, emails, external API queries).

Traditional DLP tools fail because:
- The data is often reformatted, summarized, or paraphrased by the LLM.
- Outbound requests appear to originate from authorized business agents.

PRIVGUARD AI solves this by introducing **Dynamic Context Taint Propagation**.

---

## 2. Dynamic Taint Tracking Architecture

```
                      +-----------------------------+
                      | Agent invokes read_file     |
                      | Resource: confidential.env  |
                      +--------------+--------------+
                                     |
                                     v
                      +-----------------------------+
                      | Is resource confidential?   |
                      | YES -> Mark Task as TAINTED |
                      +--------------+--------------+
                                     |
                                     v
                      +-----------------------------+
                      | Agent invokes http_request  |
                      | Dest: evil-server.com       |
                      +--------------+--------------+
                                     |
                                     v
                      +-----------------------------+
                      | Is task tainted? YES        |
                      | Is destination allowlisted? |
                      | NO -> BLOCK EXFILTRATION    |
                      +-----------------------------+
```

---

## 3. Enforcement Invariants

1. **Automatic Taint Marking:**
   Whenever an agent invokes a read tool on resources matching confidential patterns (`confidential`, `password`, `secret`, `credentials`, `.env`, `private_key`, `salary`), the task context is flagged as tainted in memory and persisted in `active_taints`.
2. **Outbound Sink Inspection:**
   All tools categorized as outbound sinks (`send_email`, `http_request`, `post_webhook`, `upload_file`, `execute_bash`) must evaluate destination endpoints.
3. **Allowlist Policy:**
   If a task is tainted, outbound calls are permitted **only to explicitly allowlisted domains** (e.g., `api.privguard.internal`). Calls to external domains or arbitrary webhooks trigger `ThreatAction.BLOCK`.
4. **Zero-Secret Payload Guarantee:**
   Regardless of destination or taint status, all arguments destined for outbound tools are scanned for credentials and private keys using [SecretScanner](file:///C:/Users/ANIKET/OneDrive/Documents/RIVA_AI/backend/app/privacy/secret_scanner.py). Any matched secret triggers an immediate hard block.
