# PRIVGUARD AI

> **Moon Sanctum Labs** — *Decode. Build. Evolve.*

PRIVGUARD AI is an independent security and privacy enforcement layer positioned between AI applications, untrusted data sources, external foundation models, and agent execution tools.

---

## Core Guarantees & Invariants

1. **Security-First & Fail-Closed:** If any inspection subsystem fails or returns an unknown category, requests are unconditionally blocked.
2. **Zero Secrets in Model Context:** API keys (OpenAI, Anthropic, AWS, GitHub, Slack), private keys, and database connection strings are intercepted and blocked before leaving the perimeter.
3. **Reversible PII Minimization:** Personal Identifiable Information (emails, phone numbers, credit cards, SSNs) is replaced with ephemeral placeholders (`<EMAIL_1>`) and de-redacted upon return.
4. **Content-Free Audit Trails:** Raw prompts, completions, and sensitive strings are never stored in audit logs. Logs store cryptographic SHA-256 fingerprints, timestamps, and entity counts.
5. **Ultra-Low Latency Overhead:** Inspection pipeline operates at under **0.25ms P95 latency** locally.

6. **Buffer-Before-Stream SSE Streaming:** Streams are buffered and reconstructed to detect credentials split across chunks before emitting SSE events to the client.
7. **Bidirectional Response Inspection:** Model outputs are treated as untrusted data and scanned for leaked secrets and prompt extraction attacks.
8. **SSRF-Proof Provider Isolation:** Client cannot specify remote upstream URLs; all endpoints resolve through server-side provider registry.
9. **Autonomous AI Threat Defense:** Deterministic prompt injection detection, untrusted content sanitization, sliding-window agent behavior monitoring, and MITRE ATT&CK T1700 exfiltration taint tracking.
10. **Secure Personal AI Memory Vault:** User-controlled personal memory protected by AES-256-GCM envelope encryption, HKDF-SHA256 derived KEKs, staged human consent proposals, and irreversible cryptographic erasure. Zero AI training usage.
11. **MCP 2026-07-28 Security Gateway:** Zero-trust enforcement layer mediating autonomous AI agents and external tools connected via the Model Context Protocol. Enforces Streamable HTTP header routing, destination SSRF validation, tool description poisoning defense, catalog drift quarantine, and sandboxed stdio isolation.

---

## Quickstart

### 1. Requirements
- Python 3.10+
- SQLite (built-in WAL mode)

### 2. Setup Environment
```bash
python -m venv .venv
.\.venv\Scripts\activate
pip install -r backend/requirements.txt
```

### 3. Run Test Suite
```bash
pytest backend/tests -v --cov=app
```

### 4. Start the Security Gateway
```bash
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

Interactive API documentation will be available at:
`http://127.0.0.1:8000/docs`

---

## Integration with OpenAI SDK

### Non-Streaming Mode
```python
from openai import OpenAI

client = OpenAI(
    base_url="http://127.0.0.1:8000/v1",
    api_key="your_privguard_api_key",
)

response = client.chat.completions.create(
    model="gpt-4o",
    messages=[
        {"role": "user", "content": "Send a memo to aniket@example.com"}
    ]
)
print(response.choices[0].message.content)
```

### Streaming Mode (Secure Buffer-Before-Stream)
```python
stream = client.chat.completions.create(
    model="gpt-4o",
    messages=[
        {"role": "user", "content": "Explain secure streaming in detail."}
    ],
    stream=True,
)

for chunk in stream:
    if chunk.choices and chunk.choices[0].delta.content:
        print(chunk.choices[0].delta.content, end="", flush=True)
```

### Agent Tool Execution with Capabilities & Approvals
```python
import httpx

# 1. Register agent & initialize task session
# 2. Obtain temporary task-scoped capability token
cap_res = httpx.post(
    "http://127.0.0.1:8000/v1/capabilities/request",
    headers={"X-API-Key": "your_privguard_api_key"},
    json={
        "agent_id": "agent_alpha",
        "task_id": "task_001",
        "tool_name": "send_email",
        "max_uses": 1,
    }
).json()
capability_token = cap_res["capability_token"]

# 3. Attempt execution (High risk -> Held as PENDING approval)
exec_res = httpx.post(
    "http://127.0.0.1:8000/v1/tools/send_email/execute",
    headers={"X-API-Key": "your_privguard_api_key"},
    json={
        "agent_id": "agent_alpha",
        "task_id": "task_001",
        "capability_token": capability_token,
        "parameters": {"recipient": "client@enterprise.com", "subject": "Update", "body": "Report ready."}
    }
)
# Returns 402 with approval_id

# 4. Human operator approves exact action via dashboard / API
# 5. Agent executes with approved ID (tamper-proof action hash verified)
```

---

### 5. Launch the Security Control Center (Frontend Dashboard)
```bash
cd frontend
npm install
npm run dev
```
The Control Center will be accessible at: `http://localhost:3000`

---

## Repository Structure

```
PRIVGUARD-AI/
├── backend/
│   ├── app/
│   │   ├── api/              # Gateway, Privacy, Policies, Audit, Agents, Tasks, Capabilities, Approvals, Tools, Threats, Dashboard, Memory, MCP
│   │   ├── agent_security/   # Identity, Task Manager, Capability Manager, Permission Engine, Tool Registry, Broker, Sandbox
│   │   ├── approvals/        # Cryptographic Action-Binding, Approval Engine, Anti-Replay
│   │   ├── memory/           # Envelope Encryption, HKDF KEK Provider, Validator, Permissions, Vault, Retrieval Service
│   │   ├── mcp/              # MCP Destination Validator (SSRF), Registry & Drift Defense, stdio Sandbox, Protected Client, Security Proxy
│   │   ├── sdk/              # Python Client SDK (PrivGuardMemoryClient, PrivGuardMCPClient)
│   │   ├── threat_detection/ # Injection Detector, Content Analyzer, Behavior Analyzer, Exfiltration Taint Tracker, Memory & Retrieval Security
│   │   ├── core/             # Config, Authentication, Security, Exceptions
│   │   ├── gateway/          # Upstream proxy, response inspector, secure streaming
│   │   ├── providers/        # Provider abstraction, OpenAI-compatible, registry
│   │   ├── privacy/          # Secret Scanner, PII Detector, Redactor, Classifier
│   │   ├── policies/         # Deterministic Policy Engine
│   │   ├── monitoring/       # Content-free Audit Logger
│   │   └── database/         # Async SQLite models, migrations, WAL mode
│   └── tests/                # 213 automated security, red-team, adversarial, load, API, memory vault, and MCP gateway tests
├── frontend/                 # Next.js 14 App Router, TypeScript, Tailwind CSS, BFF Security Proxy
│   ├── app/                  # Security Overview, Approvals, Agents, Topology Map, Threats, Privacy, Memory Vault, MCP Gateway, Tasks, Activity, Diagnostics
│   ├── components/           # Radial Segmented Protection Gauge, Metric Cards, Forecast Charts, Tables, Modals
│   └── lib/                  # Type-safe API client, types, BFF handlers
├── docs/                     # Architecture, Threat Model, AISVS Assessment, Red Team Report, Attack Scenarios, Memory Vault & MCP Gateway Specs
└── README.md
```

---

## Roadmap

- [x] **Stage 0:** Architecture, Threat Model & Specification
- [x] **Stage 1:** Backend Foundation, API Contracts, Secret Scanner, PII Redaction, Fail-Closed Pipeline
- [x] **Stage 2:** Live Upstream Model Proxying & Secure Streaming
- [x] **Stage 3:** Agent Security Broker, Capability Tokens & Human Approvals
- [x] **Stage 4:** Advanced Threat Detection (Prompt Injection, Behavioral Analysis, Exfiltration Defense)
- [x] **Stage 5:** Privacy & Security Control Center (Next.js 14 App Router, BFF Security Proxy, OWASP 2026 Telemetry)
- [x] **Stage 6:** End-to-End Integration, Red Teaming & Security Validation (OWASP AISVS 1.0, 142 Automated Tests)
- [x] **Stage 7:** Secure Personal AI Memory Vault (AES-256-GCM Envelope Encryption, Consent Proposals, Memory Poisoning Defense, Bounded Retrieval, Cryptographic Erasure, 171 Automated Tests)
- [x] **Stage 8:** MCP Security Integration (Model Context Protocol 2026-07-28 Gateway, SSRF Destination Defense, Tool Poisoning & Drift Quarantine, Sandboxed stdio Isolation, 213 Automated Tests)


