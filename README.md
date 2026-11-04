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

---

## Repository Structure

```
PRIVGUARD-AI/
├── backend/
│   ├── app/
│   │   ├── api/            # Gateway, Privacy, Policies, and Audit endpoints
│   │   ├── core/           # Config, Authentication, Security, Exceptions
│   │   ├── gateway/        # Upstream proxy, response inspector, secure streaming
│   │   ├── providers/      # Provider abstraction, OpenAI-compatible, registry
│   │   ├── privacy/        # Secret Scanner, PII Detector, Redactor, Classifier
│   │   ├── policies/       # Deterministic Policy Engine
│   │   ├── monitoring/     # Content-free Audit Logger
│   │   └── database/       # Async SQLite models and connection
│   └── tests/              # 48 automated security, upstream, and unit tests
├── docs/                   # Architecture, Threat Model, API Reference, Stage 2
└── README.md
```

---

## Roadmap

- [x] **Stage 0:** Architecture, Threat Model & Specification
- [x] **Stage 1:** Backend Foundation, API Contracts, Secret Scanner, PII Redaction, Fail-Closed Pipeline
- [x] **Stage 2:** Live Upstream Model Proxying & Secure Streaming
- [ ] **Stage 3:** Agent Security Broker, Capability Tokens & Human Approvals
- [ ] **Stage 4:** Advanced Threat Detection (Prompt Injection Signals)
- [ ] **Stage 5:** Next.js Security Dashboard & Real-Time Monitoring

