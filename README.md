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

Point your OpenAI client base URL to PRIVGUARD Gateway:

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

---

## Repository Structure

```
PRIVGUARD-AI/
├── backend/
│   ├── app/
│   │   ├── api/            # Gateway, Privacy, Policies, and Audit endpoints
│   │   ├── core/           # Config, Authentication, Security, Exceptions
│   │   ├── privacy/        # Secret Scanner, PII Detector, Redactor, Classifier
│   │   ├── policies/       # Deterministic Policy Engine
│   │   ├── monitoring/     # Content-free Audit Logger
│   │   └── database/       # Async SQLite models and connection
│   └── tests/              # 30 automated security and unit tests
├── docs/                   # Architecture, Threat Model, API Reference
└── README.md
```

---

## Roadmap

- [x] **Stage 0:** Architecture, Threat Model & Specification
- [x] **Stage 1:** Backend Foundation, API Contracts, Secret Scanner, PII Redaction, Fail-Closed Pipeline
- [ ] **Stage 2:** Live Upstream Model Proxying & Streaming
- [ ] **Stage 3:** Agent Security Broker, Capability Tokens & Human Approvals
- [ ] **Stage 4:** Next.js Security Dashboard & Real-Time Monitoring
