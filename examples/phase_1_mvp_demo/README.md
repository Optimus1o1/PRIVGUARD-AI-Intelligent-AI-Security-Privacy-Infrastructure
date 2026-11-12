# PRIVGUARD AI — Phase 1 MVP Integrated Demonstration

**Moon Sanctum Labs** — *Decode. Build. Evolve.*  
**Lead Developer**: ANIKET NANDI (Kolkata, IST)

---

## Overview

This demonstration validates the **five core Phase 1 MVP capabilities** of PRIVGUARD AI operating together in a single unified workflow:

1. **Sensitive Data Detection & Redaction**: PII tokens are reversibly replaced (`<EMAIL_1>`, `<PHONE_NUMBER_1>`) before model transmission; critical credentials (`sk-proj-...`) are immediately blocked pre-flight.
2. **Prompt Injection Detection**: Direct and indirect prompt injection attempts (`Ignore all previous instructions...`) are detected, quarantined, and recorded as threat events.
3. **Tool Permission Enforcement**: Server-side tool execution via `ToolBroker`. Sandboxed tools (`calculator`) execute only with valid, task-scoped capability tokens. Unpermitted tools (`search_mock_kb`) are rejected server-side independent of the LLM.
4. **Content-Free AI Activity Logs**: Structured, privacy-preserving audit logs record decisions, timestamps, risk classifications, and entity counts with zero raw prompt or secret leakage.
5. **User-Defined Security Policies**: Policy simulation (`/v1/policies/evaluate`) tests decisions without execution, and custom rules can be dynamically registered and enforced.

---

## Directory Layout

```text
examples/phase_1_mvp_demo/
├── README.md               # This guide
├── run_demo.py             # Single-command demonstration runner
└── mock_model_server.py    # Request-capturing mock model server for upstream verification
```

---

## Running the Demonstration

### Option A: Standalone In-Process (Fastest, Zero Infrastructure Needed)

Run the demonstration script directly in the project virtual environment. It initializes an in-memory SQLite database, mounts the full FastAPI application with middleware, and exercises the 5 core capabilities end-to-end:

```bash
python examples/phase_1_mvp_demo/run_demo.py
```

### Option B: Against Local PRIVGUARD Instance (Docker or Uvicorn)

1. Start the PRIVGUARD backend:
   ```bash
   uvicorn app.main:app --host 127.0.0.1 --port 8000
   ```
2. In a separate terminal, launch the mock upstream model server:
   ```bash
   python examples/phase_1_mvp_demo/mock_model_server.py --port 11435
   ```
3. Run the demonstration runner:
   ```bash
   python examples/phase_1_mvp_demo/run_demo.py
   ```

---

## Demonstration Scenarios Covered

| # | Scenario | Method / Endpoint | Expected Outcome |
|---|---|---|---|
| 1 | Normal AI Query | `POST /v1/privacy/inspect` | Permitted (`ALLOW`, category `PUBLIC`, risk `LOW`). |
| 2A | PII Redaction | `POST /v1/privacy/redact` | Email & phone replaced with token placeholders; reversible mapping preserved. |
| 2B | Secret Interception | `POST /v1/privacy/inspect` | OpenAI API key blocked (`BLOCK`, category `CRITICAL`, risk `CRITICAL`). |
| 3 | Prompt Injection Defense | `POST /v1/threats/inspect` | Jailbreak detected (`QUARANTINE`, threat `DIRECT_PROMPT_INJECTION`). |
| 4A | Authorized Tool Call | `POST /v1/tools/calculator/execute` | Sandboxed arithmetic executed (`25 * 4 = 100`) via valid capability token. |
| 4B | Unauthorized Tool Call | `POST /v1/tools/search_mock_kb/execute` | Tool call rejected with `HTTP 403` (capability not granted). |
| 5A | Policy Simulation | `POST /v1/policies/evaluate` | Evaluated pre-flight without calling upstream model or executing tools. |
| 5B | Policy Lifecycle | `POST /v1/policies` | Custom policy rule created and stored in database. |
| 6 | Privacy-Safe Audit Logs | `GET /v1/audit/events` | Audit trail verified: metadata present, zero raw secrets or emails. |

---

## Verifying Upstream Model Protection

To confirm that the upstream model never receives raw PII or secrets:
1. Run `python examples/phase_1_mvp_demo/mock_model_server.py --port 11435`.
2. Inspect `GET http://localhost:11435/captured-requests` after sending requests through PRIVGUARD's gateway (`POST /v1/chat/completions`).
3. Captured requests will contain tokenized strings (`<EMAIL_1>`) and zero raw credential strings.

