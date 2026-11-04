# PRIVGUARD AI — API Reference (v0.1)

**Moon Sanctum Labs** — *Decode. Build. Evolve.*

## Base URL
Default local endpoint: `http://127.0.0.1:8000`

## Authentication
All protected endpoints require an Application API key supplied in one of two formats:
- Header: `X-API-Key: <YOUR_API_KEY>`
- Header: `Authorization: Bearer <YOUR_API_KEY>`

---

## Endpoints

### 1. Health & Liveness
- `GET /health`
  Returns service health and version.
- `GET /ready`
  Returns operational status and fail-closed flags.

### 2. OpenAI-Compatible Chat Gateway
- `POST /v1/chat/completions`
  Drop-in replacement for OpenAI `/v1/chat/completions`.
  **Request:** Standard OpenAI payload (`model`, `messages`, `temperature`, `max_tokens`).
  **Behavior:**
  - Blocks with HTTP 403 `CRITICAL_SECRET_DETECTED` if API keys or credentials are in messages.
  - Redacts PII (emails, phone numbers, SSNs, credit cards) into tokens (`<EMAIL_1>`).
  - Forwards sanitized payload to upstream model or returns mock completion in local test mode.
  - Restores de-redacted tokens in response content before returning to authorized client.
  - Appends `privguard_meta` with latency and audit correlation ID.

### 3. Privacy Inspection
- `POST /v1/privacy/inspect`
  Inspects raw text for sensitive credentials and PII.
  **Response:**
  ```json
  {
    "category": "PERSONAL",
    "risk_level": "MEDIUM",
    "action": "REDACT",
    "is_blocked": false,
    "blocking_reason": null,
    "detected_secrets": [],
    "detected_pii": [{"type": "EMAIL", "start": 18, "end": 36}],
    "entity_counts": {"EMAIL": 1},
    "content_fingerprint": "a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447"
  }
  ```

- `POST /v1/privacy/redact`
  Redacts text directly and returns pseudonymization mapping.

### 4. Policies
- `GET /v1/policies`
  Lists active baseline and custom application rules.
- `POST /v1/policies/evaluate`
  Simulates policy engine evaluation for a given entity set.

### 5. Audit & Monitoring
- `GET /v1/audit/events`
  Retrieves content-free audit trail events.
  **Query Parameters:** `event_type`, `limit` (1-200), `offset`.
