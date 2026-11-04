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
  **Request:** Standard OpenAI payload (`model`, `messages`, `temperature`, `max_tokens`, `stream: bool`).
  **Behavior:**
  - **Prompt Inspection:** Blocks with HTTP 403 `CRITICAL_SECRET_DETECTED` if credentials are in messages.
  - **PII Minimization:** Redacts PII (emails, phone numbers, SSNs, credit cards) into tokens (`<EMAIL_1>`).
  - **Live Upstream Routing:** Forwards sanitized messages to server-configured model provider.
  - **Response Security Inspection:** Inspects model output before transmission. If model leaks credentials, blocks with HTTP 502 `RESPONSE_SECURITY_VIOLATION`.
  - **PII Restoration:** Restores authorized placeholders (`<EMAIL_1>`) for authorized clients.
  - **Streaming Mode (`stream: true`):**
    - Enforces Buffer-Before-Stream: Buffers upstream SSE events, inspects entire response, and emits compliant OpenAI SSE chunks (`data: {...}`, `finish_reason: "stop"`, `data: [DONE]`).
    - Media Type: `text/event-stream`.
  - **Non-Streaming Mode (`stream: false`):**
    - Returns JSON `ChatCompletionResponse` with `privguard_meta` (audit ID, tokens restored, latency).

**Error Responses:**
- `400 Bad Request`: `MODEL_NOT_CONFIGURED` (SSRF prevention)
- `401 Unauthorized`: `AUTHENTICATION_FAILED` (missing or invalid client key)
- `403 Forbidden`: `CRITICAL_SECRET_DETECTED` (secret in input prompt)
- `429 Too Many Requests`: `UPSTREAM_RATE_LIMITED`
- `502 Bad Gateway`: `RESPONSE_SECURITY_VIOLATION` (model generated secrets) or `UPSTREAM_PROVIDER_ERROR`
- `504 Gateway Timeout`: `UPSTREAM_TIMEOUT` (upstream provider exceeded timeout)

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

