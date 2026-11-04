# Stage 2 Architecture: Upstream LLM Proxy & Secure Streaming

**Moon Sanctum Labs** — *Decode. Build. Evolve.*

## 1. Architectural Overview

Stage 2 transforms PRIVGUARD AI from an isolated inspection gatekeeper into a full bidirectional security proxy for foundation models.

```
Client App (OpenAI SDK)
          |
          v
PRIVGUARD Gateway (/v1/chat/completions)
          |
    [Ingress Pipeline]
    - Secret Scanner (Hard Block)
    - PII Detector (<EMAIL_1>, <PHONE_1>)
    - Policy Engine Evaluator
          |
          v
Upstream Provider Coordinator (app/gateway/upstream.py)
          |
    [Server-Side Provider Registry] (SSRF Boundary)
    - Validates target model
    - Resolves server-managed credentials
          |
          v
External / Local Model Provider (OpenAI, Ollama, vLLM)
          |
    +-----+-----+
    |           |
 (Non-Stream) (Stream)
    |           |
    v           v
Complete     Buffer-Before-Stream SSE Reconstructor
Response        |
    |           v
    +---> Response Security Inspector (app/gateway/response_inspector.py)
          - Scans model output for leaked secrets (OpenAI, AWS, DB URLs, Private Keys)
          - Restores request-scoped PII placeholders (<EMAIL_1> -> user@example.com)
          - Blocks response if model leaked credentials (HTTP 502)
                |
                v
          Audit Logger (Content-Free Metadata)
                |
                v
          Client Application (JSON or SSE stream)
```

## 2. Key Components

### A. Provider Registry (`app/providers/registry.py`)
- **SSRF Defense:** Rejects client attempts to specify arbitrary external URLs.
- **Provider Resolution:** Resolves model names to server-side configured upstream providers (`OpenAICompatibleProvider`, `LocalMockProvider`).
- **Credential Protection:** Upstream provider API keys are held strictly in server configuration and never exposed to the client or written to audit logs.

### B. Secure Streaming Handler (`app/gateway/streaming.py`)
- **Buffer-Before-Stream Invariant:**
  - Standard passthrough streaming is vulnerable to token-splitting attacks: a model can emit `sk-` in chunk 1, `proj-` in chunk 2, and secrets in chunk 3.
  - PRIVGUARD buffers the upstream SSE events, reconstructs the message, executes full response security inspection, restores PII placeholders, and only then emits OpenAI-compatible SSE events (`data: {...}`, `finish_reason: "stop"`, `data: [DONE]`).
  - If a secret is detected, the stream is aborted with a `ResponseSecurityViolationError` before a single byte reaches the client.

### C. Response Security Inspector (`app/gateway/response_inspector.py`)
- Scans model outputs for high-entropy secrets and credentials.
- Replaces request-scoped placeholders (`<EMAIL_1>`) with the original values for the authorized client.
- Computes SHA-256 fingerprint of the response for the content-free audit trail.
