# PRIVGUARD AI — Stage 5 Architecture
## Privacy & Security Control Center (Control Plane)

**Moon Sanctum Labs** — *Decode. Build. Evolve.*  
**Lead Engineer:** ANIKET NANDI ([KOLKATA], [IST])  
**Target:** AI Developers, Autonomous-Agent Architects, Enterprise Security Engineers  
**Compliance Standard:** OWASP Top 10 for LLM Applications (2026), NIST AI RMF, CISA Agent Security Directives

---

## 1. System Overview

Stage 5 transforms PRIVGUARD AI from a headless backend enforcement engine into a full-featured, developer-first **Privacy & Security Control Center**.

The control plane is intentionally built not merely as a passive telemetry dashboard, but as an active **command and control plane**:
- **Human-in-the-Loop (HITL) Authorizations:** Reviewing held sensitive tool operations, verifying sanitized arguments, and executing single-use cryptographically bound approvals or rejections.
- **Dynamic Access Maps:** Visualizing agent-to-tool capabilities, toggling permission levels (`ALLOW`, `REQUIRE_APPROVAL`, `DENIED`), and revoking capabilities instantly.
- **Investigation Trails:** Tracing multi-step attacks (prompt injection $\to$ tool misuse $\to$ data exfiltration $\to$ quarantine) across a connected chronological timeline.
- **Privacy Policy Engine:** Creating and managing custom PII/secret redaction and blocking rules with immutable security invariants.
- **Live Diagnostics:** Measuring sub-millisecond gateway overhead and component uptime across the complete protection pipeline.

```
       +-------------------------------------------------------------+
       |                  PRIVGUARD Control Center                   |
       |                (Next.js 14 App Router / React)              |
       +-------------------------------------------------------------+
                                     |
                       HTTP / JSON (Local Session)
                                     v
       +-------------------------------------------------------------+
       |               Backend-for-Frontend (BFF) Proxy              |
       |             app/api/backend/[...path]/route.ts              |
       |   * Injects server-side PRIVGUARD_API_KEY                   |
       |   * Strips internal credentials from client response        |
       |   * Zero exposure of secrets to browser JS / localStorage   |
       +-------------------------------------------------------------+
                                     |
                         Internal Authorized Requests
                                     v
       +-------------------------------------------------------------+
       |                PRIVGUARD FastAPI Core Server                |
       |                   (http://127.0.0.1:8000)                   |
       +-------------------------------------------------------------+
        |                 |                 |                     |
        v                 v                 v                     v
  [Dashboard API]  [Threats API]    [Approvals API]       [Privacy API]
  /v1/dashboard/   /v1/threats/     /v1/approvals/        /v1/privacy/
  summary          events           pending               inspect
  threat-stats     inspect          {id}/approve          redact
  system-health    taint/{task_id}  {id}/reject           /v1/policies
```

---

## 2. Security Boundaries & Zero-Content Audit Guarantee

A core security principle of PRIVGUARD AI is **never sacrificing data privacy for administrative convenience**:

1. **Zero-Content Invariant:**
   - Raw user prompts, unmasked credentials, and full LLM response strings are **never** persisted to the SQLite database or exposed to the frontend UI.
   - All events are indexed by **SHA-256 content fingerprints**, rule IDs, entity tallies, and millisecond latency timers.
   - Payload inspection modals display verified sanitized metadata without reconstructible plaintext.

2. **Backend-for-Frontend (BFF) Key Isolation:**
   - The browser client never handles master PRIVGUARD administrative keys or upstream OpenAI/Anthropic/Gemini API keys.
   - The Next.js server route handler (`app/api/backend/[...path]/route.ts`) securely injects the `X-API-Key` server-side from environment variables.

3. **Cryptographic Binding on Approvals:**
   - Approval requests generated during Stage 3 carry an HMAC-SHA256 signature binding the `request_id`, `agent_id`, `tool_name`, `arguments_hash`, and expiration time.
   - Approvals are strictly single-use; once consumed, the token cannot be replayed or altered.

4. **Policy Enforcement Invariants:**
   - Baseline system policies (e.g. blocking prompt injections or critical secret leaks) are immutable and cannot be deleted or set to `ALLOW`.
   - Attempting to save a rule with `CRITICAL` severity and `ALLOW` action fails closed immediately.

---

## 3. UI Component Architecture & Design Language

The visual design system implements Moon Sanctum Labs' cybersecurity aesthetic:
- **Palette:** Dark graphite `#0A0B0E`, midnight card surface `#111318`, elevated borders `#1F242F`, cyber cyan `#06B6D4`, cyber emerald `#10B981`, cyber red `#F43F5E`, cyber amber `#F59E0B`, with Moon Sanctum Labs copper `#E0A45C` highlights.
- **Typography:** Space Grotesk (geometric headers, monospaced data fields) paired with Manrope for high-legibility UI text.
- **Radial Segmented Gauge (`ProtectionGauge.tsx`):**
  - Recreates the hardware-inspired semi-circular segmented arc visualization from the reference design.
  - Dynamically calculates active health score from pending critical threats, blocked attacks, and gateway latency.
- **Investigation Trail:**
  - Connected multi-phase timeline tracking Ingestion Vector $\to$ Indicators Flagged $\to$ Defensive Verdict.
- **Agent Access Map (`/agents/[id]`):**
  - Visual node topology graph representing the execution path: `Autonomous Agent -> PRIVGUARD Broker -> Permitted Tools`.

