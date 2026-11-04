# PRIVGUARD AI — Control Center User Guide
## Developer & Operator Manual for the Security Control Plane

**Moon Sanctum Labs** — *Decode. Build. Evolve.*  
**Lead Engineer:** ANIKET NANDI ([KOLKATA], [IST])  
**Target:** AI Engineers, SecOps Analysts, Security Incident Responders

---

## 1. Quick Start

### Prerequisites
- Python 3.12+ virtual environment (`.venv`)
- Node.js 18+ & npm
- PRIVGUARD Core Gateway running locally on port 8000

### Launching the Stack

**Step 1: Start the Backend Gateway**
```powershell
.\.venv\Scripts\Activate.ps1
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

**Step 2: Start the Control Center Frontend**
```powershell
cd frontend
npm run dev
```
Open your browser at [http://localhost:3000](http://localhost:3000).

---

## 2. Navigating the Control Plane

The Control Center interface is divided into seven core modules:

```
[Overview]           -> Real-time security score, threat trend forecast, quick feeds
[Threat Timeline]    -> Multi-step investigation trails, OWASP 2026 detection ledger, sandbox
[Privacy Center]     -> PII redaction playground, secrets interception, custom policy engine
[Agent Access Map]   -> Visual tool topology graph, permission toggles, capability revocation
[Approval Center]    -> Human-in-the-loop queue, cryptographic authorization, expiration countdown
[Task Sessions]      -> Active agent tasks, execution taint flags, capability abort switches
[System Health]      -> Sub-millisecond component latency probes, operational uptime ledger
```

---

## 3. Module Operations & Best Practices

### A. Security Overview (`/`)
- **Protection Score Gauge:** Recreates a hardware-style radial segmented gauge reflecting current system resilience. Automatically decreases if critical unhandled threats exist or if health probes degrade.
- **Threat Trend Chart:** Visualizes real-time request volume against threat interceptions over the last 7 days.
- **Quick Approvals Banner:** Alerts the operator immediately if autonomous agents are currently blocked awaiting human permission.

### B. Human Approval Center (`/approvals`)
- When an autonomous agent attempts a tool action tagged as `REQUIRE_APPROVAL` (or high-risk tools like shell execution or database modification), execution halts.
- **Verification:** Operators can inspect the target tool, calling agent, and sanitized argument parameters.
- **Countdown Timer:** Requests carry an automated expiration window (default 300s). Expired requests are closed automatically to prevent stale executions.
- **Cryptographic Binding:** Clicking "Approve" or "Reject" verifies an HMAC-SHA256 signature binding the exact arguments. The capability is single-use and cannot be replayed.

### C. Agent Directory & Visual Access Map (`/agents`, `/agents/[id]`)
- **Visual Node Topology:** Shows the direct execution link from the AI Agent $\to$ PRIVGUARD Broker $\to$ Authorized Tools.
- **Permission Toggles:** Operators can dynamically reconfigure permissions for individual tools:
  - `ALLOW`: Autonomous execution allowed within rate and policy limits.
  - `REQUIRE APPROVAL`: Always pauses execution for human authorization.
  - `DENIED`: Tool execution is immediately rejected.
- **Revoke All Capabilities:** Immediately invalidates active credentials and halts all running tasks for that agent.

### D. Threat Detection & Investigation Trail (`/threats`)
- **Investigation Trail (Timeline View):** Traces multi-stage attacks across:
  - *Phase 1 (Vector):* Ingress source and SHA-256 fingerprint.
  - *Phase 2 (Indicators):* Flagged prompt injection patterns, exfiltration markers, or anomaly scores.
  - *Phase 3 (Verdict):* Action taken (`BLOCKED`, `QUARANTINED`, `FLAGGED`).
- **Live Threat Sandbox:** Operators can type or paste arbitrary prompt snippets or tool outputs to simulate real-time behavioral and injection scans without saving data to disk.

### E. Privacy Center & Policy Engine (`/privacy`)
- **Interactive Playground:** Paste real text containing emails, credit cards, or API secrets. PRIVGUARD demonstrates reversible token substitution (e.g. `[EMAIL_1]`) safe for external LLM transmission.
- **Custom Rule Authoring:** Create granular rules with custom categories, actions (`REDACT`, `BLOCK`, `REQUIRE_APPROVAL`), and severities. Baseline security rules remain immutable.

### F. Activity Ledger (`/activity`)
- **Zero-Content Invariant:** Every record displays strictly timestamps, event types, rule triggers, entity counts, execution latencies, and SHA-256 hashes.
- **Exporting:** Download the complete sanitized audit log as structured JSON for compliance verification.

### G. System Diagnostics (`/system-health`)
- Live component status and microsecond latencies for AI Gateway, Privacy Engine, Agent Broker, Threat Detector, and SQLite WAL database.
- Distinguishes operational uptime from security effectiveness.
