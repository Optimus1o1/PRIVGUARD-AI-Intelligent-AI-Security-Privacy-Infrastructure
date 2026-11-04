# PRIVGUARD AI — Stage 5 Frontend Security & Threat Model
## Control Plane Trust Boundaries & Defense-in-Depth

**Moon Sanctum Labs** — *Decode. Build. Evolve.*  
**Lead Engineer:** ANIKET NANDI ([KOLKATA], [IST])  
**Target:** Security Architects, SecOps Engineers, Web Application Auditors

---

## 1. Threat Model of the Control Plane

Modern developer dashboards for AI and security gateways present high-value targets for attackers:
- An attacker with access to the dashboard could attempt to approve malicious agent actions, disable prompt injection filters, exfiltrate sensitive audit records, or steal upstream LLM provider credentials.
- In untrusted browser environments, client-side memory, local storage, browser extensions, and developer tools can be inspected or manipulated.

To mitigate these threats, PRIVGUARD AI enforces strict **defense-in-depth principles** for Stage 5:

```
[Untrusted Client Browser]
        |
        |  (1) Browser JS has ZERO access to master API keys or secrets
        |  (2) Only requests relative path: /api/backend/*
        v
[Next.js Backend-for-Frontend (BFF) Layer]
        |
        |  (3) Injects PRIVGUARD_API_KEY strictly in server memory
        |  (4) Sanitizes client response headers
        v
[FastAPI Core Security Gateway]
        |
        |  (5) Enforces authoritative authorization & HMAC token verification
        |  (6) Rejects any client-side tampering or invariant violation
        v
[SQLite WAL / Zero-Content Ledger]
```

---

## 2. Key Security Guarantees

### A. Zero Credential Exposure (BFF Architecture)
- **No Client Keys:** Upstream provider API keys (OpenAI, Anthropic, Gemini) and the master administrative key (`PRIVGUARD_API_KEY`) are **never** bundled in frontend JavaScript, transmitted to the client, or stored in `localStorage` or `sessionStorage`.
- **Server-Side Reverse Proxy:** All dashboard API calls route through Next.js server route handler (`app/api/backend/[...path]/route.ts`). The Next.js Node.js server authenticates against the internal FastAPI port (`http://127.0.0.1:8000`) using server-side environment variables.
- **Leakage Prevention:** Any upstream error messages or headers that could leak backend file paths or internal tokens are sanitized before reaching the browser.

### B. Single-Use Cryptographically Bound Approvals
- The Human Approval Center (`/approvals`) does not rely on simple database flags.
- Every approval request requires the `action_hash` generated during Stage 3:
  $$\text{HMAC-SHA256}(\text{app\_secret}, \text{task\_id} \mathbin{\Vert} \text{tool\_name} \mathbin{\Vert} \text{args\_hash} \mathbin{\Vert} \text{expires\_at})$$
- Approvals are strictly single-use (`status: CONSUMED`). Replaying an approved request is rejected by the backend.
- Expiration countdowns are enforced by the server; an expired capability cannot be approved even if forced via client manipulation.

### C. Policy Invariant Enforcement
- Baseline system policies (prompt injection defense, critical secret blocking) are marked immutable.
- The UI prevents users from setting `CRITICAL` severity policies to `ALLOW`.
- Even if a malicious actor bypasses client validation (e.g. via cURL or Postman), the FastAPI backend validates the invariant and returns:
  `400 Bad Request: Invariant Violation: Critical security policies cannot be set to ALLOW.`

### D. Zero-Content Audit Guarantee in the UI
- Audit log tables and inspection modals render SHA-256 fingerprints, rule identifiers, entity count tallies, and latency numbers.
- Raw text and unmasked secrets are never rendered in persistent audit feeds.

---

## 3. Recommended Production Hardening

For production multi-user deployments:
1. **Network Binding:** Bind the internal FastAPI server to `127.0.0.1` or a private VPC network, preventing external entities from querying FastAPI directly.
2. **Reverse Proxy TLS:** Terminate TLS using modern ciphers (TLS 1.3) with HTTP Strict Transport Security (HSTS) headers.
3. **Session Authentication:** Wrap the Next.js BFF proxy with corporate IdP authentication (SSO / OIDC via Clerk, Auth0, or NextAuth) to restrict access to authorized security administrators.
