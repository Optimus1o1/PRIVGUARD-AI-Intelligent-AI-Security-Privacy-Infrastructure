# PRIVGUARD AI — Startup Buildathon India 2026 Submission Document

**Product Name:** PRIVGUARD AI  
**Brand:** Moon Sanctum Labs — *Decode. Build. Evolve.*  
**Founder:** [ANIKET NANDI] (Kolkata, West Bengal, India | IST)  
**Track:** AI / Enterprise Security / Developer Infrastructure  
**Baseline Stage:** Phase 1 MVP Completed & Deployment-Qualified  

---

## 1. Executive Summary & One-Line Description

> **"The Independent Security Layer for AI Applications — Secure every prompt. Govern every tool. Protect every interaction."**

**PRIVGUARD AI** is a high-performance, local-first AI security gateway that enforces strict privacy policies, adversarial threat interception, cryptographic tool permissions, and content-free audit trails between client applications, large language models (LLMs), and external execution environments. PRIVGUARD solves the fundamental architectural flaw of modern generative AI: **trusting an LLM to police itself**.

---

## 2. Problem Statement: The AI Security & Privacy Crisis

As modern applications transition from static code to generative AI and autonomous agentic workflows, software teams face unprecedented security vulnerabilities:

1. **Unchecked Data Ingress & Privacy Leakage:** End users and internal employees routinely transmit Personal Identifiable Information (PII), proprietary source code, and customer records into public and private LLMs. Redaction logic is typically fragmented, ad-hoc, or non-existent.
2. **Adversarial Exploitation (Prompt Injection & Jailbreaks):** Malicious actors craft direct instruction overrides, jailbreaks, and indirect prompt injections (e.g., in fetched web pages or user documents) designed to hijack model decision-making and extract internal instructions.
3. **Unrestricted & Ungoverned Tool Execution:** Autonomous agents are granted access to databases, command-line shells, email clients, and external APIs. When an agent is compromised by prompt injection, it can execute destructive tools without independent authorization.
4. **Compliance & Audit Vacuum:** Storing raw LLM prompts in application logs creates severe GDPR, HIPAA, and DPDP compliance violations. Conversely, failing to log interactions leaves security teams blind during post-incident forensics.
5. **The Fallacy of Model Self-Governance:** Relying on system prompts or model fine-tuning to enforce boundaries is fundamentally unsafe. An LLM cannot serve as its own security kernel.

---

## 3. Proposed Solution: Independent Enforcement Boundary

PRIVGUARD introduces an out-of-band, deterministic security enforcement layer situated directly on the network boundary between the AI application and the LLM/tool ecosystem:

```
┌─────────────────────────────────┐
│       AI Application            │
│  (Chat, Copilot, Agentic Mesh)  │
└────────────────┬────────────────┘
                 │ 1. Request (Prompt / Task)
                 ▼
┌────────────────────────────────────────────────────────┐
│             PRIVGUARD AI SECURITY GATEWAY              │
│                                                        │
│  [Ingress Defense]                                     │
│   ├── Secret & Credential Scanner (Entropy + Patterns) │
│   ├── Deterministic & Semantic Prompt Injection Filter │
│   └── Presidio/Regex PII Detection & Tokenizer         │
│                                                        │
│  [Policy Evaluation & Access Control]                  │
│   ├── User-Configurable Policy Rules (ALLOW/REDACT/BLOCK│
│   └── Cryptographic Single-Use Capability Broker (HMAC)│
│                                                        │
│  [Egress Defense & Audit]                              │
│   ├── Model Leakage / Secret Reflection Inspection     │
│   ├── Reversible Placeholder De-Tokenization           │
│   └── Content-Free Keyed HMAC Audit Logger             │
└───────────────┬────────────────────────┬───────────────┘
                │                        │
       2. Sanitized Prompt      3. Authorized Tool Call
                │                        │
                ▼                        ▼
┌────────────────────────────────┐ ┌────────────────────┐
│      Model Provider            │ │  Sandboxed Tools   │
│ (Ollama / Gemini / Cloud LLMs) │ │(Executors / APIs)  │
└────────────────────────────────┘ └────────────────────┘
```

By decoupling security policy from the generative model, PRIVGUARD guarantees **deterministic, fail-closed protection** regardless of model hallucinations, jailbreak novelties, or autonomous tool loops.

---

## 4. Current MVP Capabilities (Phase 1 Completed)

PRIVGUARD's Phase 1 MVP is fully implemented, qualified, and verified:

| Capability | Technical Mechanism | Verified Outcome |
|---|---|---|
| **Sensitive Data Protection** | Multi-entity PII detection (emails, phones, credentials) with reversible tokenization (`<EMAIL_1>`). | Raw PII is 100% absent across the socket boundary to the model; restored only for authorized clients. |
| **Prompt Injection Defense** | Multi-layer heuristic and signature scanner (`INJ_OVERRIDE_001`, jailbreak patterns, base64 decoding). | Intercepts adversarial overrides fail-closed with HTTP `403 POLICY_VIOLATION` before LLM context is loaded. |
| **Tool Authorization** | Server-side `ToolBroker` enforcing task-scoped, single-use, HMAC-signed cryptographic capability tokens. | Prevents unauthorized, out-of-sequence, or replay tool invocations by compromised agents. |
| **Content-Free Activity Logs** | Keyed HMAC-SHA256 content fingerprints and metadata-only telemetry (`audit_events`, `threat_events`). | Forensic accountability without storing raw sensitive prompts, preventing database snapshot leaks. |
| **Security Policy Engine** | User-defined, tier-based policies with real-time dry-run simulation and evaluation. | Developers configure customizable privacy actions (ALLOW, REDACT, BLOCK) per data category. |

---

## 5. Technical Architecture & Technology Stack

- **Backend Gateway:** Python 3.12, FastAPI, Uvicorn, AsyncIO.
- **Data & State Management:** SQLAlchemy Async, SQLite (WAL mode for zero-dependency local deployments) / PostgreSQL (enterprise deployments).
- **Security & Cryptography:** Python Cryptography primitives, HMAC-SHA256, Fernet tokenization, deterministic constant-time verification.
- **Frontend Console & BFF:** Next.js 15 (App Router), React 19, TypeScript, Tailwind CSS, Lucide Icons.
- **Model Interoperability:** OpenAI-compatible proxy interface supporting local LLMs (Ollama `llama3.2:3b`), self-hosted vLLM, and cloud foundation models.
- **Client SDK:** Native Python SDK (`privguard`) with synchronous and asynchronous gateway clients.

---

## 6. Product Differentiation

| Feature / Dimension | Standard LLM Wrapper | General Cloud WAF | PRIVGUARD AI |
|---|---|---|---|
| **Inspection Boundary** | Inside LLM prompt context | HTTP network layer only | Ingress + Egress AI Application Layer |
| **Enforcement Nature** | Probabilistic (Model decides) | IP/Rate-limit focused | Deterministic & Fail-Closed |
| **PII Handling** | Raw PII sent to third-party | No PII tokenization | Automated Reversible Tokenization |
| **Agent Tool Security** | Hardcoded client permissions | None | Cryptographic Task-Scoped Capability Tokens |
| **Deployment Model** | Cloud-dependent SaaS | Cloud Appliance | Local-First (Local Zero-Egress or Pre-Egress Cloud Redaction) |
| **Audit Privacy** | Full text stored in logs | Header/IP logs only | Keyed HMAC Content-Free Forensic Audit |

---

## 7. Target Market & Customer Beachhead

### Initial Beachhead Market (Ideal Customer Profile)
- **AI SaaS Startups & LLM Engineers:** Startups building agentic platforms, document AI, or customer copilots that handle sensitive user data and need SOC2 / DPDP compliance on day one.
- **Healthcare & Legal Tech AI Builders:** Developers constrained by strict confidentiality who cannot send raw patient or client data into external AI APIs.

### Total Addressable Market (TAM) Context
- The global **AI Trust, Risk, and Security Management (AI TRiSM)** and **AI Security** market is projected by major industry analysts to exceed \$15 Billion by 2030, driven by global privacy legislation (EU AI Act, India DPDP Act 2023, US Executive Orders).
- PRIVGUARD's immediate focus is the developer-first segment: dev-friendly infrastructure enabling compliant AI deployments within minutes.

---

## 8. Business Model Hypotheses

1. **Open Core / Developer Tier (Free):** Local-first gateway for individual developers, local Ollama integration, single-node SQLite, community rules.
2. **Team / Growth Tier (\$99 – \$499/month):** Multi-tenant policies, team collaboration, centralized audit dashboards, advanced threat rule packs.
3. **Enterprise Dedicated / Air-Gapped License (Annual Contract):** High-throughput distributed clustering, HSM/KMS integration, custom SIEM connectors (Splunk, Datadog), and dedicated SLAs.

*Note: These business models represent initial hypotheses to be validated through customer discovery during the Buildathon.*

---

## 9. Product Roadmap: The Three-Phase Vision

- **Phase 1: Local-First AI Security Gateway (CURRENT — COMPLETED & FROZEN)**
  - Local proxy gateway, multi-entity redaction, deterministic injection defense, task capability tokens, content-free audit logs, and Next.js management console.
- **Phase 2: Agent Security & Execution Mesh (PLANNED)**
  - Distributed multi-agent capability propagation, runtime taint analysis across multi-hop reasoning chains, and human-in-the-loop approval escalation.
- **Phase 3: Privacy Infrastructure & Autonomous Policy Synthesis (LONG-TERM)**
  - Distributed zero-knowledge redaction verification, verifiable confidential computing enclaves, and enterprise-wide automated policy compliance synthesis.

---

## 10. Founder Profile & Execution Pedigree

- **Founder:** [ANIKET NANDI]
- **Agency / Lab:** Moon Sanctum Labs (*Decode. Build. Evolve.*), Kolkata, India.
- **Engineering Track Record:** Full-stack architecture, systems programming, and cybersecurity tooling. Built PRIVGUARD AI from foundational threat models to a deployment-qualified gateway with 438+ automated tests, zero Bandit security vulnerabilities, and verified network socket redaction boundaries.

---

## 11. Known Risks & Technical Limitations

1. **Obfuscation Arms Race:** Sophisticated multi-lingual or multi-step adversarial injections require continuous rule expansion and semantic vector classification.
2. **Inference Latency Overhead:** Security inspection introduces a 5–25ms overhead per request. Performance tuning (C-extensions/Rust rewrites) is earmarked for Phase 2.
3. **Contextual Token Alignment:** Extreme token compression in certain small models may occasionally misinterpret placeholder tokens if prompts lack clarity.

