# PRIVGUARD AI — Stage 10.9: Compliance Evidence Engine

**Agency:** Moon Sanctum Labs — *Decode. Build. Evolve.*  
**Lead Engineer:** ANIKET NANDI (Kolkata, IST)  
**Baseline Commit:** `2f22156`  
**Milestone:** Stage 10.9 — Compliance Evidence Engine  
**Release Date:** November 2026  

---

## 1. Executive Summary & Design Principles

The **Compliance Evidence Engine** establishes an automated, cryptographically verifiable evidence and control-mapping layer for PRIVGUARD AI. Rather than generating superficial checkbox reports, the engine directly inspects, collects, fingerprints, and signs technical telemetry emitted by PRIVGUARD AI's operational subsystems.

### Core Non-Negotiable Invariants
1. **Prove What Exists — No Checkbox Theater:** A green compliance indicator requires an unexpired, cryptographically verifiable evidence artifact linked to an authoritative PRIVGUARD AI subsystem.
2. **Evidence is Not Certification:** A passing technical test proves that an engineering control functioned as designed; it does not constitute statutory legal certification, regulatory safe-harbor, or an independent third-party audit opinion. Prominent disclaimers are enforced across all UI views, API schemas, and exported packages.
3. **Phased Statutory Commencement & Independence:**
   - **India DPDP Act, 2023 & DPDP Rules, 2025:** Modeled independently. The Act is modeled at Section level (Sections 1–44). The Rules distinguish three statutory commencement groups:
     - *13 November 2025 (Immediate / 1 Year):* Rules 1, 2, and 17–21 (Preliminary, definitions, Board inquiry proceedings, appeals, reviews).
     - *13 November 2026 (One Year):* Rule 4 (Security safeguards, breach reporting formats, logging).
     - *13 May 2027 (Eighteen Months):* Rules 3, 5–16, 22, and 23. Specifically, Rule 3 (Notice requirements) is scheduled for the eighteen-month phase, **not** the immediate phase.
   - **EU AI Act (Regulation (EU) 2024/1689):** Phased enforcement reflecting amendments in force as of November 2026:
     - *2 February 2025:* Prohibited AI practices (Chapter I & II, Art. 5) and AI literacy (Art. 4).
     - *2 August 2025:* GPAI model obligations, systemic risk classification, and notifying authorities (Chapters III Sec. 4, V, XII).
     - *2 August 2026:* Majority of requirements, including transparency provisions (Art. 50).
     - *2 December 2026:* Additional prohibitions under amended technical standards.
     - *2 December 2027:* Annex III standalone high-risk AI systems (biometrics, critical infrastructure, employment, essential services).
     - *2 August 2028:* Annex I high-risk AI systems embedded as safety components in regulated products.
   - **NIST AI RMF 1.0 (NIST AI 100-1) & Privacy Framework 1.0:** Structured mapping to functions (`GOVERN`, `MAP`, `MEASURE`, `MANAGE`) without claiming statutory certification.
   - **ISO/IEC 27001:2022 & SOC 2 TSC (5 Categories):** Includes Security (CC), Availability (A), Processing Integrity (PI), Confidentiality (C), and Privacy (P) using proprietary-safe identifiers and original technical summaries.
4. **Dedicated Evidence-Signing Key Architecture:** Provisions `KeyPurpose.EVIDENCE_SIGNING` in `SigningKeyManager` separate from policy-signing and approval HMAC keys. Export manifests are signed with Ed25519. Public verification keys are exported at `/v1/compliance/signing-keys/public` for third-party verification without internal database access.
5. **Defense-in-Depth Export Sanitization:** Strict allowlisted Pydantic metadata schemas by default, tenant-scoped access checks, and dual-layer secret/PII scanning before packaging. Zero real API keys, credentials, or unredacted memories/prompts are ever exported.
6. **Five-State Assurance Separation Model:** Distinct states for Control Implementation, Evidence Verification, Evidence Freshness, Assurance Level, and Applicability Decision. Stale evidence reduces assurance status (to LOW or INSUFFICIENT); it does **not** alter the control implementation status.

---

## 2. Standardized Control Catalog (20 Domains, 35 Controls)

| Domain | Control ID | Control Title | Criticality | Owner Role |
| :--- | :--- | :--- | :--- | :--- |
| **1. Identity & Auth** | `PG-CONTROL-001` | Application API Key Cryptographic Hashing | CRITICAL | Security Engineer |
| | `PG-CONTROL-002` | Agent Identity Registration & Ownership Scoping | HIGH | Security Engineer |
| **2. Authorization & RBAC** | `PG-CONTROL-003` | 8-Role Enterprise Role-Based Access Control | CRITICAL | Security Engineer |
| | `PG-CONTROL-004` | Separation of Duties & Policy Admin Boundary | HIGH | Compliance Officer |
| **3. Multi-Tenancy & Isolation** | `PG-CONTROL-005` | PostgreSQL Row-Level Security (`FORCE RLS`) | CRITICAL | Database Admin |
| | `PG-CONTROL-006` | Session Tenant Context Scoping | CRITICAL | Database Admin |
| **4. Privacy & PII** | `PG-CONTROL-007` | Deterministic PII Detection & Token Substitution | CRITICAL | Privacy Officer |
| | `PG-CONTROL-008` | Reversible De-Redaction on Downstream Return | HIGH | Privacy Officer |
| **5. Personal AI Memory** | `PG-CONTROL-009` | AES-256-GCM Envelope Encryption (Vault) | CRITICAL | Security Engineer |
| | `PG-CONTROL-010` | Cryptographic Erasure & DEK Destruction | CRITICAL | Privacy Officer |
| **6. Consent & Staging** | `PG-CONTROL-011` | Human Consent Gate for Long-Term Memory | HIGH | Privacy Officer |
| | `PG-CONTROL-012` | Memory Poisoning & Directive Override Scanning | CRITICAL | Security Engineer |
| **7. Agent Governance** | `PG-CONTROL-013` | Revocable Scoped Capability Tokens | CRITICAL | Security Engineer |
| | `PG-CONTROL-014` | Atomic CAS Anti-Replay Capability Protection | CRITICAL | Security Engineer |
| **8. Human Approvals** | `PG-CONTROL-015` | HMAC Action Hash Anti-Tampering | CRITICAL | Security Engineer |
| | `PG-CONTROL-016` | High-Risk Action Authorization Gate | CRITICAL | Compliance Officer |
| **9. MCP Gateway** | `PG-CONTROL-017` | MCP SSRF Destination Protection | CRITICAL | Security Engineer |
| | `PG-CONTROL-018` | MCP Tool Poisoning & Drift Quarantine | HIGH | Security Engineer |
| **10. Prompt Injection** | `PG-CONTROL-019` | Deterministic Prompt Injection Detection | CRITICAL | Security Engineer |
| | `PG-CONTROL-020` | Untrusted Content Boundary Neutralization | HIGH | Security Engineer |
| **11. Exfiltration Defense** | `PG-CONTROL-021` | Monotonic Taint Tracking (MITRE T1700) | CRITICAL | Security Engineer |
| | `PG-CONTROL-022` | Outbound Network Sink Enforcement | CRITICAL | Security Engineer |
| **12. Audit Integrity** | `PG-CONTROL-023` | Tamper-Evident SHA-256 Chained Ledger | CRITICAL | Compliance Officer |
| | `PG-CONTROL-024` | Zero-Content Audit Storage Invariant | CRITICAL | Privacy Officer |
| **13. Cryptography & KMS** | `PG-CONTROL-025` | Provider-Independent KMS Abstraction | CRITICAL | Security Engineer |
| | `PG-CONTROL-026` | Non-Destructive Key Rotation & Versioning | HIGH | Security Engineer |
| **14. Policy Governance** | `PG-CONTROL-027` | Ed25519-Signed Governance Policy Bundles | CRITICAL | Compliance Officer |
| | `PG-CONTROL-028` | Anti-Downgrade Version Enforcement | HIGH | Compliance Officer |
| **15. Supply Chain** | `PG-CONTROL-029` | CycloneDX 1.6 Machine-Readable SBOMs | HIGH | Security Engineer |
| | `PG-CONTROL-030` | SLSA Level 3 Provenance & Cosign Verification | CRITICAL | Security Engineer |
| **16. Vulnerabilities** | `PG-CONTROL-031` | Automated Dependency & Image Security Gates | CRITICAL | Security Engineer |
| **17. Observability** | `PG-CONTROL-032` | Continuous Synthetic Security Canaries (8) | CRITICAL | DevOps Engineer |
| **18. Edge Bounding** | `PG-CONTROL-033` | ASGI Request Size & Streaming Chunk Limits | HIGH | DevOps Engineer |
| **19. Execution Budgets** | `PG-CONTROL-034` | Policy-Configurable Step Quotas & Revocation | CRITICAL | Security Engineer |
| **20. Disaster Recovery** | `PG-CONTROL-035` | Transactional Outbox & Dead-Letter Isolation | HIGH | DevOps Engineer |

---

## 3. Five-State Assurance Separation Model

```
┌────────────────────────────────────────────────────────────────────────┐
│ 1. Control Implementation Status                                       │
│    - IMPLEMENTED | PARTIALLY_IMPLEMENTED | NOT_IMPLEMENTED | etc.      │
├────────────────────────────────────────────────────────────────────────┤
│ 2. Evidence Verification Status                                        │
│    - VERIFIED | FAILED | UNKNOWN | REQUIRES_REVIEW                     │
├────────────────────────────────────────────────────────────────────────┤
│ 3. Evidence Freshness                                                  │
│    - CURRENT | STALE | EXPIRED                                         │
├────────────────────────────────────────────────────────────────────────┤
│ 4. Assurance Level                                                     │
│    - HIGH | MEDIUM | LOW | INSUFFICIENT                                │
├────────────────────────────────────────────────────────────────────────┤
│ 5. Applicability Decision                                              │
│    - APPLICABLE | NOT_APPLICABLE | REQUIRES_REVIEW                     │
└────────────────────────────────────────────────────────────────────────┘
```

**Semantic Invariant:** If operational evidence expires past its TTL, `freshness_status` transitions to `STALE` and `assurance_level` transitions to `LOW` or `INSUFFICIENT`. The underlying `control_implementation_status` is **not** altered, preserving the distinction between whether code is implemented vs whether recent operational verification evidence is fresh.

---

## 4. Cryptographic Packaging & Verification

Exported audit packages are signed with Ed25519 keys provisioned under `KeyPurpose.EVIDENCE_SIGNING`:

```
privguard-evidence-package-{tenant}-{framework}-{timestamp}.zip
├── manifest.json              # RFC 8785 Canonical JSON with artifact hashes and Ed25519 signature
├── manifest.sig               # Detached Base64 Ed25519 signature
├── public_key.pem             # SubjectPublicKeyInfo PEM for kid
├── verification_instructions.md # Standalone verification steps for external auditors
├── summary.json               # Allowlisted compliance summary and gap findings
├── applicability.json         # Scoped organizational applicability decisions & role rationales
├── controls/                  # Standardized control definitions (PG-CONTROL-001..035)
├── mappings/                  # Mappings to framework clauses
└── artifacts/                 # Allowlisted, hashed evidence records (Zero secrets/PII)
```

Auditors independently verify manifest integrity using standard OpenSSL or Python with zero PRIVGUARD database access:
```bash
# Independent Python verification
python -c '
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import json, hashlib

with open("public_key.pem", "rb") as f:
    pub_key = serialization.load_pem_public_key(f.read())

with open("manifest.json", "r") as f:
    m = json.load(f)

sig = bytes.fromhex(m.pop("signature"))
canon = json.dumps(m, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
pub_key.verify(sig, canon)
print("✓ Manifest Ed25519 signature is VALID.")
'
```

