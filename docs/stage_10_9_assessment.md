# Stage 10.9 Assessment: Compliance Evidence Engine (Revised)

**PRIVGUARD AI** — *Independent Security & Privacy Enforcement Layer for Agentic AI*  
**Organization:** Moon Sanctum Labs — *Decode. Build. Evolve.*  
**Lead Engineer:** ANIKET NANDI (Kolkata, IST)  
**Baseline Commit:** `2f22156`  
**Milestone:** Stage 10.9 — Compliance Evidence Engine  
**Revision:** v1.1 (Revalidated Legal Framework Timelines, Dedicated Evidence Signing, Five-State Assurance Separation)

---

## 1. Executive Summary & Design Philosophy

PRIVGUARD AI has established a deep, production-grade security, privacy, and governance perimeter across Stages 1–10.8:
- Model Gateway and PII/Secret redaction (Stages 1–2)
- Agent Broker and revocable capability tokens (Stages 3–4)
- Personal AI Memory Vault with AES-256-GCM envelope encryption (Stages 5–6)
- Model Context Protocol (MCP) Security Gateway (Stage 8)
- Enterprise Multi-Tenancy, 8-Role RBAC, and Ed25519-Signed Policy Bundles (Stage 9)
- Hardened Container Deployment & Network Isolation (Stage 10.1–10.3)
- Cloud-Neutral Kubernetes & Helm Deployment (Stage 10.4)
- Enterprise KMS Key Management & Non-Destructive Rotation (Stage 10.5)
- Zero-Content Observability & 8 Active Synthetic Canaries (Stage 10.6)
- SLSA v1.0 Level 3 Supply Chain Integrity & Sigstore Cosign Signing (Stage 10.7)
- Production Hardening, Edge Resource Bounding & Deterministic Chaos Engineering (Stage 10.8)

**The Core Mission:** The **Compliance Evidence Engine** is an evidence-collection, control-mapping, and verification platform that transforms existing technical controls into traceable, versioned, tamper-evident compliance artifacts.

### Core Non-Negotiable Invariants
1. **Prove What Exists — No Checkbox Theater:** PRIVGUARD AI proves what it actually enforces. A green indicator requires an unexpired, cryptographically verifiable evidence artifact linked to an authoritative subsystem.
2. **Evidence is Not Certification:** A passing technical test proves the control functioned; it does not constitute legal certification or independent audit sign-off. All UI views, API schemas, and exported packages feature prominent legal disclaimers.
3. **Phased Statutory Commencement & Applicability:**
   - **India DPDP Rules, 2025:** Accurately models the three phased commencement milestones (13 Nov 2025, 13 Nov 2026, 13 May 2027) with Rule 3 Notice requirements commencing on 13 May 2027.
   - **EU AI Act (Regulation (EU) 2024/1689):** Models the phased enforcement timeline (2 Feb 2025, 2 Aug 2025, 2 Aug 2026, 2 Dec 2026, 2 Dec 2027, 2 Aug 2028).
   - **NIST AI RMF 1.0 (NIST AI 100-1) & Privacy Framework 1.0:** Structured mapping to functions (`GOVERN`, `MAP`, `MEASURE`, `MANAGE`) without claiming statutory certification.
   - **ISO/IEC 27001:2022 & SOC 2 TSC (5 Categories):** Respects copyright by referencing identifiers (e.g. `A.8.24`, `CC6.1`), original technical descriptions, and mapping rationales without reproducing proprietary standard text.
4. **Dedicated Cryptographic Signing:** Evidence export packages and manifests are signed using a dedicated `KeyPurpose.EVIDENCE_SIGNING` Ed25519 key, separate from policy-signing and approval HMAC keys. Public keys are exported for independent third-party verification without internal database access.
5. **Defense-in-Depth Export Sanitization:** Allowlisted metadata schemas by default, tenant-scoped access checks, and dual-layer secret/PII scanning before packaging. Zero real API keys, tokens, or personal memories are ever exported.
6. **Five-State Assurance Model:** Distinct fields for Control Implementation, Evidence Verification, Evidence Freshness, Assurance Level, and Applicability. Stale evidence reduces assurance; it does not declare a working control unimplemented.

---

## 2. Reusable Subsystems & Zero-Duplication Architecture

| Subsystem | Existing Module & Symbols | Compliance Engine Integration |
| :--- | :--- | :--- |
| **Tenant Scoping & RLS** | `app.core.tenant`: `TenantContext`, `resolve_tenant_context` | Enforces tenant scoping on all compliance models via PostgreSQL RLS. |
| **Enterprise RBAC** | `app.enterprise.rbac`: `RBACAuthorizer`, `Permission` | Enforces `compliance:read`, `compliance:collect`, `compliance:review`, `compliance:export`, `compliance:admin`. |
| **Immutable Audit Ledger** | `app.enterprise.audit`: `EnterpriseAuditLedger`, `verify_chain_integrity` | Audit-logs evidence collections, assessment reviews, and export events into SHA-256 chained ledger. |
| **Cryptographic Signing** | `app.key_management.signing`: `SigningKeyManager` | Provisions dedicated `KeyPurpose.EVIDENCE_SIGNING` Ed25519 keys for manifest signing. |
| **Canonical JSON** | `app.policies.signing`: `canonical_json_bytes` | Enforces RFC 8785 canonical byte formatting for structured evidence artifact hashing. |
| **KMS & Envelope Encryption** | `app.memory.vault`: `MemoryVault`, `app.memory.crypto`: `EnvelopeEncryption` | Verifies data-at-rest encryption controls (AES-256-GCM, KEK/DEK wrapping) as live evidence. |
| **Active Synthetic Canaries** | `app.observability.canary.runner`: `get_canary_runner` | Harvests live canary verification runs proving controls continuously fail closed. |
| **Supply Chain & Release** | `scripts/security/generate_sboms.py`, `scripts/security/verify_release.py` | Validates CycloneDX 1.6 SBOMs, Cosign signatures, and SLSA v1.0 Level 3 provenance metadata. |

---

## 3. Statutory & Framework Specifications

### 3.1 India Digital Personal Data Protection Act, 2023 & DPDP Rules, 2025
- **Act Enactment:** 11 August 2023 (Gazette of India). Modeled at Section level (Sections 1–44).
- **DPDP Rules, 2025 Notification:** Ministry of Electronics and Information Technology (MeitY).
- **Phased Commencement Schedule:**
  1. **13 November 2025 (Immediate / 1 Year):** Rules 1, 2, 17, 18, 19, 20, 21 (Preliminary, definitions, Data Protection Board proceedings, appeals, and review).
  2. **13 November 2026 (One Year):** Rule 4 (Security safeguards, data breach reporting formats, and logging).
  3. **13 May 2027 (Eighteen Months):**
     - **Rule 3 (Notice Requirements):** Provision-level notice standards and multilingual itemization.
     - **Rule 5 (Consent Architecture):** Accessible, granular consent mechanisms.
     - **Rule 6 (Consent Managers):** Registration and interoperability standards.
     - **Rule 7 (Children’s Personal Data):** Verifiable parental consent.
     - **Rules 8–16 (Data Fiduciary Obligations):** Retention, grievance redressal, and audits.
     - **Rules 22–23 (Cross-Border Transfers):** Blacklisted jurisdictions and reporting.
- **Commencement Statuses:** `COMMENCED`, `PHASED_FUTURE`, `NOT_APPLICABLE`.

### 3.2 EU AI Act (Regulation (EU) 2024/1689)
- **Entered into Force:** 1 August 2024. Phased timeline reflecting current amendments:
  - **2 February 2025:** Prohibited AI practices (Chapter I & II, Art. 5) and AI literacy (Art. 4).
  - **2 August 2025:** General-Purpose AI (GPAI) model obligations, systemic risk classification, and notifying authorities governance (Chapter III Sec. 4, Chapter V, Chapter XII).
  - **2 August 2026:** Majority of applicable requirements, including transparency provisions (Art. 50).
  - **2 December 2026:** Additional prohibitions under amended technical standards.
  - **2 December 2027:** High-risk AI systems listed in Annex III (biometrics, critical infrastructure, employment, essential services).
  - **2 August 2028:** High-risk AI systems embedded as safety components in regulated products (Annex I / Art. 6(1)).

### 3.3 NIST AI RMF 1.0 & Privacy Framework 1.0
- **NIST AI RMF 1.0 Identifier:** **NIST AI 100-1** (NIST, January 2023).
  - Functions: `GOVERN` (GV), `MAP` (MP), `MEASURE` (MS), `MANAGE` (MG).
- **NIST Privacy Framework 1.0:**
  - Functions: `IDENTIFY-P`, `GOVERN-P`, `CONTROL-P`, `COMMUNICATE-P`, `PROTECT-P`.

### 3.4 ISO/IEC 27001:2022 & SOC 2 Trust Services Criteria
- **ISO/IEC 27001:2022:** Clauses 4–10 & Annex A controls (A.5, A.6, A.7, A.8). Uses official control identifiers (e.g., `A.8.24` Use of cryptography) and original technical mapping rationales.
- **SOC 2 Trust Services Criteria (2017/2022):** All **five** Trust Services Categories:
  1. **Security** (Common Criteria CC1–CC9)
  2. **Availability** (A1)
  3. **Processing Integrity** (PI1)
  4. **Confidentiality** (C1)
  5. **Privacy** (P1–P8)

---

## 4. Internal Control Catalog (20 Domains, 35 Standardized Controls)

1. *Identity & Authentication:* `PG-CONTROL-001` (App API Key Hashing), `PG-CONTROL-002` (Agent Identity Registration)
2. *Authorization & RBAC:* `PG-CONTROL-003` (8-Role Enterprise RBAC), `PG-CONTROL-004` (Separation of Duties & Least Privilege)
3. *Multi-Tenancy & Data Isolation:* `PG-CONTROL-005` (PostgreSQL Row-Level Security), `PG-CONTROL-006` (Connection Pool Tenant Context Scoping)
4. *Privacy & PII Minimization:* `PG-CONTROL-007` (Deterministic PII Detection & Token Substitution), `PG-CONTROL-008` (Reversible De-redaction Return)
5. *Personal AI Memory Vault:* `PG-CONTROL-009` (AES-256-GCM Envelope Encryption), `PG-CONTROL-010` (Cryptographic Erasure & DEK Destruction)
6. *Consent & Proposal Staging:* `PG-CONTROL-011` (Human Consent Gate for Long-Term Memory), `PG-CONTROL-012` (Memory Poisoning & Directive Overrides Scanning)
7. *Agent Execution Governance:* `PG-CONTROL-013` (Revocable Capability Tokens), `PG-CONTROL-014` (Atomic CAS Anti-Replay Protection)
8. *Human-in-the-Loop Approvals:* `PG-CONTROL-015` (HMAC Action Hash Anti-Tampering), `PG-CONTROL-016` (High-Risk Tool Authorization Gate)
9. *MCP Security Gateway:* `PG-CONTROL-017` (SSRF Destination Protection), `PG-CONTROL-018` (Tool Description Poisoning & Catalog Drift Quarantine)
10. *Prompt Injection Defense:* `PG-CONTROL-019` (Deterministic Prompt Injection Detection), `PG-CONTROL-020` (Untrusted Data Content Sanitization)
11. *Data Exfiltration Defense:* `PG-CONTROL-021` (Monotonic Taint Tracking - MITRE T1700), `PG-CONTROL-022` (Outbound Network Sink Enforcement)
12. *Audit Trail Integrity:* `PG-CONTROL-023` (Tamper-Evident SHA-256 Chained Ledger), `PG-CONTROL-024` (Zero-Content Audit Storage Invariant)
13. *Cryptographic Key Management:* `PG-CONTROL-025` (Provider-Independent KMS Abstraction), `PG-CONTROL-026` (Non-Destructive Key Rotation & Versioning)
14. *Policy Governance & Signing:* `PG-CONTROL-027` (Ed25519-Signed Policy Bundles), `PG-CONTROL-028` (Anti-Downgrade Version Enforcement)
15. *Software Supply Chain:* `PG-CONTROL-029` (CycloneDX 1.6 Machine-Readable SBOMs), `PG-CONTROL-030` (SLSA Level 3 Provenance & Cosign Signature Verification)
16. *Vulnerability Management:* `PG-CONTROL-031` (Automated Dependency & Container Vulnerability Gates)
17. *Zero-Content Observability:* `PG-CONTROL-032` (Continuous Synthetic Security Canaries)
18. *Edge Resource Bounding:* `PG-CONTROL-033` (ASGI Request Size & Streaming Chunk Bounding)
19. *Execution Budget & Runaway Defense:* `PG-CONTROL-034` (Policy-Configurable Agent Step Quotas & Auto-Revocation)
20. *Disaster Recovery & Outbox Durability:* `PG-CONTROL-035` (Transactional Outbox & Dead-Letter Isolation)

---

## 5. Five-State Assurance Separation Model

To prevent misleading compliance assertions, the engine maintains distinct states:

```
+---------------------------------------------------------------------------------------------------+
| 1. Control Implementation Status                                                                  |
|    - IMPLEMENTED | PARTIALLY_IMPLEMENTED | NOT_IMPLEMENTED | NOT_ASSESSED | NOT_APPLICABLE        |
+---------------------------------------------------------------------------------------------------+
| 2. Evidence Verification Status                                                                   |
|    - VERIFIED | FAILED | UNKNOWN | REQUIRES_REVIEW                                               |
+---------------------------------------------------------------------------------------------------+
| 3. Evidence Freshness                                                                             |
|    - CURRENT | STALE | EXPIRED                                                                    |
+---------------------------------------------------------------------------------------------------+
| 4. Assurance Level                                                                                |
|    - HIGH (Current verified evidence matches implementation)                                      |
|    - MEDIUM (Supporting or partial evidence verified)                                             |
|    - LOW (Evidence is stale or unverified; underlying control remains implemented)                |
|    - INSUFFICIENT (Missing or failed evidence)                                                    |
+---------------------------------------------------------------------------------------------------+
| 5. Applicability Decision                                                                         |
|    - APPLICABLE | NOT_APPLICABLE | REQUIRES_REVIEW                                                |
+---------------------------------------------------------------------------------------------------+
```

**Semantic Invariant:** When evidence expires, `evidence_freshness` becomes `STALE` and `assurance_level` transitions to `LOW` or `INSUFFICIENT`. The `control_implementation_status` is not altered automatically, preserving accurate separation between engineering implementation and ongoing audit assurance.

---

## 6. Hardened Evidence Collectors

1. **PostgreSQL RLS Collector:**
   - Validates `pg_tables.rowsecurity = true`.
   - Queries `current_setting('is_superuser') == 'off'` and `rolbypassrls = false` for the runtime role.
   - Executes an isolated, non-destructive query confirming an unauthorized tenant `SELECT` returns 0 rows.
2. **KMS Collector:**
   - Distinguishes key metadata (active version, algorithm) from live provider health ping and historical rotation jobs (`key_rotation_jobs`).
   - Does not claim re-encryption based solely on metadata.
3. **Supply Chain Collector:**
   - Validates SBOM SHA-256 digests against build records.
   - Verifies Cosign signatures against Sigstore OIDC identity.
   - Validates SLSA provenance subject digests and builder identity.
   - Marks status as `UNKNOWN` or `REQUIRES_REVIEW` if assurance cannot be verified.
4. **Synthetic Canaries Collector:**
   - Evaluates the 8 live security canaries and stores execution time, failure reason, and verification status.

---

## 7. Cryptographic Export Packaging & Verification

```
privguard-evidence-package-{tenant}-{framework}-{timestamp}.zip
├── manifest.json              # RFC 8785 Canonical JSON with artifact hashes and Ed25519 signature
├── manifest.sig               # Detached Base64 Ed25519 signature
├── public_key.pem             # Public verification key for this signing key ID (kid)
├── verification_instructions.md # Standalone verification steps for external auditors
├── summary.json               # Allowlisted compliance summary and gap findings
├── applicability.json         # Scoped organizational applicability decisions & role rationales
├── controls/                  # Standardized control definitions (PG-CONTROL-001..035)
├── mappings/                  # Mappings to framework clauses
└── artifacts/                 # Allowlisted, hashed evidence records (Zero secrets/PII)
```

**Signature Procedure:**
1. Serialize `manifest.json` without the `signature` field using RFC 8785 canonical JSON bytes.
2. Compute `signature = ed25519_sign(evidence_signing_key, canonical_manifest_bytes)`.
3. Set `manifest.signature = base64_encode(signature)` and output detached `manifest.sig`.
4. Independent verification computes `ed25519_verify(public_key, canonical_manifest_bytes, signature)` with zero database access.
