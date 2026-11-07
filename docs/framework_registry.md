# PRIVGUARD AI — Statutory & Governance Framework Registry

**Agency:** Moon Sanctum Labs — *Decode. Build. Evolve.*  
**Lead Engineer:** ANIKET NANDI (Kolkata, IST)  
**Module:** `backend/app/compliance/framework_registry.py`  
**Reference Date:** November 2026

---

## 1. Overview & Framework Inventory

PRIVGUARD AI models statutory legislation and industry security frameworks natively within its database and service layer. Each framework definition tracks official gazettes, governing authorities, requirement taxonomies, and precise phased commencement dates.

### Supported Frameworks

| Framework ID | Name | Jurisdiction / Standard | Governing Authority | Total Requirements |
| :--- | :--- | :--- | :--- | :--- |
| `dpdp-2023` | Digital Personal Data Protection Act, 2023 | India | MeitY | 8 Sections |
| `dpdp-rules-2025` | Digital Personal Data Protection Rules, 2025 | India | MeitY | 7 Rules |
| `eu-ai-act` | EU Artificial Intelligence Act | European Union | European AI Office / EC | 8 Articles / Annexes |
| `nist-ai-100-1` | NIST AI Risk Management Framework 1.0 | United States / Global | NIST | 6 Subcategories |
| `nist-privacy-1-0` | NIST Privacy Framework 1.0 | United States / Global | NIST | 5 Subcategories |
| `iso-27001-2022` | ISO/IEC 27001:2022 Information Security | Global | ISO / IEC | 7 Annex A Controls |
| `soc2-tsc` | SOC 2 Trust Services Criteria (All 5 Categories) | Global | AICPA | 8 Criteria |

---

## 2. India DPDP Act & Rules Phased Commencement

PRIVGUARD AI models the Act and the subordinate Rules **independently**.

### 2.1 DPDP Act, 2023 (Act No. 22 of 2023)
Enacted 11 August 2023. Modeled at Section level:
- `Section 4`: Grounds for Processing Personal Data
- `Section 6`: Consent Requirements & Clear Notice
- `Section 8(5)`: Reasonable Security Safeguards (Technical Controls)
- `Section 8(6)`: Mandatory Personal Data Breach Notification
- `Section 8(7)`: Obligation of Erasure upon Purpose Fulfillment
- `Section 10`: Additional Obligations of Significant Data Fiduciaries (DPO, DPIA)
- `Section 12`: Right to Correction and Erasure of Personal Data
- `Section 16`: Cross-Border Transfer of Personal Data

### 2.2 DPDP Rules, 2025 (Three Commencement Tiers)
Subordinate rules notified under Section 40 of the Act carry three distinct statutory milestones:
1. **Tier 1 (Immediate / Nov 13, 2025):** Rules 1, 2, and 17–21.
   - Preliminary definitions, Data Protection Board digital inquiry procedures, summons, electronic hearings, and appellate procedures.
2. **Tier 2 (One Year / Nov 13, 2026):** Rule 4.
   - Technical safeguards, audit logging standards, and 6-hour intimation requirements for breaches.
3. **Tier 3 (Eighteen Months / May 13, 2027):** Rules 3, 5–16, 22, and 23.
   - **Crucial Invariant:** Rule 3 (Detailed multilingual itemized notice specifications) is in this 18-month phase, **not** the immediate phase. Also includes Rule 5 (Consent Managers), Rule 7 (Verifiable parental consent for minors), Rule 10 (72-hour / 7-day grievance resolution), and Rule 22 (Restricted transfer lists).

---

## 3. EU AI Act Phased Enforcement Timeline (Regulation (EU) 2024/1689)

PRIVGUARD AI tracks the 6 statutory milestones established by Regulation (EU) 2024/1689:

```
2025-02-02   Phase 1: Prohibited Practices (Art. 5) & AI Literacy (Art. 4)
             └── Subliminal manipulation, social scoring, biometric scraping bans.
2025-08-02   Phase 2: GPAI Obligations (Art. 51-53) & Notifying Authorities
             └── Foundation models, systemic risk mitigation, copyright compliance.
2026-08-02   Phase 3: Transparency & Core Deployer Obligations
             └── Art. 50 (Synthetic content marking), Art. 14 (Human oversight), Art. 12 (Logging).
2026-12-02   Phase 4: Extended Technical Standards & Annex Guidance
             └── Harmonised technical standards from CEN-CENELEC.
2027-12-02   Phase 5: Annex III Standalone High-Risk AI Systems
             └── Biometrics, critical infrastructure, employment, essential public services.
2028-08-02   Phase 6: Annex I High-Risk Embedded Safety Components
             └── AI embedded in medical devices, aviation, vehicles, machinery.
```

---

## 4. Global Security & Privacy Frameworks

### 4.1 NIST AI 100-1 (AI RMF 1.0)
Structured into four core functions:
- `GOVERN-1.1`: Legal, regulatory, and ethical risk policies for AI.
- `MAP-1.5`: Context, data pipeline, and system boundary categorization.
- `MEASURE-2.3`: AI safety, security, and adversarial robustness evaluation.
- `MANAGE-1.3`: Incident response, containment, and override procedures.
- `MANAGE-2.2`: Third-party tool and model supply chain risk tracking.
- `GOVERN-6.1`: Human oversight and rollback intervention mechanisms.

### 4.2 NIST Privacy Framework 1.0
- `ID.PO-P1`: Governance and role-based privacy authority.
- `CT.DP-P1`: Data processing transparency and principal controls.
- `CM.PO-P2`: Cryptographic protection of stored personal data.
- `PR.DS-P1`: Data sanitization and irreversible erasure upon purpose completion.
- `RS.CO-P1`: Privacy breach intimation and incident communication.

### 4.3 ISO/IEC 27001:2022 (Annex A)
- `A.5.15`: Access Control Management.
- `A.5.33`: Protection of Records (Zero-content audit logging).
- `A.8.10`: Information Deletion (Cryptographic DEK erasure).
- `A.8.11`: Data Masking (Deterministic PII token substitution).
- `A.8.24`: Use of Cryptography (Envelope encryption & KMS).
- `A.8.28`: Secure Coding & Software Verification.
- `A.8.30`: Outsourced Development & Supply Chain Security.

### 4.4 SOC 2 Trust Services Criteria (All 5 Categories)
- **Security (Common Criteria):** `CC6.1` (Logical boundary defense), `CC6.6` (Code and artifact integrity verification).
- **Availability:** `A1.2` (Resilience, failover, and fault injection tolerance).
- **Processing Integrity:** `PI1.4` (State machine input validation, anti-tampering, and taint tracking).
- **Confidentiality:** `C1.1` (Envelope encryption of sensitive memory vaults), `C1.2` (Cryptographic key management and destruction).
- **Privacy:** `P3.1` (Notice and consent gating for long-term storage), `P6.1` (Data minimization and principal deletion rights).

