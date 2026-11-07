# PRIVGUARD AI — Compliance Applicability & Organization Roles

**Agency:** Moon Sanctum Labs — *Decode. Build. Evolve.*  
**Lead Engineer:** ANIKET NANDI (Kolkata, IST)  
**Module:** `backend/app/compliance/applicability.py`  
**Reference Date:** November 2026

---

## 1. Scoping & Organization Role Taxonomy

In modern data privacy and AI regulations, an organization's statutory obligations vary depending on its role in the processing lifecycle. PRIVGUARD AI models five canonical organizational roles:

| Role Identifier | Description & Context | Typical Regulatory Classification |
| :--- | :--- | :--- |
| `DATA_FIDUCIARY` | Determines the purpose and means of processing personal data. | India DPDP Act Data Fiduciary; GDPR Data Controller. |
| `DATA_PROCESSOR` | Processes personal data on behalf of a Data Fiduciary under contract. | India DPDP Act Data Processor; GDPR Data Processor. |
| `SIGNIFICANT_DATA_FIDUCIARY` | Designated entity handling high volumes or sensitive personal data. | India DPDP Act Section 10 entity (mandating DPO, DPIA, audit). |
| `AI_PROVIDER` | Develops an AI system or model and places it on the market. | EU AI Act Provider (Arts. 9–15, 51–53). |
| `AI_DEPLOYER` | Uses an AI system under its authority in a professional context. | EU AI Act Deployer (Arts. 26, 50). |

---

## 2. Applicability Decision States

For every requirement in a supported framework, a tenant organization's compliance officer can assign an explicit applicability determination:

- **`APPLICABLE` (Default):** The requirement applies to the tenant and is evaluated in gap analysis and coverage scoring.
- **`NOT_APPLICABLE`:** The requirement does not apply to this tenant given its organizational role or processing boundaries. A documented, non-empty legal or technical justification is strictly mandatory.
- **`REQUIRES_REVIEW`:** Flagged for triage or legal assessment (e.g. when statutory rules change or a new AI model deployment commences).

---

## 3. Justification Audit Trail

When an applicability decision is recorded or updated via `POST /v1/compliance/applicability`:
1. `tenant_id`: Enforces tenant isolation.
2. `framework_id`: Canonical framework ID (e.g. `dpdp-2023`, `eu-ai-act`).
3. `requirement_id`: Exact statutory section or clause (e.g. `DPDP-ACT-SEC-10`).
4. `decision`: `APPLICABLE`, `NOT_APPLICABLE`, or `REQUIRES_REVIEW`.
5. `role`: Selected organizational role.
6. `justification`: Mandatory string explaining why the requirement does or does not apply (e.g., *"Tenant acts purely as a B2B SaaS data processor under customer DPA; Section 10 Significant Data Fiduciary obligations do not attach."*).
7. `reviewed_by`: Audit identity of the compliance reviewer.
8. `reviewed_at`: UTC timestamp of the determination.

---

## 4. Impact on Gap Analysis & Compliance Scoring

The Gap Analysis engine (`gap_analysis.py`) respects applicability scoping:
- Requirements flagged as `NOT_APPLICABLE` are omitted from the unmapped/gap count.
- In executive summaries and compliance dashboards, applicability statistics are broken down separately so auditors can inspect all non-applicable clauses along with their justifications.

