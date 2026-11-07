# PRIVGUARD AI — Control Mapping Methodology & Coverage Scoring

**Agency:** Moon Sanctum Labs — *Decode. Build. Evolve.*  
**Lead Engineer:** ANIKET NANDI (Kolkata, IST)  
**Module:** `backend/app/compliance/control_mapping.py`  
**Reference Date:** November 2026

---

## 1. Mapping Philosophy: Substantive Engineering vs. Checkbox Theater

PRIVGUARD AI rejects superficial one-to-one checkbox mapping. An internal control (`PG-CONTROL-xxx`) is mapped to an external statutory or regulatory requirement only when the control provides a direct, measurable technical mechanism that prevents, detects, or mitigates the risk identified in that requirement.

### 1.1 The Crosswalk Model
```
┌───────────────────────────────────────┐
│ External Statutory / Standard Req     │
│ (e.g. DPDP Sec 8(5), EU AI Art 14)    │
└──────────────────┬────────────────────┘
                   │
                   ▼ Bi-directional Crosswalk
┌───────────────────────────────────────┐
│ Standardized Internal Controls        │
│ (PG-CONTROL-001 through 035)          │
└──────────────────┬────────────────────┘
                   │
                   ▼ Direct Telemetry & Automated Probes
┌───────────────────────────────────────┐
│ Authoritative PRIVGUARD Subsystems    │
│ (KMS, Vault, Canaries, Policies)      │
└───────────────────────────────────────┘
```

---

## 2. Mapping Types & Coverage Scoring

Every mapping entry between an internal control and an external requirement defines:
1. `control_id`: Standardized internal control ID (`PG-CONTROL-xxx`).
2. `requirement_id`: Standardized statutory requirement ID.
3. `mapping_type`: Classification of technical fulfillment (`DIRECT`, `PARTIAL`, `SUPPORTING`).
4. `rationale`: Verifiable engineering justification.
5. `coverage_score`: Weighted numeric coefficient used in framework coverage aggregation.

| Mapping Type | Coverage Score | Criteria & Definition | Example |
| :--- | :---: | :--- | :--- |
| **DIRECT** | `1.0` | The internal control directly enforces and fully satisfies the core technical mandate of the requirement. | `PG-CONTROL-005` (FORCE RLS) directly satisfies `DPDP-ACT-SEC-8-5` (Security safeguards). |
| **PARTIAL** | `0.6` | The internal control addresses a substantial technical subset of the requirement, but external administrative, procedural, or policy measures are also necessary. | `PG-CONTROL-021` (Monotonic Taint Tracking) partially satisfies `DPDP-ACT-SEC-16` (Cross-border data transfer controls). |
| **SUPPORTING** | `0.3` | The internal control provides forensic evidence, telemetry, or auxiliary defense-in-depth supporting the requirement. | `PG-CONTROL-023` (Tamper-evident Audit Ledger) supports `DPDP-ACT-SEC-8-6` (Data breach notification & forensics). |

---

## 3. Framework Coverage Calculation

When calculating overall coverage for a compliance framework:
1. Each framework defines $N$ mandatory requirements: $\{R_1, R_2, \dots, R_N\}$.
2. For each requirement $R_i$, the engine evaluates all associated internal controls and determines the **highest coverage score**:
   $$S_i = \max_{m \in \text{mappings}(R_i)} (\text{coverage\_score}_m)$$
   If no internal control is mapped to $R_i$, $S_i = 0.0$.
3. The framework's overall **Coverage Percentage** is:
   $$\text{Coverage \%} = \frac{\sum_{i=1}^N S_i}{N} \times 100$$
4. **Mapped Count:** The number of requirements where $\text{mappings}(R_i) \neq \emptyset$.

---

## 4. Multi-Tenant Applicability Filtering

Not all statutory requirements apply to every tenant organization:
- A tenant acting solely as a **Data Processor** or **AI Deployer** can mark Data Fiduciary-specific requirements (e.g. DPIA, resident DPO, child consent mechanisms) as `NOT_APPLICABLE` with a legally recorded rationale.
- Requirements classified as `NOT_APPLICABLE` are excluded from denominator calculations when computing tenant-specific compliance health scores.

