# PRIVGUARD AI — Compliance Evidence Architecture

**Agency:** Moon Sanctum Labs — *Decode. Build. Evolve.*  
**Lead Engineer:** ANIKET NANDI (Kolkata, IST)  
**Component:** Compliance Evidence Engine  
**Module:** `backend/app/compliance/`  
**API Prefix:** `/v1/compliance`

---

## 1. Architectural Purpose & Boundaries

The **Compliance Evidence Engine** serves as PRIVGUARD AI's automated, cryptographically bound evidence collection, assessment, and export subsystem. Its primary function is to transform runtime telemetry, configuration state, cryptographic keys, and security enforcement events into tamper-evident compliance artifacts.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        PRIVGUARD AI CORE SUBSYSTEMS                    │
│  Canaries  •  KMS  •  Policy Governance  •  RLS  •  SBOM  •  Audit Log │
└────────────────────────────────────┬───────────────────────────────────┘
                                     │
                                     ▼ Automated Collector Layer
┌────────────────────────────────────────────────────────────────────────┐
│             EvidenceCollector (`app.compliance.evidence_collector`)    │
│  - Executes automated non-destructive telemetry & state probes         │
│  - Enforces allowlisted schema sanitization (strips all secrets/PII)   │
└────────────────────────────────────┬───────────────────────────────────┘
                                     │
                                     ▼ Freshness & Five-State Engine
┌────────────────────────────────────────────────────────────────────────┐
│         Freshness & Assessment Engine (`evidence_freshness.py`)        │
│  - Tracks TTL per evidence record (Default: 24h, Canaries: 1h)         │
│  - Computes 5-state assurance: Implementation, Verification, Freshness,│
│    Assurance Level, and Applicability Scoping                          │
└────────────────────────────────────┬───────────────────────────────────┘
                                     │
                                     ▼ Cryptographic Provenance Layer
┌────────────────────────────────────────────────────────────────────────┐
│             RFC 8785 JSON Canonicalization & Ed25519 Signing           │
│  - Computes SHA-256 fingerprint over JCS (RFC 8785) canonical bytes    │
│  - Signs audit manifests with KeyPurpose.EVIDENCE_SIGNING key pair     │
│  - Exposes unauthenticated public key at /signing-keys/public          │
└────────────────────────────────────┬───────────────────────────────────┘
                                     │
                                     ▼ Output & Export Boundaries
┌────────────────────────────────────────────────────────────────────────┐
│                 Audit Packages (JSON, CSV, Verifiable ZIP)             │
│  - manifest.json, manifest.sig, public_key.pem, verification.md        │
│  - Enforces prominent legal disclaimers: Technical evidence ≠ Legal cert│
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Subsystem Data Flows

### 2.1 Evidence Collection Flow
1. **Trigger:** Collection is initiated either via background schedule or an authenticated API call (`POST /v1/compliance/evidence/collect`).
2. **Execution:** `EvidenceCollector` runs dedicated probes across authoritative subsystems:
   - `collect_synthetic_canaries()`: Queries `CanaryRunner` execution history across all 8 security canaries.
   - `collect_kms_evidence()`: Inspects `KMSManager` for active KMS provider configuration, key rotation status, and health.
   - `collect_policy_evidence()`: Validates `PolicyGovernanceManager` bundle signature verification, active ruleset version, and downgrade prevention.
   - `collect_rls_evidence()`: Verifies database session tenant isolation and `FORCE RLS` on sensitive tables.
   - `collect_supply_chain_evidence()`: Checks machine-readable SBOM presence, Cosign container signing configuration, and SLSA provenance.
   - `collect_chaos_resilience_evidence()`: Ingests automated chaos test results and fault-injection circuit breaker status.
3. **Defense-in-Depth Sanitization:** All raw collector outputs are passed through `sanitize_payload()`:
   - Strict allowlisted dictionary keys.
   - High-entropy credential regex replacement (`[REDACTED_CREDENTIAL]`).
   - PII pattern neutralization (`[REDACTED_PII]`).
4. **Fingerprinting & Persistence:** An RFC 8785 canonical SHA-256 hash is computed and stored alongside the `ComplianceEvidenceRecord` with tenant scoping.

### 2.2 Freshness and Evaluation Flow
1. Each evidence record carries an explicit `valid_until` timestamp derived from its control's TTL policy.
2. When an assessment or gap analysis is requested, `EvidenceFreshnessEvaluator` determines the freshness state:
   - `CURRENT`: `now < valid_until`
   - `STALE`: `valid_until <= now < valid_until + grace_period`
   - `EXPIRED`: `now >= valid_until + grace_period`
3. Stale or expired evidence downgrades the overall **Assurance Level** to `LOW` or `INSUFFICIENT`, but **never** mutates the control's underlying **Implementation Status**.

---

## 3. Cryptographic Signing Boundaries

### 3.1 Key Purpose Isolation
To prevent cross-protocol attacks and privilege escalation:
- **Policy Governance** uses `KeyPurpose.POLICY_SIGNING`.
- **Action Approvals** use HMAC tokens with dedicated approval secrets.
- **Compliance Evidence & Exports** strictly use `KeyPurpose.EVIDENCE_SIGNING` (Ed25519).

### 3.2 Unauthenticated Public Key Export
Auditors and third-party inspectors must be able to verify exported audit packages without needing access to PRIVGUARD AI's database or internal network.
- Endpoint: `GET /v1/compliance/signing-keys/public`
- Response: PEM-encoded Ed25519 public key, Key ID (`kid`), algorithm identifier (`Ed25519`), purpose (`evidence_signing`), and validity status.

---

## 4. Legal & Regulatory Non-Equivalence Invariant

> [!IMPORTANT]
> **Technical Evidence Is Not Legal Certification.**  
> PRIVGUARD AI mathematically proves that specific engineering controls (encryption, RLS, tokenization, policy enforcement, canary probes) executed and satisfied technical criteria at a given timestamp. Technical evidence does not constitute legal counsel, formal statutory compliance, or an accredited third-party SOC 2 / ISO audit opinion.

