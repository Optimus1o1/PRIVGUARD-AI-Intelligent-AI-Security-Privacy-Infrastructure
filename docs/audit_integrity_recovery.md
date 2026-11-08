# PRIVGUARD AI — Audit Integrity & Evidence Preservation on Recovery

Organization: Moon Sanctum Labs  
Motto: *Decode. Build. Evolve.*  
Date: November 2026

---

## 1. Cryptographic Audit Chain Preservation

PRIVGUARD AI's compliance and audit records are content-free, SHA-256 fingerprint-bound records arranged in sequential hash chains. Following a disaster recovery restore:

1. **Gap Detection**:
   If continuous WAL archiving stopped at LSN $L_1$ and the primary crashed at $L_2 > L_1$, an uncommitted gap may exist.
   - The recovery reconciliation script compares the highest audit log sequence in PostgreSQL with the external hash chain index.
   - Any detected discrepancy emits Prometheus alert `PrivguardAuditLedgerDiscrepancy` and enters a containment quarantine.

2. **Compliance Evidence Signature Verification**:
   Compliance export archives generated under Stage 10.9 are signed with a dedicated Ed25519 key.
   - Restoring infrastructure does not invalidate generated compliance packages because their cryptographic signature is verified against the public key independent of local database state.
   - The offline SDK verifier (`privguard_sdk.verification.evidence`) can verify compliance archives even if the entire PRIVGUARD backend cluster is offline.

