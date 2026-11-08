# PRIVGUARD AI — Stage 10.11 Preflight Findings & Carry-Over Resolution

**Organization**: Moon Sanctum Labs  
**Motto**: Decode. Build. Evolve.  
**Lead Engineer**: Aniket Nandi (Kolkata, IST)  
**Baseline Commit**: `16c0ed5`  
**Date**: November 8, 2026  

---

## 1. Executive Summary

Prior to beginning implementation of **Stage 10.11: Disaster Recovery & Production Validation**, a comprehensive preflight audit of the codebase, Git baseline, and Stage 10.10 deliverables was conducted. 

Three specific carry-over items identified in the milestone review were inspected:
1. Python version compatibility in `privguard-sdk` metadata and CI workflows.
2. Performance latency assertion modifications in `backend/tests/test_performance_stage_3.py`.
3. Security boundaries, trust separation, and malicious ZIP defenses in the offline compliance verifier (`privguard_sdk.verification`).

All three items have been investigated, with concrete remediation paths detailed below.

---

## 2. Preflight Item 1: Python Compatibility Mismatch

### Inspection Findings
- In `sdk/python/pyproject.toml`:
  - Line 11 specifies `requires-python = ">=3.10"`.
  - Classifiers include `"Programming Language :: Python :: 3.10"`.
- In `.github/workflows/sdk-ci.yml`:
  - The test matrix runs `python-version: ["3.10", "3.11", "3.12", "3.13"]`.

### Context & Remediation
- Python 3.10 officially reached end-of-life on October 1, 2026. Supporting an EOL runtime introduces dependency vulnerability risks and prevents modern typing adoption.
- In 2026, Python 3.11, 3.12, 3.13, and 3.14 are active supported versions.
- **Action Required**:
  1. Update `sdk/python/pyproject.toml` to set `requires-python = ">=3.11"`.
  2. Remove Python 3.10 classifier and add Python 3.14 (validated on dependencies `httpx`, `pydantic`, `cryptography`).
  3. Update `.github/workflows/sdk-ci.yml` matrix to `["3.11", "3.12", "3.13", "3.14"]`.
  4. Rebuild wheel and update distribution metadata.

---

## 3. Preflight Item 2: Performance Regression Test Modification

### Git Diff Inspection (`1ee1fcd` vs `16c0ed5`)
```diff
--- a/backend/tests/test_performance_stage_3.py
+++ b/backend/tests/test_performance_stage_3.py
@@ -76,6 +76,6 @@ async def test_stage_3_latency_benchmarks(
     )
 
     assert hash_p95 < 1.0  # sub-millisecond
-    assert cap_p95 < 250.0
-    assert exec_p95 < 400.0
+    assert cap_p95 < 600.0  # bounded capability issuance under full-suite load
+    assert exec_p95 < 800.0
```

### Empirical Analysis & Benchmark Findings
- When `test_stage_3_latency_benchmarks` is run in **isolation**, the benchmark results are:
  - **Action Hash P95**: `0.0225 ms` (limit `< 1.0 ms`) — **PASSED**
  - **Capability Issuance P95**: `102.71 ms` (limit `< 250.0 ms`) — **PASSED**
  - **Tool Broker Exec P95**: `195.76 ms` (limit `< 400.0 ms`) — **PASSED**
- During full-suite execution of all 406 backend tests running sequentially in a single process across 11 minutes on Windows with SQLite, thread scheduling and database file lock contention caused temporary latency spikes (`cap_p95` reached 440ms, `exec_p95` reached 486ms).
- Rather than widening thresholds, the proper engineering fix is:
  1. Add an explicit warmup and garbage collection sweep prior to timing loops.
  2. Restore the original strict thresholds: `cap_p95 < 250.0` and `exec_p95 < 400.0`.
  3. This ensures the original performance contract remains 100% intact without false test failures under suite load.

---

## 4. Preflight Item 3: SDK Offline Verifier Security & Trust Model

### Inspection of `privguard_sdk/verification/evidence.py`
A thorough code review of `evidence.py` and `manifests.py` identified four critical security improvements required for production-grade verification:

1. **Conflation of Cryptographic Signature Validity with Identity Trust**:
   - Currently, if `allow_embedded_key=True` is passed without an explicit `trusted_public_key`, `verify_export_package()` verifies mathematical consistency and returns `is_valid=True` with a warning.
   - **Fix**: An embedded public key inside an untrusted ZIP archive proves only self-consistency; it cannot prove authenticity. We must decouple `signature_valid` from `trust_verified`. The package is only `is_valid=True` when verified against an explicitly supplied, trusted public key (`trusted_public_key`). Embedded keys can only yield `is_valid=False, signature_valid=True, trust_verified=False` with `errors=["Embedded key verification provides self-consistency only; identity is UNTRUSTED"]`.

2. **Malicious ZIP & Path Traversal Protections**:
   - Currently, `zf.namelist()` paths are joined with `base_dir` without validating against directory traversal sequences (`..`, leading `/`, or absolute Windows paths `C:\`).
   - **Fix**: Reject any archive containing paths with `..`, leading slashes, backslashes, or control characters.

3. **Unmanifested & Extraneous Artifact Rejection**:
   - Currently, the verifier iterates through `manifest.artifact_hashes`. Any extraneous files in the ZIP archive (e.g. injected executable scripts or unmanifested trojans) are ignored.
   - **Fix**: The archive must be strictly closed-world: every file in the ZIP archive must be explicitly accounted for (either listed in `manifest["artifact_hashes"]`, `manifest.json`, or `public_key.pem`). Any unexpected or unmanifested files fail verification immediately (`errors=["Unmanifested file found in archive: '<path>'"]`).

4. **Decompression Bomb & Size Quota Defenses**:
   - Maliciously crafted ZIP archives (zip bombs) can exhaust memory during `zf.read()`.
   - **Fix**: Enforce strict size limits:
     - Maximum archive uncompressed total size: 100 MB.
     - Maximum single artifact uncompressed size: 50 MB.
     - Maximum compression ratio check (reject if uncompressed/compressed ratio > 100:1).
     - Reject duplicate filenames in ZIP header.

---

## 5. Existing Repository Recovery Inventory

An inspection of `backend/app/`, `deploy/`, and `scripts/` confirmed:
- **PostgreSQL**: Authoritative for all relational data (Tenants, Applications, Agents, Tasks, Capabilities, Approvals, Memory Records, Compliance Controls, Outbox, Managed Keys). No existing backup scripts exist.
- **Redis**: Used for rate limiting (`rl:`), distributed taint tracking (`taint:`), policy sync (`policy:`), revocation broadcast (`revocations:`), and outbox event bus (`stream:events`).
- **KMS / Keys**: Multi-provider KMS abstraction (`AWSKMSProvider`, `GCPKMSProvider`, `LocalKMSProvider`), envelope encryption (`AES-256-GCM`), and dedicated Ed25519 signing keys.
- **Memory Erasure**: In `backend/app/memory/vault.py`, `delete_memory()` overwrites record fields (`[CRYPTOGRAPHICALLY_ERASED]`, `[DEK_DESTROYED]`). Restoring an older PostgreSQL base backup without anti-resurrection reconciliation would restore previous ciphertext and wrapped DEK.
- **Tooling**: Zero backup/restore scripts currently exist in the repository.

---

## 6. Action Plan for Stage 10.11

1. Apply preflight fixes (Python 3.11+ SDK metadata, strict performance benchmark contract, hardened offline verifier).
2. Design and implement the Disaster Recovery Architecture and anti-resurrection reconciliation engine.
3. Build native PostgreSQL and Redis backup/restore tooling with cryptographic manifests in `scripts/recovery/`.
4. Implement isolated recovery and chaos test suite in `backend/tests/recovery/`.
5. Produce complete documentation suite and runbooks in `docs/`.

