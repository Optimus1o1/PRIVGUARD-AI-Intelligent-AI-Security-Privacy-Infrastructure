# PRIVGUARD AI — Python SDK Security Architecture & Safeguards

**Organization**: Moon Sanctum Labs  
**Motto**: Decode. Build. Evolve.  
**Package**: `privguard-sdk` (import: `privguard_sdk`)  
**Specification Version**: 1.0.0 (SDK Version: 0.1.0)  

---

## 1. Security Invariants & Client Boundary

The `privguard-sdk` operates under a zero-trust model with respect to client-side code:

1. **Server-Side Enforcement Invariant**:  
   The client SDK contains zero authorization bypasses, mock evaluations, or local capability validations. All tokens, signatures, policies, and permissions are evaluated and enforced exclusively on PRIVGUARD AI server instances.
2. **Deterministic Immutability**:  
   Once constructed, client configuration parameters (base URL, timeouts, SSL verification) remain immutable during request lifecycles.
3. **No Unencrypted Credential Serialization**:  
   The SDK will never serialize raw API keys, bearer tokens, or decrypted user memory to disk or unauthenticated logging frameworks.

---

## 2. Credential Protection & Redaction Safeguards

### String Representation Masking

API keys inadvertently printed in logs or debugging output represent a serious security hazard. The SDK enforces masking in `__repr__()`:

```python
config = PrivGuardConfig(api_key="sk-live-1234567890abcdef")
print(config)
# Output: PrivGuardConfig(base_url='http://localhost:8000', api_key='sk-l...cdef', ...)
```

- Keys longer than 8 characters: Exposes the first 4 characters and the last 4 characters, with `'...'` in between.
- Keys with 8 characters or fewer: Replaced entirely with `'***'`.
- Missing keys: Evaluated as `None`.

---

## 3. Network Security & SSRF Defenses

### TLS Verification Enforced by Default

The SDK defaults to `verify_ssl=True` across all environments. Certificate authority bundles are loaded from Python's standard `certifi` package. Disabling TLS validation emits warnings and is prohibited in production builds.

### Redirection Defense (`follow_redirects=False`)

HTTP redirects (`301`, `302`, `307`, `308`) can be exploited in Server-Side Request Forgery (SSRF) attacks or can inadvertently leak `Authorization: Bearer` headers to untrusted downstream origins. The SDK enforces `follow_redirects=False` across both synchronous and asynchronous transports.

---

## 4. Offline Cryptographic Evidence Verification

The `privguard_sdk.verification` package provides complete offline verification of compliance export archives (`.zip`) created by PRIVGUARD AI.

### Cryptographic Guarantees

1. **RFC 8785 Canonical JSON Serialization**:  
   Standard `json.dumps()` is non-deterministic (key order, floating point representation, ASCII escaping). The SDK implements RFC 8785 canonical serialization:
   - Object keys sorted by UTF-16 code units.
   - Whitespace completely stripped (`separators=(',', ':')`).
   - UTF-8 encoding without byte-order marks.
2. **SHA-256 Digest Integrity**:  
   Every file listed in `manifest["artifacts"]` is hashed with SHA-256 and matched against its recorded digest. Any modification, truncation, or file addition fails verification.
3. **Ed25519 Signature Verification**:  
   The manifest includes a signature over its own canonical representation (with the signature field omitted). The SDK verifies this signature against the organization's public key using `cryptography.hazmat.primitives.asymmetric.ed25519`.

### Standalone Python Verification Script

```python
from privguard_sdk import verify_export_package

# Load trusted public key (from secure storage, KMS, or PKI)
with open("trusted_compliance_ed25519.pub", "rb") as f:
    trusted_public_key = f.read()

# Verify exported bundle completely offline
result = verify_export_package(
    zip_path_or_bytes="privguard_compliance_export_2026-11-08.zip",
    trusted_public_key=trusted_public_key,
)

if result.is_valid:
    print(f"VERIFIED: Export {result.export_id} is authentic and untampered.")
    print(f"Artifacts checked: {len(result.artifacts_verified)}")
    print(f"Signed by: {result.signer_identity}")
else:
    print("VERIFICATION FAILED:")
    for error in result.errors:
        print(f" - {error}")
```

