# PRIVGUARD AI — Evidence Provenance, RFC 8785 Hashing & Signing

**Agency:** Moon Sanctum Labs — *Decode. Build. Evolve.*  
**Lead Engineer:** ANIKET NANDI (Kolkata, IST)  
**Module:** `backend/app/compliance/evidence_integrity.py`  
**Reference Date:** November 2026

---

## 1. Provenance Architecture & Non-Repudiation

Compliance evidence must withstand adversarial scrutiny. If an evidence record or exported snapshot could be modified after generation without detection, it would have zero legal or forensic value.

PRIVGUARD AI establishes end-to-end provenance via:
1. **RFC 8785 JSON Canonicalization Scheme (JCS):** Guarantees that equivalent JSON structures always serialize to identical byte sequences regardless of key ordering or whitespace.
2. **SHA-256 Digest Fingerprints:** Generated over canonical JSON bytes for structured telemetry and binary bytes for raw artifacts.
3. **Dedicated Ed25519 Digital Signatures:** Produced using an isolated, dedicated private key under `KeyPurpose.EVIDENCE_SIGNING`.
4. **Detached Manifest Signatures:** Manifests are packaged with detached signature files (`manifest.sig`) and the active public verification key (`public_key.pem`).

---

## 2. RFC 8785 Canonical Serialization

JSON serializations in standard libraries vary by dictionary iteration order, float representation, and whitespace formatting. To eliminate non-determinism, PRIVGUARD AI implements RFC 8785 JCS:
- Object keys are sorted lexicographically by their UTF-16 code units.
- Whitespace between separators (`:`, `,`) is eliminated.
- Unicode characters are handled strictly according to JSON specification.

### 2.1 Hashing Workflow
```python
# RFC 8785 canonical hash computation
canonical_bytes = canonical_json_bytes(payload)
sha256_fingerprint = hashlib.sha256(canonical_bytes).hexdigest()
```

---

## 3. Dedicated Key Isolation (`KeyPurpose.EVIDENCE_SIGNING`)

PRIVGUARD AI enforces cryptographic separation of duty between operational keys and compliance evidence signing keys:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        SigningKeyManager Registry                      │
├────────────────────────┬───────────────────────┬───────────────────────┤
│ KeyPurpose             │ Algorithm             │ Usage                 │
├────────────────────────┼───────────────────────┼───────────────────────┤
│ POLICY_SIGNING         │ Ed25519               │ Governance Bundles    │
│ EVIDENCE_SIGNING       │ Ed25519 (Dedicated)   │ Compliance Manifests  │
│ APPROVAL_SECRET        │ HMAC-SHA256           │ Human Action Approvals│
└────────────────────────┴───────────────────────┴───────────────────────┘
```

The evidence signing private key is generated on first startup or retrieved from secure KMS backend storage. It is strictly forbidden from signing policy bundles or decrypting memory vaults.

---

## 4. Manifest Signing & Verification Invariant

When an audit package is generated:
1. An audit manifest dictionary is constructed containing framework IDs, control list, evidence record hashes, export timestamps, and tenant scoping.
2. The active `signing_kid` is injected into the manifest.
3. The `signature` property is explicitly excluded before computing canonical bytes:
   $$\text{canonical\_bytes} = \text{RFC8785}(\text{manifest} \setminus \{\text{"signature"}\})$$
4. The Ed25519 signature is generated across `canonical_bytes` and placed into both the signed manifest object and `manifest.sig`.
5. External verification performs the identical operation using the public key:
   $$\text{verify}(\text{public\_key}, \text{canonical\_bytes}, \text{signature}) \to \text{True}$$

---

## 5. Public Key Distribution

External auditors, regulatory bodies, and compliance tools can retrieve the current public verification key without authentication:

```http
GET /v1/compliance/signing-keys/public HTTP/1.1
Host: privguard.internal
```

### Example Response:
```json
{
  "kid": "ev-sig-202611-001",
  "purpose": "evidence_signing",
  "algorithm": "Ed25519",
  "public_key_hex": "b5a93...04f2",
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA...\n-----END PUBLIC KEY-----\n",
  "is_active": true,
  "created_at": "2026-11-07T12:00:00Z"
}
```
Auditors can independently verify exported ZIP bundles using standard OpenSSL, Python `cryptography`, or Node.js `crypto` utilities.

