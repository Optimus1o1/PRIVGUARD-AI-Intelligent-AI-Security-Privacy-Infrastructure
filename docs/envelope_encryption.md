# PRIVGUARD AI — Envelope Encryption Specification
## Multi-Tenant AES-256-GCM Envelope Encryption

**Organization:** Moon Sanctum Labs — *Decode. Build. Evolve.*  
**Author:** Aniket Nandi (Kolkata, IST)  
**Baseline:** Stage 10.5  

---

### 1. Overview

PRIVGUARD AI protects personal AI memories using a two-tier envelope encryption architecture:
1. **Data Encryption Key (DEK):** An ephemeral, randomly generated 256-bit AES-GCM key encrypts the record plaintext payload.
2. **Key Encryption Key (KEK):** The DEK is encrypted (wrapped) under a managed KEK residing in a KMS provider.

```
Plaintext Content + Nonce + AAD
           |
           v
   +------------------+
   | AES-256-GCM Enc  | <--- Fresh 256-bit DEK (os.urandom)
   +------------------+
           |
           v
    Ciphertext Payload
           +
   +------------------+
   | KMS KEK Wrap     | <--- Managed KEK (AWS KMS / GCP / Vault)
   +------------------+
           |
           v
    Wrapped DEK (Base64)
```

---

### 2. Envelope Formats: V1 vs V2

| Attribute | Stage 7 V1 Format (`v1_legacy`) | Stage 10.5 V2 Format (`v2_kms`) |
| :--- | :--- | :--- |
| **KEK Derivation** | HKDF-SHA256 from local master key + user salt | Managed KMS provider (`local`, `aws_kms`, `gcp_kms`, `vault_transit`) |
| **DEK Wrapping** | Local AES-256-GCM under user KEK | KMS Provider `wrap_key` API |
| **Authenticated Data (AAD)** | `{memory_id}:{owner_id}:{category}` | `{tenant_id}:{owner_id}:{memory_id}:{category}:v2` |
| **DEK AAD Binding** | `wrapped_dek:{memory_id}:{key_version}` | `tenant_id={tenant_id}, purpose=memory_dek, version={ver}` |
| **Key ID Tracking** | None (`NULL`) | Explicit `key_id` referencing `ManagedKey` |
| **Content Fingerprint** | SHA-256 hex of plaintext | SHA-256 hex of plaintext |

---

### 3. Nonce Generation & Unique DEK Invariant

- **Ciphertext Nonce:** Exactly 12 bytes (96 bits) generated cryptographically randomly (`os.urandom(12)`) per encryption operation.
- **DEK Nonce:** 12 bytes generated cryptographically randomly for local wrapping. For external cloud providers (AWS KMS, GCP KMS), IV/nonce is managed internally by the provider's HSM.
- **Unique DEK Guarantee:** Every record encryption generates a new DEK. Encrypting the exact same plaintext string twice produces two distinct DEKs, two distinct wrapped DEKs, and two distinct ciphertexts.

---

### 4. Authenticated Context Binding (AAD)

Decryption enforces strict Additional Authenticated Data verification. Any attempt to modify:
- `tenant_id` (cross-tenant access attempt)
- `owner_id` (cross-user access attempt)
- `memory_id` (memory ID collision / injection)
- `category` (category elevation / classification tampering)

will trigger an immediate `MemoryTamperingError` during AES-GCM tag verification.

#### Non-Destructively Migrated Records & Dual-AAD Fallback
When a record has been migrated from V1 to V2 via DEK rewrapping without re-encrypting the underlying payload:
- The data ciphertext remains authenticated with the V1 AAD.
- The V2 decryptor first attempts decryption with the V2 AAD.
- If an `InvalidTag` exception is caught, it falls back to the V1 AAD using the unwrapped DEK.
- If both fail, `MemoryTamperingError` is raised. This allows 100% data preservation during migration without risk of tampering.
