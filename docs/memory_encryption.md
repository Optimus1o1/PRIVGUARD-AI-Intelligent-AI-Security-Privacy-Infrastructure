# PRIVGUARD AI — Memory Encryption & Cryptographic Architecture

*Moon Sanctum Labs — Decode. Build. Evolve.*

## 1. Cryptographic Specifications

PRIVGUARD implements enterprise-grade envelope encryption for all personal memories stored in the AI Memory Vault.

| Parameter | Specification | Purpose |
|---|---|---|
| **Cipher** | AES-256-GCM (Galois/Counter Mode) | Authenticated encryption providing confidentiality and integrity |
| **Key Size** | 256 bits (32 bytes) | High security margin against brute force attacks |
| **Nonce Size** | 96 bits (12 bytes) | Cryptographically secure random bytes per encryption |
| **Authentication Tag** | 128 bits (16 bytes) | Verifies ciphertext integrity and detects tampering |
| **KEK Derivation** | HKDF-SHA256 (RFC 5869) | Per-owner Key Encryption Key derived from Master Key + Owner ID |
| **DEK Wrapping** | AES-256-GCM | Encrypts Data Encryption Key under owner's KEK |
| **AAD Binding** | `memory_id:owner_id:category` | Binds ciphertext to tenant, user, category, and record ID |

---

## 2. Key Derivation Function (HKDF-SHA256)

User Key Encryption Keys (KEKs) are deterministically derived rather than stored on disk in plaintext:

$$\text{PRK} = \text{HMAC-SHA256}(\text{salt}=\text{"privguard\_kek\_salt\_v1"}, \text{IKM}=\text{MasterKey})$$
$$\text{KEK} = \text{HKDF-Expand}(\text{PRK}, \text{info}=\text{"privguard:memory:kek:"} \parallel \text{owner\_id} \parallel \text{":v"} \parallel \text{version}, \text{length}=32)$$

### Properties:
1. **User Isolation:** Each user has a cryptographically distinct KEK.
2. **Versioned Key Rotation:** Rotating a user's KEK increments `version`, deriving a completely distinct 256-bit key without altering the master key.
3. **No Key Storage on Disk:** KEKs are derived on demand in memory and never written to persistence.

---

## 3. Envelope Encryption Flow

```
Plaintext Memory Content
           |
           v
  +------------------+     AES-256-GCM (DEK)
  | Generate DEK     | -------------------------> Ciphertext (Encrypted Content)
  | 32 random bytes  |       AAD: id:owner:cat
  +------------------+
           |
           v
  +------------------+     AES-256-GCM (KEK)
  | Wrap DEK         | -------------------------> Wrapped DEK (Encrypted Key)
  | with Owner KEK   |       AAD: id:version
  +------------------+
```

### Encryption Payload Schema
When persisted to SQLite/Postgres in `MemoryRecord`, the record contains:
- `encrypted_content`: Base64-encoded AES-256-GCM ciphertext + 16-byte authentication tag.
- `nonce`: Base64-encoded 12-byte random initialization vector for data encryption.
- `wrapped_dek`: Base64-encoded DEK encrypted under user's KEK.
- `dek_nonce`: Base64-encoded 12-byte initialization vector for DEK encryption.
- `key_version`: Integer tracking the user KEK version (e.g. 1, 2, 3).
- `content_fingerprint`: SHA-256 hash of plaintext for integrity verification without exposing content.

---

## 4. Tamper Detection & Cryptographic Integrity

If any byte of `encrypted_content`, `nonce`, or `wrapped_dek` is modified:
1. AES-GCM tag verification fails immediately (`InvalidTag`).
2. PRIVGUARD catches the tag validation failure and raises `MemoryTamperingError`:
   - HTTP status: `403 Forbidden`
   - Error code: `MEMORY_INTEGRITY_COMPROMISED`
3. Decryption aborts instantly without returning corrupted or attacker-manipulated data.

### Splicing Prevention via AAD
Additional Authenticated Data (AAD) prevents database administrators or attackers from copying valid ciphertext from one record to another:
- `AAD_data = f"{memory_id}:{owner_id}:{category}"`
- If an attacker copies User A's encrypted record into User B's row, decryption under User B's owner ID fails AAD validation and raises `MemoryTamperingError`.

---

## 5. $O(1)$ Zero-Re-encryption Key Rotation

When a user triggers KEK rotation (`POST /v1/memory/key/rotate`):
1. PRIVGUARD derives new $\text{KEK}_{v+1}$.
2. For each active memory record:
   - Decrypts only `wrapped_dek` using $\text{KEK}_v$.
   - Re-encrypts `DEK` using $\text{KEK}_{v+1}$ with fresh `dek_nonce`.
   - Updates `wrapped_dek`, `dek_nonce`, and `key_version = v+1`.
3. The underlying `encrypted_content` ciphertext remains untouched on disk.
4. **Complexity:** $O(1)$ cryptographic work per record regardless of the size of stored memory documents.

---

## 6. Stage 10.5 Enterprise KMS Envelope Encryption (V2)

In Stage 10.5, PRIVGUARD elevated envelope encryption to provider-independent KMS architectures:
- **Cloud Providers:** DEK wrapping and unwrapping delegated to Hardware Security Modules in AWS KMS (`aws_kms`), Google Cloud KMS (`gcp_kms`), Azure Key Vault (`azure_key_vault`), or HashiCorp Vault (`vault_transit`).
- **Server-Side Native ReEncrypt:** For AWS KMS and HashiCorp Vault, key rotation uses native server-side rewrapping without DEK plaintext exposure to application memory.
- **Tenant Isolation Context (AAD):** `AAD_v2 = f"{tenant_id}:{owner_id}:{memory_id}:{category}:v2"`.
- **Non-Destructive V1-to-V2 Migration:** Legacy Stage 7 HKDF records are migrated to V2 KMS envelopes by rewrapping DEKs while preserving 100% of the original content ciphertext and nonces. Dual-AAD fallback ensures zero downtime and backward compatibility.
- **Retirement Invariants:** The legacy master key cannot be deleted or retired until all unmigrated records and active database backup retention windows have elapsed.


