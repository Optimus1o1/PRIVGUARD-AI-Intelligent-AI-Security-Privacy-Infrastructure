# PRIVGUARD AI — Memory Retention, Expiration & Cryptographic Erasure

*Moon Sanctum Labs — Decode. Build. Evolve.*

## 1. Regulatory Alignment (GDPR, CCPA & Right to be Forgotten)

Modern privacy regulations and enterprise security frameworks require that personal data processed by AI systems can be:
- Retained for no longer than necessary.
- Transparently audited and inspected by the data subject.
- Permanently and irreversibly deleted upon request.

PRIVGUARD AI's Personal AI Memory Vault satisfies these principles through automated retention policies and cryptographic erasure.

---

## 2. Retention Policies & Automated Expiration

Each memory entry can specify an optional `retention_days` parameter (1 to 3650 days):
- `expires_at = created_at + timedelta(days=retention_days)`
- When a retrieval query encounters an expired record (`expires_at < now`):
  1. The record's status is automatically updated to `EXPIRED`.
  2. The record is excluded from all search and retrieval results.
  3. No plaintext is decrypted or exposed.

---

## 3. Cryptographic Erasure Mechanics

Unlike standard relational database row deletions (where data remains in write-ahead logs, deleted page blocks, or backup snapshots), PRIVGUARD implements **Cryptographic Erasure**:

```python
# 1. Update status
record.status = "DELETED"

# 2. Overwrite and destroy the Data Encryption Key (DEK)
record.wrapped_dek = "[DEK_DESTROYED]"
record.dek_nonce = "[WIPED]"

# 3. Overwrite ciphertext and nonce
record.encrypted_content = "[CRYPTOGRAPHICALLY_ERASED]"
record.nonce = "[WIPED]"

# 4. Commit atomic wipe
await db.commit()
```

### Security Guarantee
Because the per-record DEK is destroyed:
1. Even if raw database pages or disk forensics recover the previous ciphertext bytes, **decryption is mathematically impossible**.
2. Neither PRIVGUARD administrators, database operators, nor compromised infrastructure can reconstruct the original plaintext.

---

## 4. Complete Vault Purge (Right to be Forgotten)

Users can initiate a complete purge of their Personal AI Memory Vault via the Control Center or the API (`POST /v1/memory/purge`):

```
User Requests Account Purge
           |
           v
  +-----------------------------------------------------+
  | 1. Create Audited Deletion Job (Status: PROCESSING) |
  +-----------------------------------------------------+
           |
           v
  +-----------------------------------------------------+
  | 2. Iterate All Active & Archived User Records        |
  |    - Overwrite Ciphertext -> [CRYPTOGRAPHICALLY_ERASED]|
  |    - Destroy Wrapped DEK -> [DEK_DESTROYED]         |
  |    - Overwrite Nonces -> [WIPED]                    |
  |    - Set Status -> DELETED                          |
  +-----------------------------------------------------+
           |
           v
  +-----------------------------------------------------+
  | 3. Mark Deletion Job COMPLETED                      |
  |    - Log Content-Free Audit Event                   |
  +-----------------------------------------------------+
```

### Safety Protections:
- **UI Confirmation:** The frontend requires typing `"DELETE ALL MEMORIES"` exactly before the purge button is enabled.
- **Tenant Scoping:** The purge strictly wipes records matching the authenticated user ID and application ID.

