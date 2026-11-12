# PRIVGUARD AI — Automated Key Rotation Specification
## Lifecycle Transitions, Non-Destructive DEK Rewrapping & CAS Concurrency

**Organization:** Moon Sanctum Labs — *Decode. Build. Evolve.*  
**Author:** Aniket Nandi (Kolkata, IST)  
**Baseline:** Stage 10.5  

---

### 1. Key State Machine

Every `ManagedKey` and its associated `KeyVersion` records follow a strict deterministic lifecycle:

```
[ CREATED ] ---> [ ACTIVE ] ---> [ ROTATION_PENDING ] ---> [ ROTATING ] ---> [ VERIFYING ] ---> [ RETIRED ]
     |                |                                                                             ^
     |                +-----------------------> [ COMPROMISED ] ------------------------------------+
     v
[ DESTROYED ]
```

- **`ACTIVE`:** Currently utilized for wrapping new DEKs and decrypting existing data.
- **`ROTATION_PENDING`:** New active version provisioned; existing version retired for new writes but active for read/rewrap.
- **`ROTATING`:** Asynchronous batch worker actively rewrapping dependent record DEKs under the new KEK version.
- **`VERIFYING`:** Validation pass confirming that all records can be decrypted under the new key version.
- **`RETIRED`:** All records rewrapped to a newer version. Key remains available in read-only mode for historical backups.
- **`COMPROMISED`:** Declared compromised during security incident. Immediately revoked for all operations.

---

### 2. Automated Rotation Engine Workflow

1. **Triggering Rotation:** Initiated via schedule (e.g., 90 days), manually via `POST /v1/keys/{id}/rotate`, or via emergency incident declaration.
2. **Version Creation:** Provider advances version (`v_next`). A new `KeyVersion` row is inserted in database.
3. **Write Path Switch:** `ManagedKey.active_version_id` points immediately to the new version. All new memory records are encrypted under `v_next`.
4. **Batch Rewrapping Job:** A `KeyRotationJob` tracks the progress of rewrapping existing records in chunks (default 50 records).
5. **Non-Destructive Rewrap:** The worker unwraps the DEK from `v_prev` and rewraps it under `v_next` (or calls native server-side `ReEncrypt`). The memory content ciphertext and nonce are completely untouched.
6. **Optimistic Concurrency Control (CAS):**
   ```sql
   UPDATE memory_records
   SET wrapped_dek = :new_wrapped_dek,
       dek_nonce = :new_dek_nonce,
       key_version = :new_version,
       version = version + 1
   WHERE id = :id AND version = :current_version;
   ```
   If a concurrent update modified the record, rowcount is 0, preventing race conditions or overwritten data.
7. **Retirement:** Once all records have been migrated and verified, `ManagedKey.status` returns to `ACTIVE`, and the old `KeyVersion` is marked `RETIRED`.
