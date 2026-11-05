# PRIVGUARD AI — Legacy Key Migration & Retirement Policy
## Non-Destructive Stage 7 V1 to V2 KMS Envelope Migration

**Organization:** Moon Sanctum Labs — *Decode. Build. Evolve.*  
**Author:** Aniket Nandi (Kolkata, IST)  
**Baseline:** Stage 10.5  

---

### 1. The Migration Challenge

Stage 7 introduced personal memory vault encryption using an HKDF-SHA256 user key derivation model rooted in `PRIVGUARD_MASTER_KEY`. Stage 10.5 transitions this to provider-independent KMS envelope encryption.

Because personal memory vaults may contain millions of entries:
1. Re-encrypting content payloads would introduce unacceptable I/O latency, CPU load, and risk of data loss.
2. An all-at-once migration would lock the database.
3. Premature deletion of the Stage 7 master key would permanently destroy historical backups and unmigrated records.

---

### 2. Non-Destructive Rewrapping Architecture

The `LegacyMemoryMigrator` achieves non-destructive migration by decoupling the DEK from the payload:

1. **Read V1 Record:** Loads `encrypted_content`, `nonce`, and `wrapped_dek`.
2. **Unwrap DEK with Legacy Provider:** Decrypts `wrapped_dek` using the legacy user KEK derived from `PRIVGUARD_MASTER_KEY` and the Stage 7 AAD.
3. **Wrap DEK with Target KMS KEK:** Wraps the exact same 256-bit DEK under the tenant's new KMS KEK (`key_id`).
4. **Compare-And-Swap Database Update:**
   ```python
   # record.encrypted_content is NOT changed
   # record.nonce is NOT changed
   # record.content_fingerprint is NOT changed
   cas_update = (
       update(MemoryRecord)
       .where(MemoryRecord.id == record.id, MemoryRecord.version == record.version)
       .values(
           wrapped_dek=new_wrapped_dek_b64,
           dek_nonce=new_dek_nonce_b64,
           key_version=new_key_version,
           encryption_format="V2",
           key_id=key_id,
           version=record.version + 1,
           updated_at=utcnow(),
       )
   )
   ```
5. **Immediate Decryption Verification:** Before checkpointing the record as migrated, `LegacyMemoryMigrator` executes a test decryption using `EnvelopeEncryption.decrypt()` to guarantee mathematical recoverability.

---

### 3. Legacy Key Retirement Policy & Safeguards

PRIVGUARD AI implements an automated safeguard against premature master key destruction:

1. **Database Check:**
   `legacy_migrator.can_retire_legacy_key(db, tenant_id)` queries for any records where `encryption_format == 'V1'` or `encryption_format IS NULL`.
   - If `count > 0`: System strictly blocks key retirement, returning:
     `Cannot retire legacy key: {count} unmigrated V1 records exist in active database.`
   - If `count == 0`: Retirement is permitted for active records, with a mandatory warning regarding historical backup retention.

2. **Backup Retention Requirement:**
   Even when active database records are 100% migrated to V2, `PRIVGUARD_MASTER_KEY` must be archived in cold vault storage until all database backups containing V1 records have expired according to the enterprise retention schedule (e.g. 90, 180, or 365 days).
