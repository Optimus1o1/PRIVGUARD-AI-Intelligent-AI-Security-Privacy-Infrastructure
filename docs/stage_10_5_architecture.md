# PRIVGUARD AI — Stage 10.5 Architecture Specification
## Enterprise Secrets Management & Cryptographic Key Lifecycle Infrastructure

**Organization:** Moon Sanctum Labs — *Decode. Build. Evolve.*  
**Author:** Aniket Nandi (Kolkata, IST)  
**Status:** Implemented & Verified  
**Milestone:** Stage 10.5  

---

### 1. Executive Summary

Stage 10.5 establishes a provider-independent cryptographic key management and enterprise secrets infrastructure for PRIVGUARD AI. It decouples data encryption keys (DEKs), key encryption keys (KEKs), asymmetric policy signing keys, and approval action binding HMAC secrets. This prevents single-master-key compromise cascading across application subsystems, guarantees zero plaintext credential leakage, and enables cloud-neutral deployments across AWS KMS, GCP Cloud KMS, Azure Key Vault, HashiCorp Vault Transit, and isolated development environments.

```
                              +---------------------------------------+
                              |         PRIVGUARD APPLICATION         |
                              +---------------------------------------+
                                                  |
                                                  v
                              +---------------------------------------+
                              |       KMS & CRYPTOGRAPHIC ENGINE      |
                              +---------------------------------------+
                                 /                |                \
                                /                 |                 \
                               v                  v                  v
         +-----------------------+   +-----------------------+   +-----------------------+
         |   ENVELOPE ENCRYPTION |   |  POLICY SIGNING (KID) |   |  APPROVAL HMAC ENGINE |
         |   AES-256-GCM DEK/KEK |   |  Ed25519 Asymmetric   |   |  Decoupled HMAC-SHA256|
         +-----------------------+   +-----------------------+   +-----------------------+
                     |                            |                            |
                     v                            v                            v
         +-----------------------+   +-----------------------+   +-----------------------+
         | Personal Memory Vault |   | Signed Policy Bundles |   | Dual-Token Approvals  |
         +-----------------------+   +-----------------------+   +-----------------------+
```

---

### 2. Core Architectural Pillars

1. **Separation of Keys & Lifecycles:**
   - **Data Encryption Keys (DEKs):** Ephemeral 256-bit AES-GCM keys generated per record (`os.urandom(32)`). Never stored unencrypted.
   - **Key Encryption Keys (KEKs):** Master wrapping keys maintained in external KMS or local vault. Versioned and independently rotated.
   - **Policy Signing Keys:** Ed25519 asymmetric keypairs. Public keys recorded in tamper-evident database; private keys held securely for bundle publication.
   - **Approval Action Binding Keys:** Versioned HMAC-SHA256 secrets decoupled from data encryption keys, preventing approval forgery even under data key exposure.

2. **Provider Neutrality:**
   A unified `KMSProvider` interface with synchronous and asynchronous operations abstracts cloud specifics:
   - `local`: Development/testing provider with HKDF-SHA256 derivation and AES-256-GCM wrapping.
   - `aws_kms`: Production AWS KMS driver with native server-side `ReEncrypt` API support.
   - `gcp_kms`: Google Cloud KMS Cloud Key Management adapter.
   - `azure_key_vault`: Azure Key Vault Cryptography Client adapter.
   - `vault_transit`: HashiCorp Vault Transit engine adapter with `/transit/rewrap`.

3. **Production Invariants:**
   - In production environments (`ENVIRONMENT=production`), the `local` KMS provider is strictly rejected during startup.
   - Application secrets metadata records (`SecretMetadataRecord`) strictly prohibit plaintext storage.
   - Master legacy key cannot be retired or deleted as long as unmigrated Stage 7 V1 records exist in the database or active backup retention window.

---

### 3. Subsystem Breakdown

| Subsystem | Modules | Primary Role |
| :--- | :--- | :--- |
| **KMS Abstraction** | `app.key_management.base`, `manager`, `registry`, `providers` | Unified interface for key wrapping, unwrapping, rewrapping, and status verification. |
| **Envelope Crypto Engine** | `app.memory.crypto` | Dual-mode V1 (legacy HKDF) and V2 (KMS envelope) encryption/decryption with authenticated context binding (AAD). |
| **Legacy Migrator** | `app.key_management.migration` | Non-destructive V1-to-V2 DEK rewrapping preserving ciphertext, nonce, and content fingerprint. |
| **Rotation Engine** | `app.key_management.rotation` | State machine driven key version rotation (`ACTIVE` -> `ROTATING` -> `ACTIVE`), background DEK rewrapping, and CAS concurrency control. |
| **Signing Manager** | `app.key_management.signing` | Ed25519 keypair generation and verification, versioned `kid` HMAC approval binding. |
| **Secrets Manager** | `app.secrets.manager`, `base`, `providers` | Metadata-only tracking of operational credentials, rotation scheduling, and revocation without plaintext exposure. |
| **Compromise Manager** | `app.key_management.compromise` | Incident response workflows for DEK, KEK, signing key, and HMAC key compromises. |
| **Control Dashboard** | `frontend/app/security/...` | Next.js 14 UI for keys inventory, version lineage, rotation tracking, secret metadata, and incident containment. |
