# PRIVGUARD AI — Key Management & KMS Disaster Recovery

Organization: Moon Sanctum Labs  
Motto: *Decode. Build. Evolve.*  
Date: November 2026

---

## 1. Cryptographic Key Custody & Architecture

PRIVGUARD AI maintains independent cryptographic key hierarchies to prevent cross-domain compromise:

| Key Role | Purpose | Algorithm | Custody & Rotation |
| :--- | :--- | :--- | :--- |
| **Root Master Key (KEK)** | Envelope encryption of DEKs | AES-256-GCM / AWS KMS / GCP KMS | Cloud KMS / HSM with automatic annual rotation. |
| **Audit Ledger Key** | Hash-chain block signing | Ed25519 | Dedicated HSM key with 90-day rotation. |
| **Compliance Export Key** | Signing ZIP evidence archives | Ed25519 | Dedicated compliance signing key. |
| **Backup Signing Key** | Signing base backup manifests | Ed25519 (`KeyPurpose.BACKUP_SIGNING`) | Dedicated air-gapped backup key. |

---

## 2. Multi-Provider KMS Failover

If the primary KMS provider becomes unavailable:
1. **Secondary KMS Failover**: PRIVGUARD supports automatic failover between AWS KMS, Google Cloud KMS, and HashiCorp Vault.
2. **Encrypted DEKs**: Data Encryption Keys (DEKs) wrapped under the primary KEK can be re-wrapped under the secondary KEK using the key rotation workflow (`POST /v1/kms/rotate`).
3. **Emergency Key Custody Break-Glass**: In the event of complete cloud provider outage, recovery operators can inject an offline emergency Master Key via dual-authorized break-glass ceremony.

