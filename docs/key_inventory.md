# PRIVGUARD AI — Cryptographic Key & Secrets Inventory
## Classification, Ownership, Storage & Lifecycle Guarantees
**Agency**: Moon Sanctum Labs — *Decode. Build. Evolve.*  
**Milestone**: Stage 10.5  
**Version**: 1.0  
**Classification**: Enterprise Security Architecture Document  

---

## 1. Executive Summary

This document establishes the official cryptographic key and operational secrets inventory for PRIVGUARD AI. Every secret and cryptographic material utilized within the system is inventoried, classified, and assigned an explicit lifecycle, ownership boundary, rotation policy, and recovery requirement.

> [!IMPORTANT]
> **Zero Plaintext Invariant**: This document records cryptographic metadata, algorithms, and lifecycle requirements only. Plaintext key material, passwords, tokens, or seeds are strictly prohibited from appearing in documentation, source repositories, or audit trails.

---

## 2. Key & Secret Classification Matrix

```
                          PRIVGUARD SECRET TAXONOMY
                                      |
         +----------------------------+----------------------------+
         |                                                         |
         v                                                         v
   CRYPTOGRAPHIC KEYS                                      OPERATIONAL SECRETS
         |                                                         |
   +-----+-----+-----+                                       +-----+-----+-----+
   |           |     |                                       |           |     |
   v           v     v                                       v           v     v
Data (DEK)  Wrap(KEK) Signing(Ed25519/HMAC)             Database      Cache   Integrations
```

| Key Identifier | Purpose | Owner | Scope | Storage Location | Algorithm | Key Versioning | Rotation Policy | Expiration | Revocation Procedure | Recovery Requirement |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`mem_dek`** | Encrypt personal memory payloads | Memory Vault Engine | Per-record | Wrapped in `memory_records.wrapped_dek` | AES-256-GCM (256-bit) | Bound to KEK version | Rewrapped on KEK rotation; regenerated on compromise | None (persists with record) | Cryptographic erasure (destroy DEK) | Irrevocable once erased; restore from backup requires KEK |
| **`mem_kek_v1`** (Legacy) | Wrap V1 memory DEKs | Memory Vault Engine | Per-user | Derived deterministically on-the-fly | HKDF-SHA256 (32 bytes derived from master key) | Monotonic integer (`key_version`) | Migrated to V2 KMS; retained for read-compatibility | None | Disable user version | Master key backup |
| **`mem_kek_v2`** (KMS) | Wrap V2 memory DEKs | Enterprise Tenant / KMS | Per-tenant / organization | External KMS (AWS KMS, GCP KMS, Vault) | AES-256 (KMS-managed KEK) | Provider Key Version / ARN alias | 90 days automatic rotation (rewrap DEKs) | Configurable | Disable KEK in KMS | KMS multi-region replica / HSM backup |
| **`privguard_master_key`** | Root secret for V1 KEKs and local dev | Platform Operator | Cluster / Node | Kubernetes Secret / Docker Secret (`/run/secrets/`) | High-entropy random string (≥ 32 chars) | Managed via SecretStore | 365 days or on compromise (re-encrypt V1 data) | None | Invalidate secret, deploy new cluster secret | Sealed KMS backup / offline cold storage |
| **`policy_signing_ed25519`** | Sign enterprise policy bundles | Central Policy Authority | Per-tenant / organization | Kubernetes Secret / KMS Asymmetric Key | Ed25519 (256-bit) | Unique Key ID (`kid`) | 180 days; historical public keys preserved | None | Publish revocation in `key_versions`, re-sign active policies | Public key retained in database for historical verification |
| **`approval_binding_hmac`** | Cryptographic action binding for approvals | Approval Engine | Platform / Tenant | Kubernetes Secret / Environment | HMAC-SHA256 (256-bit) | Unique Key ID (`kid`) | 90 days; pending approvals honored for TTL (max 300s) | TTL-bound | Invalidate key ID, force re-request of pending approvals | Re-derive or restore from secret store |
| **`db_app_password`** | Authenticate runtime backend to PostgreSQL | Database Administrator | Cluster / Tenant DB | Kubernetes Secret (`privguard-database-credentials`) | Opaque high-entropy token (32 chars) | Managed via SecretStore | 90 days with rolling pod rollout | None | Update PostgreSQL role, restart pods | Managed DB snapshot / secret manager version history |
| **`db_migrator_password`**| Authenticate Alembic migration Job (DDL) | Release Engineer | Migration Job | Kubernetes Secret (`privguard-database-credentials`) | Opaque high-entropy token (32 chars) | Managed via SecretStore | 90 days; only mounted during upgrades | None | Update PostgreSQL role | Secret manager version history |
| **`redis_password`** | Authenticate to Redis cluster | Infrastructure Team | Cluster cache | Kubernetes Secret (`privguard-redis-credentials`) | Opaque high-entropy token (32 chars) | Managed via SecretStore | 90 days | None | Update Redis `AUTH`, rolling restart | Secret manager version history |
| **`admin_api_key`** | Bootstrap & emergency administrator API auth | Security Administrator | Global Platform | Kubernetes Secret (`privguard-secrets`) | `pg_live_` prefixed hex (192-bit) | Monotonic version | 90 days or on admin personnel departure | None | Delete key hash from database / config | Admin key reissue via CLI |
| **`mcp_integration_cred`** | Authenticate to upstream MCP tools | Tenant Admin | Per-MCP Server | Encrypted in `integration_credentials` table | AES-256-GCM (wrapped under Tenant KEK) | String version (`v1`, `v2`) | On upstream credential rotation | Configurable | Delete record from database | Re-provision from upstream service |
| **`llm_provider_api_key`** | Authenticate to OpenAI/Anthropic | Tenant Admin | Application Gateway | Kubernetes Secret / External Secret Manager | Provider-specific bearer token | Provider version | Per organization security policy | None | Revoke in provider console, update Secret | Re-provision in provider console |

---

## 3. Cryptographic Purpose Segregation

To uphold the principle of least privilege and prevent privilege escalation across subsystems:

```
+---------------------------------------------------------------------------------+
|                                    ISOLATION ZONES                              |
+------------------------+-------------------------------+------------------------+
| DATA ENCRYPTION ZONE   | SIGNING & AUTHENTICATION ZONE | INFRASTRUCTURE ZONE    |
| - Memory DEKs (AES-GCM)| - Ed25519 Policy Signing Keys | - PostgreSQL Passwords |
| - Memory KEKs (KMS)    | - HMAC Approval Binding Keys  | - Redis Password       |
| - Legacy Master Key    | - Admin API Keys              | - MCP Server Tokens    |
|                        | - Agent Capability Tokens     | - Upstream LLM Keys    |
+------------------------+-------------------------------+------------------------+
```

### Invariants:
1. **Never Share Key Material**: An encryption key must never be used for HMAC or digital signing.
2. **Never Cross Isolation Boundaries**: Compromising an HMAC approval key does not yield access to memory encryption KEKs or database passwords.
3. **Dedicated Key Derivation Contexts**: When sub-keys are derived via HKDF, distinct, domain-separated `info` and `salt` strings are mandatory.

---

## 4. Key Lifecycle State Machine

Every cryptographic key managed by PRIVGUARD progresses through a deterministic, auditable state machine:

```
  +---------+
  | CREATED |
  +----+----+
       |
       v
  +----+----+
  | ACTIVE  +<---------------+
  +----+----+                |
       |                     | (Rollback if verification fails)
       v                     |
  +----+-------------+       |
  | ROTATION_PENDING |       |
  +----+-------------+       |
       |                     |
       v                     |
  +----+-----+               |
  | ROTATING +---------------+
  +----+-----+
       |
       v
  +----+----+
  |VERIFYING|
  +----+----+
       |
       v
  +----+----+
  | RETIRED |
  +----+----+
       |
       v
  +----+----+
  |DESTROYED|
  +---------+
```

### State Descriptions:
1. **`CREATED`**: Key generated or registered in KMS; not yet serving live traffic.
2. **`ACTIVE`**: Current primary key version used for new encryptions and digital signatures.
3. **`ROTATION_PENDING`**: New key version provisioned; preparing for asynchronous data rewrapping or dual-verification rollout.
4. **`ROTATING`**: Background workers are rewrapping DEKs or updating references.
5. **`VERIFYING`**: Rewrapped records undergoing cryptographic roundtrip integrity verification.
6. **`RETIRED`**: Key version no longer used for new writes; retained strictly for historical verification and legacy read operations.
7. **`DESTROYED`**: Key material permanently wiped from KMS or local storage after all dependent records are migrated and backup retention windows elapse.
8. **`COMPROMISED`**: Emergency state triggered during security incidents. Restricts key usage immediately.

---

## 5. Storage & Secret Integration Rules

1. **Kubernetes Deployments**:
   - Workloads must consume secrets exclusively via `existingSecret` parameters.
   - Workload Identity (AWS IRSA, GKE Workload Identity, Azure Workload Identity) is required for external KMS authentication. Static cloud credentials in pods are prohibited.
2. **Docker Deployments**:
   - Production Docker Compose mounts secrets via file-based secrets (`/run/secrets/*`).
   - Plaintext environment variables for credentials in production trigger fatal startup errors.
3. **Audit Trail Exclusion**:
   - Audit events record key identifiers (`key_id`), version numbers, and cryptographic digests only.
   - Any log entry containing plaintext key material or DEKs violates system invariants.
