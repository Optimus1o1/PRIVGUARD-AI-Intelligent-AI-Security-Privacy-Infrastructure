# PRIVGUARD AI — KMS Provider Integration Guide
## Multi-Cloud and On-Premises Cryptographic Key Management

**Organization:** Moon Sanctum Labs — *Decode. Build. Evolve.*  
**Author:** Aniket Nandi (Kolkata, IST)  
**Baseline:** Stage 10.5  

---

### 1. Supported Providers

PRIVGUARD AI implements a provider-independent KMS abstraction. The target provider is configured via `KMS_PROVIDER` and corresponding credentials/endpoints.

| Provider | `KMS_PROVIDER` | Best For | Native ReEncrypt Support |
| :--- | :--- | :--- | :--- |
| **Local / Test** | `local` | Local development, CI tests | Yes (in-process AES-256-GCM) |
| **AWS KMS** | `aws_kms` | AWS EKS, EC2, ECS workloads | **Yes** (via `ReEncrypt` API) |
| **Google Cloud KMS** | `gcp_kms` | GKE, Cloud Run workloads | Yes (unwrap + wrap cycle) |
| **Azure Key Vault** | `azure_key_vault` | AKS, Azure App Service | Yes (unwrap + wrap cycle) |
| **HashiCorp Vault** | `vault_transit` | Multi-cloud, Hybrid, On-prem | **Yes** (via `/transit/rewrap` API) |

---

### 2. Configuration & Authentication

#### 2.1 AWS KMS (`aws_kms`)
- **Configuration:**
  ```bash
  KMS_PROVIDER=aws_kms
  KMS_KEY_ID=arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012
  KMS_REGION=us-east-1
  ```
- **Authentication:** Standard AWS credential chain or Kubernetes IRSA (IAM Roles for Service Accounts). PRIVGUARD never requires long-lived access keys inside container files.
- **Required IAM Permissions:**
  - `kms:Encrypt`
  - `kms:Decrypt`
  - `kms:ReEncrypt*`
  - `kms:DescribeKey`

#### 2.2 Google Cloud KMS (`gcp_kms`)
- **Configuration:**
  ```bash
  KMS_PROVIDER=gcp_kms
  KMS_KEY_ID=projects/{project-id}/locations/{location}/keyRings/{ring}/cryptoKeys/{key}
  ```
- **Authentication:** Google Cloud Workload Identity Federation on GKE or Application Default Credentials (ADC).
- **Required IAM Permissions:**
  - `roles/cloudkms.cryptoKeyEncrypterDecrypter`
  - `roles/cloudkms.viewer`

#### 2.3 Azure Key Vault (`azure_key_vault`)
- **Configuration:**
  ```bash
  KMS_PROVIDER=azure_key_vault
  KMS_ENDPOINT=https://privguard-vault.vault.azure.net/
  KMS_KEY_ID=privguard-master-kek
  ```
- **Authentication:** Azure Workload Identity (federated token exchange).
- **Required RBAC Permissions:**
  - `Key Vault Crypto User` (wrap, unwrap)

#### 2.4 HashiCorp Vault Transit (`vault_transit`)
- **Configuration:**
  ```bash
  KMS_PROVIDER=vault_transit
  KMS_ENDPOINT=https://vault.internal.corp:8200
  KMS_KEY_ID=privguard-memory-kek
  VAULT_TOKEN=s.exampletoken
  ```
- **Authentication:** Kubernetes Vault auth method or AppRole.
- **Endpoints Utilized:**
  - `POST /v1/transit/encrypt/{name}`
  - `POST /v1/transit/decrypt/{name}`
  - `POST /v1/transit/rewrap/{name}` (Server-side rewrap without returning plaintext DEK)

#### 2.5 Local Provider (`local`)
- **Configuration:**
  ```bash
  KMS_PROVIDER=local
  PRIVGUARD_MASTER_KEY=pg_master_key_minimum_32_characters_long_for_dev
  ```
- **Security Guardrail:** Automatically blocked when `ENVIRONMENT=production`. Startup will fail with an exception if attempted in production.
