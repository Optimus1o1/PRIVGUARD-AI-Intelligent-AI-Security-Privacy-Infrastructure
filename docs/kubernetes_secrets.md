# PRIVGUARD AI — Kubernetes Secrets & Key Management
## Secret Isolation, External Secrets Operator & Rotation Strategies
**Agency**: Moon Sanctum Labs — *Decode. Build. Evolve.*  
**Milestone**: Stage 10.4

---

## 1. Zero Plaintext Secrets Policy

The PRIVGUARD AI Helm chart enforces a strict zero-plaintext policy:
- No passwords, private keys, API tokens, or master keys may be committed to Helm `values.yaml` files or source repositories.
- Workloads mount secrets exclusively through Kubernetes `Secret` resources referenced by name (`existingSecret`).
- If an existing secret is missing or misnamed, pods fail fast with configuration errors rather than running with unauthenticated fallbacks.

---

## 2. Required Secrets Reference Matrix

| Secret Target | Default Secret Name | Required Keys | Consumer Workload |
| :--- | :--- | :--- | :--- |
| **Application Role Password** | `privguard-database-credentials` | `postgres_password` | Backend (`privguard-backend`), Worker (`privguard-worker`) |
| **Migration Role Password** | `privguard-database-credentials` | `migration_password` | Migration Job (`privguard-migration`) |
| **Redis Authentication** | `privguard-redis-credentials` | `redis_password` | Backend (`privguard-backend`), Worker (`privguard-worker`) |
| **PRIVGUARD Master Key** | `privguard-secrets` | `privguard_master_key` | Backend (`privguard-backend`) |
| **Admin API Key** | `privguard-secrets` | `privguard_admin_api_key` | Backend (`privguard-backend`) |

---

## 3. Creating Secrets via `kubectl` (Manual Workflow)

For air-gapped or staging environments:

```bash
kubectl create namespace privguard

# 1. Database credentials
kubectl create secret generic privguard-database-credentials \
  --namespace privguard \
  --from-literal=postgres_password="$(openssl rand -base64 32)" \
  --from-literal=migration_password="$(openssl rand -base64 32)"

# 2. Redis credentials
kubectl create secret generic privguard-redis-credentials \
  --namespace privguard \
  --from-literal=redis_password="$(openssl rand -base64 32)"

# 3. Application master key and admin key
kubectl create secret generic privguard-secrets \
  --namespace privguard \
  --from-literal=privguard_master_key="$(openssl rand -base64 32)" \
  --from-literal=privguard_admin_api_key="pg_live_$(openssl rand -hex 24)"
```

---

## 4. Enterprise Integration via External Secrets Operator (ESO)

In enterprise production clusters, secrets should be synced dynamically from enterprise secret managers (AWS Secrets Manager, Google Cloud Secret Manager, Azure Key Vault, or HashiCorp Vault) using the [External Secrets Operator (ESO)](https://external-secrets.io/).

### 4.1 Example `SecretStore` (AWS Secrets Manager)
```yaml
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: aws-secrets-manager
  namespace: privguard
spec:
  provider:
    aws:
      service: SecretsManager
      region: us-east-1
      auth:
        jwt:
          serviceAccountRef:
            name: privguard-eso-sa
```

### 4.2 Example `ExternalSecret` for PRIVGUARD Core Secrets
```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: privguard-secrets-sync
  namespace: privguard
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secrets-manager
    kind: SecretStore
  target:
    name: privguard-secrets
    creationPolicy: Owner
  data:
    - secretKey: privguard_master_key
      remoteRef:
        key: production/privguard/app
        property: MASTER_KEY
    - secretKey: privguard_admin_api_key
      remoteRef:
        key: production/privguard/app
        property: ADMIN_API_KEY
```

### 4.3 Example `ExternalSecret` for Database Credentials
```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: privguard-database-credentials-sync
  namespace: privguard
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secrets-manager
    kind: SecretStore
  target:
    name: privguard-database-credentials
    creationPolicy: Owner
  data:
    - secretKey: postgres_password
      remoteRef:
        key: production/privguard/postgres
        property: APP_PASSWORD
    - secretKey: migration_password
      remoteRef:
        key: production/privguard/postgres
        property: MIGRATOR_PASSWORD
```

---

## 5. Kubernetes Secret Encryption at Rest

To protect Kubernetes `Secret` resources from unauthorized inspection in etcd snapshots or direct host filesystem access:
- **AWS EKS**: Enable AWS KMS envelope encryption for Secrets during cluster creation.
- **Google GKE**: Enable Cloud KMS Database Encryption for Secrets.
- **Azure AKS**: Enable Azure Key Vault KMS for Secrets Encryption.
- **Self-Managed / Bare-Metal**: Configure the Kubernetes API server `--encryption-provider-config` with an AES-CBC, AES-GCM, or KMS plugin provider.

---

## 6. Secret Rotation Operational Procedures

### 6.1 Database Password Rotation
1. Update user password in PostgreSQL:
   ```sql
   ALTER USER privguard_app WITH PASSWORD '<NEW_PASSWORD>';
   ```
2. Update the Kubernetes Secret (`privguard-database-credentials`) or trigger ESO resync.
3. Perform rolling rollout of backend and worker deployments:
   ```bash
   kubectl rollout restart deployment/privguard-backend -n privguard
   kubectl rollout restart deployment/privguard-worker -n privguard
   ```

### 6.2 Admin API Key Rotation
1. Generate and update `privguard_admin_api_key` in the secret store.
2. Restart backend deployment:
   ```bash
   kubectl rollout restart deployment/privguard-backend -n privguard
   ```
3. Update external CI/CD or governance agents with the new API key.

### 6.3 Master Key Rotation & KMS Workload Identity
PRIVGUARD supports envelope encryption where data encryption keys (DEKs) are wrapped by Key Encryption Keys (KEKs) residing in external KMS providers.
- When `KMS_PROVIDER` is set to `aws_kms`, `gcp_kms`, `azure_key_vault`, or `vault_transit`, the pod authenticates using Kubernetes Workload Identity (AWS IRSA, GKE Workload Identity, or Azure Workload Identity).
- Zero master key material is mounted inside the container filesystem.
- KEK rotation is triggered via `POST /v1/keys/{id}/rotate`, advancing the provider version and triggering non-destructive background DEK rewrapping without downtime.

---

## 7. Stage 10.5 KMS Helm Configuration

The PRIVGUARD Helm chart exposes a dedicated `kms:` configuration block:

```yaml
kms:
  provider: "aws_kms"  # or gcp_kms, azure_key_vault, vault_transit, local
  keyId: "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
  region: "us-east-1"
  endpoint: ""
```

In production, `kms.provider: "local"` is rejected by the backend startup validator. Pods must authenticate to the cloud KMS service via service account annotations (`eks.amazonaws.com/role-arn` or `iam.gke.io/gcp-service-account`).


