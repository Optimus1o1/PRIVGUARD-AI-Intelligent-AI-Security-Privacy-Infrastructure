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

### 6.3 Master Key Rotation
PRIVGUARD supports envelope encryption where data keys are encrypted by the Master Key.
- Stage 10.5 will implement key rotation routines and dual-key re-encryption transitions.
