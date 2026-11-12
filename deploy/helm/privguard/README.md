# PRIVGUARD AI — Production Helm Chart

**Agency**: Moon Sanctum Labs — *Decode. Build. Evolve.*  
**Chart Version**: `0.1.0`  
**Application Version**: `0.1.0`  
**Target Environments**: Cloud-neutral (AWS EKS, Google GKE, Azure AKS, Self-managed Kubernetes 1.26+)  

---

## 1. Overview

This Helm chart deploys the **PRIVGUARD AI** security and privacy enforcement layer on Kubernetes. The architecture strictly isolates workloads according to the Kubernetes **Restricted Pod Security Standard**, enforces three-tier network policies, separates DDL schema migrations into dedicated Kubernetes Jobs, and routes external client traffic solely through the Next.js BFF frontend.

---

## 2. Prerequisites

1. **Kubernetes Cluster**: Version 1.26+ with a CNI that enforces `NetworkPolicy` (e.g., Calico, Cilium, AWS VPC CNI with NetworkPolicy enabled, GKE Dataplane V2, Azure CNI powered by Cilium).
2. **Helm**: Version 3.12+ (tested on Helm v4.x).
3. **External Managed PostgreSQL**: PostgreSQL 16+ with non-superuser role `privguard_app` (`NOBYPASSRLS`) and migration role `privguard_migrator`.
4. **External Managed Redis**: Redis 7.x cluster or standalone instance with authentication enabled.
5. **Pre-Existing Kubernetes Secrets**:
   - `privguard-database-credentials`: containing `postgres_password` and `migration_password`.
   - `privguard-redis-credentials`: containing `redis_password`.
   - `privguard-secrets`: containing `privguard_master_key` and `privguard_admin_api_key`.

---

## 3. Quickstart

### Step 1: Create Namespace and Pre-Requisite Secrets
```bash
kubectl create namespace privguard

# Create database credentials secret
kubectl create secret generic privguard-database-credentials \
  --namespace privguard \
  --from-literal=postgres_password='<STRONG_APP_PASSWORD>' \
  --from-literal=migration_password='<STRONG_MIGRATOR_PASSWORD>'

# Create Redis credentials secret
kubectl create secret generic privguard-redis-credentials \
  --namespace privguard \
  --from-literal=redis_password='<STRONG_REDIS_PASSWORD>'

# Create core encryption secrets
kubectl create secret generic privguard-secrets \
  --namespace privguard \
  --from-literal=privguard_master_key='<MIN_32_CHAR_BASE64_MASTER_KEY>' \
  --from-literal=privguard_admin_api_key='<ADMIN_API_KEY>'
```

### Step 2: Install PRIVGUARD Chart
```bash
# Production installation
helm install privguard ./deploy/helm/privguard \
  --namespace privguard \
  -f ./deploy/helm/privguard/values/production.yaml
```

---

## 4. Key Parameters

| Parameter | Description | Default |
|---|---|---|
| `global.environment` | Environment label (`production`, `staging`, `development`) | `"production"` |
| `global.failClosedMode` | Enforce fail-closed security when upstream services degrade | `true` |
| `backend.replicaCount` | Number of FastAPI security gateway replicas | `2` |
| `backend.securityContext.runAsUser` | UID for backend process | `10001` |
| `frontend.replicaCount` | Number of Next.js frontend BFF replicas | `2` |
| `frontend.securityContext.runAsUser` | UID for frontend process | `1001` |
| `worker.enabled` | Deploy background transactional outbox and event worker | `true` |
| `migration.enabled` | Run one-shot Alembic migration Job before rollout | `true` |
| `ingress.enabled` | Enable Ingress exposing only the frontend service | `false` |
| `networkPolicy.enabled` | Deploy multi-tier Kubernetes NetworkPolicies | `true` |
| `networkPolicy.defaultDeny` | Apply default-deny for ingress and egress in namespace | `true` |

---

## 5. Security & Isolation Architecture

- **Restricted Pod Security**: All pods drop all capabilities (`drop: ["ALL"]`), disallow privilege escalation (`allowPrivilegeEscalation: false`), mount root filesystems read-only (`readOnlyRootFilesystem: true`), and run with `RuntimeDefault` seccomp profiles.
- **Zero Ingress to Backend/Data**: The Ingress controller routes exclusively to the frontend service on port 3000. Backend (port 8000), database (port 5432), and Redis (port 6379) are completely shielded from ingress.
- **NetworkPolicies**: Restrict pod-to-pod communication so that only frontend pods can reach backend pods, and only backend/worker pods can reach external data stores.

