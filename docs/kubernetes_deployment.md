# PRIVGUARD AI — Kubernetes Deployment Guide
## Production Installation & Operations via Helm
**Agency**: Moon Sanctum Labs — *Decode. Build. Evolve.*  

---

## 1. Prerequisites

Before installing the PRIVGUARD Helm chart:
- **Kubernetes Cluster**: Version 1.26 or higher with a CNI supporting NetworkPolicies (Calico, Cilium, AWS VPC CNI with NetworkPolicies, GKE Dataplane V2, Azure CNI powered by Cilium).
- **Helm**: Version 3.12+ (tested on Helm v4.x).
- **External PostgreSQL**: Managed PostgreSQL 16+ instance.
- **External Redis**: Managed Redis 7.x instance.

---

## 2. Secrets Provisioning

Create required Kubernetes Secret objects in the target namespace before running `helm install`:

```bash
kubectl create namespace privguard

# 1. Database credentials secret
kubectl create secret generic privguard-database-credentials \
  --namespace privguard \
  --from-literal=postgres_password='<APPLICATION_ROLE_PASSWORD>' \
  --from-literal=migration_password='<MIGRATION_ROLE_PASSWORD>'

# 2. Redis credentials secret
kubectl create secret generic privguard-redis-credentials \
  --namespace privguard \
  --from-literal=redis_password='<REDIS_PASSWORD>'

# 3. PRIVGUARD encryption and admin secrets
kubectl create secret generic privguard-secrets \
  --namespace privguard \
  --from-literal=privguard_master_key='<MIN_32_CHAR_BASE64_MASTER_KEY>' \
  --from-literal=privguard_admin_api_key='<ADMIN_API_KEY>'
```

---

## 3. Installation & Upgrades

### Installing Production Release
```bash
helm install privguard ./deploy/helm/privguard \
  --namespace privguard \
  -f ./deploy/helm/privguard/values/production.yaml
```

### Performing Rolling Upgrades
```bash
# 1. Inspect upgrade diff
helm diff upgrade privguard ./deploy/helm/privguard -f ./deploy/helm/privguard/values/production.yaml

# 2. Execute upgrade
helm upgrade privguard ./deploy/helm/privguard \
  --namespace privguard \
  -f ./deploy/helm/privguard/values/production.yaml
```

During an upgrade:
1. The migration Job runs `alembic upgrade head` before application pods roll out.
2. If migrations succeed, Kubernetes performs a rolling update of backend and frontend deployments (`maxSurge: 25%`, `maxUnavailable: 0`).
3. If migrations fail, the release halts, preventing deployment of incompatible pods.

---

## 4. Verification & Diagnostics

Check pod rollout and readiness:
```bash
kubectl get pods -n privguard -l app.kubernetes.io/instance=privguard
```

Verify backend and Redis health via port-forward:
```bash
kubectl port-forward svc/privguard-backend -n privguard 8000:8000
curl http://localhost:8000/health/live
curl http://localhost:8000/health/ready
curl http://localhost:8000/health/redis
curl http://localhost:8000/health/database
```
