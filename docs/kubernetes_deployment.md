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

Verify backend, Redis, and security health via port-forward:
```bash
kubectl port-forward svc/privguard-backend -n privguard 8000:8000
curl http://localhost:8000/health/live
curl http://localhost:8000/health/ready
curl http://localhost:8000/health/security
```

---

## 5. Prometheus Observability & ServiceMonitor Integration

When the Prometheus Operator is running in your cluster, enable automated scraping by setting `serviceMonitor.enabled: true` in your values file or via `--set`:

```bash
helm upgrade privguard ./deploy/helm/privguard \
  --namespace privguard \
  --reuse-values \
  --set serviceMonitor.enabled=true \
  --set serviceMonitor.path="/metrics" \
  --set serviceMonitor.interval="15s"
```

Verify that Prometheus has registered the scrape target:
```bash
curl http://localhost:8000/metrics
```
Output reflects low-cardinality Prometheus metrics including `privguard_http_requests_total`, `privguard_gateway_latency_seconds`, and `privguard_canary_executions_total`.

---

## 6. Supply Chain Integrity & Production Digest Pinning

In high-assurance production Kubernetes clusters, workloads should strictly reference container images by immutable cryptographic digests (`@sha256:...`) rather than mutable semantic tags.

Before initiating a production rollout, execute the automated release verification script:
```bash
python scripts/security/verify_release.py \
  --manifest-path dist/release-manifest.json \
  --expected-repo "privguard-ai/privguard" \
  --expected-tag "v1.0.0"
```

Once validated, deploy with digest pinning:
```bash
helm upgrade privguard ./deploy/helm/privguard \
  --namespace privguard \
  --reuse-values \
  --set backend.image.digest="sha256:<VERIFIED_BACKEND_DIGEST>" \
  --set frontend.image.digest="sha256:<VERIFIED_FRONTEND_DIGEST>"
```

---

## 7. Resilience, Chaos & Failure Containment

In Kubernetes multi-node clusters:
- **Pod Disruption Budgets (PDB):** Enforce `minAvailable: 1` during node maintenance, cluster autoscaler drains, and rolling updates.
- **Fail-Closed Probes:** Liveness probes (`/health/live`) and readiness probes (`/health/ready`) automatically remove failing pods from ClusterIP load balancing.
- **PostgreSQL-Authoritative State:** If Redis pods crash or partition, backend replicas fail closed on sensitive reads and query PostgreSQL directly, preventing privilege leakage or stale authorizations.
- **Edge Resource Protection:** Kubernetes container memory limits combined with `RequestSizeLimitMiddleware` (10 MB request limit) prevent OOM kills from volumetric payload attacks.
- **Agent Runaway Quotas:** Hard step limits (default: 100 steps) ensure looping or prompt-injected agents are terminated with HTTP 429 and auto-revoked before exhausting cluster compute or upstream API budgets.
