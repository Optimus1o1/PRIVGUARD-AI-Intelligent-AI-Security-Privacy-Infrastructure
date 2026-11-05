# PRIVGUARD AI — Stage 10.4 Architecture Specification
## Cloud-Neutral Kubernetes Deployment & Helm Architecture
**Agency**: Moon Sanctum Labs — *Decode. Build. Evolve.*  
**Lead Developer**: Aniket Nandi (Kolkata, IST)  
**Milestone**: Stage 10.4  

---

## 1. Architectural Vision

PRIVGUARD AI Stage 10.4 establishes a cloud-neutral, portable Kubernetes deployment model using Helm (`deploy/helm/privguard/`). The architecture is designed to deploy on self-managed Kubernetes, AWS EKS, Google GKE, Azure AKS, and conformant distributions without hardcoding vendor-specific resources.

```
                                  INTERNET
                                      |
                                      v
                            [ INGRESS CONTROLLER ]
                           (TLS Termination / FQDN)
                                      |
                                      v  ClusterIP: 3000
                            [ FRONTEND SERVICE ]
                                      |
                        +-------------+-------------+
                        |                           |
                        v                           v
              [ NEXT.JS POD 1 ]           [ NEXT.JS POD 2 ]
              (UID 1001, BFF)             (UID 1001, BFF)
                        |                           |
                        +-------------+-------------+
                                      |
                                      v  ClusterIP: 8000
                            [ BACKEND SERVICE ]
                                      |
                 +--------------------+--------------------+
                 |                    |                    |
                 v                    v                    v
        [ FASTAPI POD 1 ]    [ FASTAPI POD 2 ]    [ FASTAPI POD 3 ]
        (UID 10001, RLS)     (UID 10001, RLS)     (UID 10001, RLS)
                 |                    |                    |
                 +--------------------+--------------------+
                                      |
        +-----------------------------+-----------------------------+
        |                             |                             |
        v                             v                             v
[ EXTERNAL POSTGRESQL ]        [ EXTERNAL REDIS ]          [ WORKER PODS ]
(Cloud Managed / Aurora /     (Cloud Managed / ElastiCache/ (Outbox Relay &
 Cloud SQL / Flexible Server)  MemoryStore / Redis Cloud)    Stream Worker)
        ^                                                           ^
        |                                                           |
 [ MIGRATION JOB ]                                                  |
 (Alembic DDL Runner) ----------------------------------------------+
```

---

## 2. Key Architecture Invariants

1. **Frontend-Only Public Ingress**: The Kubernetes Ingress routes traffic exclusively to `frontend` pods on port 3000. Backend, worker, database, and Redis are completely shielded from external ingress.
2. **Next.js BFF Pattern**: The Next.js frontend acts as the backend-for-frontend (BFF). Browser clients never connect directly to the backend; requests are proxied internally using Kubernetes service DNS (`http://privguard-backend:8000`).
3. **Decoupled State Lifecycle**: PostgreSQL and Redis are managed as external services (e.g. AWS RDS/ElastiCache, GCP Cloud SQL/Memorystore, Azure Flexible Server/Azure Cache). They are not coupled to the application Helm release lifecycle.
4. **Pre-Rollout Schema Migrations**: Alembic migrations run as a dedicated, version-specific Kubernetes Job (`alembic upgrade head`) using dedicated migration credentials (`privguard_migrator`) before new application pods are scheduled.
5. **Restricted Pod Security Standard**: All pods enforce `runAsNonRoot: true`, `readOnlyRootFilesystem: true`, capabilities drop `ALL`, and `RuntimeDefault` seccomp profiles. Writable state is restricted to memory-backed `/tmp` mounts.
6. **Multi-Tier NetworkPolicies**: Default-deny policies block unauthorized pod-to-pod and egress traffic. Only frontend pods can reach backend pods; only backend and worker pods can reach external data stores.
7. **External Secrets Exclusivity**: Secrets are consumed via `existingSecret` references; no passwords or private keys are stored in `values.yaml` or printed in Helm NOTES.

