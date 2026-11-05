# PRIVGUARD AI — Kubernetes Security Architecture
## Pod Security Standards, Least Privilege & Isolation Guarantees
**Agency**: Moon Sanctum Labs — *Decode. Build. Evolve.*  
**Milestone**: Stage 10.4

---

## 1. Executive Security Summary

The PRIVGUARD AI Helm chart implements Kubernetes **Restricted Pod Security Standard** compliance out-of-the-box across all deployed workloads:
- **Frontend** (`privguard-frontend`)
- **Backend API** (`privguard-backend`)
- **Event Worker** (`privguard-worker`)
- **Database Migration Job** (`privguard-migration`)

Every container operates under the principle of least privilege, with read-only root filesystems, dropped capabilities, unprivileged user execution, explicit temporary memory limits, and disabled ServiceAccount token automounting.

---

## 2. Pod Security Standards (PSS) Compliance

### Namespace Labeling for Restricted Enforcement
In production Kubernetes clusters, namespaces should be labeled with the `restricted` Pod Security Standard:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: privguard
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/audit-version: latest
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/warn-version: latest
```

All PRIVGUARD pods pass validation under this policy without requiring exceptions or exemptions.

---

## 3. Workload Security Contexts

### 3.1 Security Context Matrix

| Workload | UID / GID | Root FS | Capabilities | Seccomp Profile | Privilege Escalation | Automount SA Token |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Frontend** (Next.js) | `1001:1001` | Read-only | Drop `ALL` | `RuntimeDefault` | `false` | `false` |
| **Backend** (FastAPI) | `10001:10001` | Read-only | Drop `ALL` | `RuntimeDefault` | `false` | `false` |
| **Worker** (Outbox/Stream) | `10001:10001` | Read-only | Drop `ALL` | `RuntimeDefault` | `false` | `false` |
| **Migration Job** (Alembic) | `10001:10001` | Read-only | Drop `ALL` | `RuntimeDefault` | `false` | `false` |

### 3.2 Backend & Worker Pod Security Context
```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 10001
  runAsGroup: 10001
  fsGroup: 10001
  seccompProfile:
    type: RuntimeDefault

containerSecurityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop:
      - ALL
```

### 3.3 Frontend Pod Security Context
```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1001
  runAsGroup: 1001
  fsGroup: 1001
  seccompProfile:
    type: RuntimeDefault

containerSecurityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop:
      - ALL
```

---

## 4. Ephemeral Filesystem Isolation

To support runtime caching and scratch writes without compromising root filesystem immutability (`readOnlyRootFilesystem: true`), ephemeral directories are mounted as bounded, memory-backed `emptyDir` volumes:

1. **Backend `/tmp`**:
   - Medium: `Memory`
   - Size limit: `64Mi`
   - Use: Temporary token generation buffers, cryptographic scratchpads.
2. **Frontend `/tmp` and Next.js Cache**:
   - Medium: `Memory`
   - Size limit: `128Mi`
   - Mount paths: `/tmp`, `/app/.next/cache`
   - Use: Next.js standalone server page compilation and image optimization caches.

Memory-backed mounts prevent disk filling attacks on node storage and ensure all ephemeral files are immediately destroyed upon pod termination.

---

## 5. ServiceAccount & API Server Isolation

By default, Kubernetes mounts a JSON Web Token (JWT) into `/var/run/secrets/kubernetes.io/serviceaccount/token` inside every container. Compromised workloads can use this token to query the Kubernetes API server and attempt lateral privilege escalation.

PRIVGUARD completely eliminates this attack vector:
- `automountServiceAccountToken: false` is configured on both the `ServiceAccount` and the pod specifications.
- Neither frontend, backend, worker, nor migration containers mount or possess API server tokens.
- No ClusterRoles or Roles are provisioned for runtime workloads.

---

## 6. Process & Ingress Boundary Guarantees

1. **Ingress Boundary**:
   - Ingress routes traffic exclusively to the frontend ClusterIP Service on port 3000.
   - Backend (port 8000), Worker, and Databases are never exposed via Ingress.
2. **Next.js BFF Mediation**:
   - Browser clients communicate only with Next.js frontend routes.
   - All backend API interactions occur server-to-server inside the cluster via internal Kubernetes DNS (`http://privguard-backend:8000`).
   - Secrets and backend API keys never leak to client browsers.
3. **Database Privilege Separation**:
   - Runtime Backend & Worker pods connect via the unprivileged `privguard_app` database role (CRUD only on tenant tables, no DDL).
   - Migration Job runs one-shot using the `privguard_migrator` database role (DDL privileges strictly on `privguard_*` schemas).
