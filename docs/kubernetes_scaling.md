# PRIVGUARD AI — Kubernetes Scaling, High Availability & Resilience
## Horizontal Pod Autoscaling, PodDisruptionBudgets & Topology Spread
**Agency**: Moon Sanctum Labs — *Decode. Build. Evolve.*  
**Milestone**: Stage 10.4

---

## 1. Overview

PRIVGUARD AI is architected as a horizontally scalable, stateless execution layer backed by distributed state in PostgreSQL and Redis. Multiple backend, frontend, and worker replicas can run simultaneously across multiple Kubernetes nodes and availability zones.

---

## 2. Horizontal Pod Autoscaling (HPA v2)

Horizontal Pod Autoscalers use the `autoscaling/v2` API to dynamically scale replica counts based on CPU and memory utilization reported by the Kubernetes Metrics Server.

### 2.1 Backend Autoscaling Policy
The backend performs cryptographic hashing, token validation, policy evaluation, and database interactions. Autoscaling is tuned for steady throughput:

```yaml
backend:
  autoscaling:
    enabled: true
    minReplicas: 3
    maxReplicas: 10
    targetCPUUtilizationPercentage: 75
    targetMemoryUtilizationPercentage: 80
```

### 2.2 Frontend Autoscaling Policy
The frontend runs Next.js 14 in standalone mode, serving React server components and BFF route proxies:

```yaml
frontend:
  autoscaling:
    enabled: true
    minReplicas: 2
    maxReplicas: 6
    targetCPUUtilizationPercentage: 70
```

---

## 3. High Availability & Failure Domains

To guarantee zero downtime during cluster upgrades, node replacements, and availability zone outages, PRIVGUARD incorporates two availability primitives:

### 3.1 PodDisruptionBudgets (`policy/v1`)
PodDisruptionBudgets (PDBs) limit voluntary disruptions (such as `kubectl drain` during node maintenance or Kubernetes version upgrades):

- **Backend PDB**: `minAvailable: 2` (or `maxUnavailable: 1`). Ensures at least 2 backend instances are always serving traffic.
- **Frontend PDB**: `minAvailable: 1` (or `maxUnavailable: 1`). Ensures at least 1 frontend instance is always reachable.

### 3.2 Topology Spread Constraints
Topology Spread Constraints distribute pods evenly across availability zones and physical worker nodes:

```yaml
topologySpreadConstraints:
  - maxSkew: 1
    topologyKey: "topology.kubernetes.io/zone"
    whenUnsatisfiable: ScheduleAnyway
    labelSelector:
      matchLabels:
        app.kubernetes.io/name: privguard
        app.kubernetes.io/component: backend
  - maxSkew: 1
    topologyKey: "kubernetes.io/hostname"
    whenUnsatisfiable: ScheduleAnyway
    labelSelector:
      matchLabels:
        app.kubernetes.io/name: privguard
        app.kubernetes.io/component: backend
```

---

## 4. Resource Allocation & QoS Classes

PRIVGUARD containers are configured with explicit `requests` and `limits`, placing them in the **Burstable** Quality of Service (QoS) class:

| Component | CPU Request | CPU Limit | Memory Request | Memory Limit |
| :--- | :--- | :--- | :--- | :--- |
| **Backend** | `250m` | `1000m` | `512Mi` | `1024Mi` |
| **Frontend** | `150m` | `500m` | `256Mi` | `512Mi` |
| **Worker** | `200m` | `500m` | `256Mi` | `512Mi` |
| **Migration Job** | `100m` | `500m` | `256Mi` | `512Mi` |

---

## 5. Health Probes & Traffic Routing

Kubernetes relies on HTTP probes to determine pod lifecycle state:

1. **Liveness Probe** (`/health/live`):
   - Path: `http://<pod-ip>:8000/health/live`
   - Purpose: Verifies internal process responsiveness. If it fails 3 consecutive times, kubelet restarts the container.
2. **Readiness Probe** (`/health/ready`):
   - Path: `http://<pod-ip>:8000/health/ready`
   - Purpose: Validates external connectivity to PostgreSQL and Redis. If either dependency becomes unreachable, the pod is immediately removed from the Service endpoints to prevent failed client requests.
3. **Graceful Shutdown**:
   - Containers handle `SIGTERM` signals cleanly.
   - In-flight requests are allowed up to 30 seconds (`terminationGracePeriodSeconds: 30`) to complete before forced termination.
