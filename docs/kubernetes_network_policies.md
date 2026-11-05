# PRIVGUARD AI — Kubernetes Network Policies & Traffic Isolation
## Micro-Segmentation, Default-Deny & Zero-Trust In-Cluster Routing
**Agency**: Moon Sanctum Labs — *Decode. Build. Evolve.*  
**Milestone**: Stage 10.4

---

## 1. Network Security Model

PRIVGUARD uses a strict **Zero-Trust Network Architecture** inside the Kubernetes cluster. All intra-cluster and extra-cluster communication is denied by default and explicitly allowed only through defined Kubernetes `NetworkPolicy` resources.

```
       [ Public Internet ]
               |
               v
     [ Ingress Controller ]
               | (Port 3000 only)
               v
   +-----------------------+
   |  PRIVGUARD Frontend   |
   |     (Port 3000)       |
   +-----------------------+
               | (Internal ClusterIP, Port 8000 only)
               v
   +-----------------------+           +-----------------------+
   |   PRIVGUARD Backend   |           |   PRIVGUARD Worker    |
   |      (Port 8000)      |           |     (No Ingress)      |
   +-----------------------+           +-----------------------+
        |             |                     |             |
        | Port 5432   | Port 6379           | Port 5432   | Port 6379
        v             v                     v             v
  [ PostgreSQL ]  [ Redis ]           [ PostgreSQL ]  [ Redis ]
```

---

## 2. Policy Enforcement Matrix

| Source | Destination | Port / Protocol | Justification |
| :--- | :--- | :--- | :--- |
| **Ingress Controller** | Frontend Pods | `3000/TCP` | Route user browser traffic to Next.js UI |
| **Frontend Pods** | Backend Pods | `8000/TCP` | Server-to-server BFF route handler calls |
| **Frontend Pods** | CoreDNS (`kube-system`) | `53/UDP`, `53/TCP` | Resolve backend internal cluster DNS |
| **Backend Pods** | PostgreSQL (External) | `5432/TCP` | Authenticated database queries (Tenant RLS) |
| **Backend Pods** | Redis (External) | `6379/TCP` | Distributed rate limits, invalidation pub/sub |
| **Backend Pods** | CoreDNS (`kube-system`) | `53/UDP`, `53/TCP` | Resolve external database and Redis endpoints |
| **Worker Pods** | PostgreSQL (External) | `5432/TCP` | Process outbox events, cleanup jobs |
| **Worker Pods** | Redis (External) | `6379/TCP` | Consume Redis stream events and audit tails |
| **Worker Pods** | CoreDNS (`kube-system`) | `53/UDP`, `53/TCP` | Resolve external database and Redis endpoints |
| **Migration Job** | PostgreSQL (External) | `5432/TCP` | Apply Alembic schema migrations |
| **Prometheus Pods** | Backend / Frontend Pods | `8000/TCP`, `3000/TCP` | Scrape `/metrics` endpoints (when enabled) |

**Explicit Prohibitions**:
- Ingress controller cannot access Backend pods, Worker pods, or Migration jobs directly.
- Frontend pods cannot communicate with PostgreSQL or Redis.
- Worker pods do not accept any incoming connections (ingress is completely empty).
- Pods within the namespace cannot communicate with other namespaces except for CoreDNS in `kube-system`.

---

## 3. NetworkPolicy Definitions

When `networkPolicy.enabled: true` is set in Helm values, the chart generates 5 distinct NetworkPolicy resources:

### 3.1 Default Deny All (`{{ .Release.Name }}-default-deny`)
Applies to all pods matching `app.kubernetes.io/part-of: privguard`. Isolates all pods by default for both Ingress and Egress.

### 3.2 Frontend NetworkPolicy (`{{ .Release.Name }}-frontend`)
- **Ingress**: Allows traffic on port 3000 from:
  - Ingress controller pods matching `networkPolicy.ingressController.namespaceSelector` and `podSelector`.
  - Configurable ingress CIDRs.
- **Egress**:
  - Port 8000 to backend pods matching `app.kubernetes.io/name: privguard, app.kubernetes.io/component: backend`.
  - Port 53 (UDP & TCP) to DNS pods in `kube-system`.

### 3.3 Backend NetworkPolicy (`{{ .Release.Name }}-backend`)
- **Ingress**:
  - Port 8000 only from frontend pods matching `app.kubernetes.io/name: privguard, app.kubernetes.io/component: frontend`.
  - Port 8000 from monitoring pods matching `networkPolicy.monitoring.namespaceSelector` and `podSelector` (if enabled).
- **Egress**:
  - External PostgreSQL port (configurable, default `5432`).
  - External Redis port (configurable, default `6379`).
  - Port 53 (UDP & TCP) to CoreDNS.

### 3.4 Worker NetworkPolicy (`{{ .Release.Name }}-worker`)
- **Ingress**: Completely blocked (no ingress rules).
- **Egress**: External PostgreSQL (`5432`), External Redis (`6379`), and DNS (`53`).

### 3.5 Migration Job NetworkPolicy (`{{ .Release.Name }}-migration`)
- **Ingress**: Completely blocked.
- **Egress**: External PostgreSQL (`5432`) and DNS (`53`).

---

## 4. CNI Provider Compatibility

Kubernetes NetworkPolicies require a Container Network Interface (CNI) plugin with policy enforcement capabilities.

Supported and verified CNI providers:
- **AWS EKS**: AWS VPC CNI with Amazon VPC Network Policy controller enabled (`enableNetworkPolicy: "true"`), or Project Calico for EKS.
- **Google GKE**: GKE Dataplane V2 (eBPF / Cilium-based, default for GKE 1.24+).
- **Azure AKS**: Azure CNI powered by Cilium or Azure Network Policy Manager.
- **Self-Managed / Bare-Metal**: Cilium, Calico, or Weave Net.

> [!WARNING]
> Clusters running standard Flannel or AWS VPC CNI without the network policy agent ignore `NetworkPolicy` objects without reporting an error. Ensure your cluster CNI supports policy enforcement before relying on these rules in production.

---

## 5. Egress to Managed Database Services

When deploying to cloud providers where PostgreSQL (e.g., AWS RDS Aurora, Google Cloud SQL, Azure Flexible Server) or Redis (e.g., AWS ElastiCache, Google Cloud Memorystore) have public or VPC-peered endpoints:

Configure explicit CIDR blocks under `networkPolicy.egress`:
```yaml
networkPolicy:
  egress:
    postgresCidr: "10.0.0.0/16"
    redisCidr: "10.0.0.0/16"
```

If left unconstrained (`postgresCidr: "0.0.0.0/0"`), egress is permitted to the database port across all reachable IP destinations while restricting protocol to TCP port 5432/6379.
