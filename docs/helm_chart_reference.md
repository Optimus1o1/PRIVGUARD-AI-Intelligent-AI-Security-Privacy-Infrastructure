# PRIVGUARD AI — Helm Chart Reference
## Complete Values Specification & Parameter Catalog
**Agency**: Moon Sanctum Labs — *Decode. Build. Evolve.*  

---

## 1. Global Values (`global`)

| Parameter | Type | Default | Description |
|---|---|---|---|
| `global.environment` | string | `"production"` | Deployment environment (`production`, `staging`, `development`). |
| `global.debug` | boolean | `false` | Enable verbose debugging (rejected in production). |
| `global.failClosedMode` | boolean | `true` | Enforce fail-closed security across inspection subsystems. |
| `global.maxRequestSizeBytes` | integer | `10485760` | Maximum allowable payload size (10 MB). |
| `global.corsAllowedOrigins` | list | `["https://privguard.internal"]` | Whitelisted browser CORS origins. |
| `global.imagePullSecrets` | list | `[]` | Secret references for private container registries. |
| `global.appVersion` | string | `"0.1.0"` | Override chart application version. |

---

## 2. Backend Values (`backend`)

| Parameter | Type | Default | Description |
|---|---|---|---|
| `backend.replicaCount` | integer | `2` | Number of backend FastAPI pods. |
| `backend.image.repository` | string | `"privguard/backend"` | Image repository. |
| `backend.image.tag` | string | `""` | Image tag (defaults to `Chart.AppVersion`). |
| `backend.service.port` | integer | `8000` | Internal ClusterIP port. |
| `backend.securityContext.runAsUser` | integer | `10001` | Non-root UID for backend container. |
| `backend.resources.requests.cpu` | string | `"250m"` | CPU request. |
| `backend.resources.requests.memory` | string | `"256Mi"` | Memory request. |
| `backend.autoscaling.enabled` | boolean | `false` | Enable HorizontalPodAutoscaler (requires Metrics Server). |
| `backend.podDisruptionBudget.enabled` | boolean | `true` | Enable PodDisruptionBudget. |

---

## 3. Frontend Values (`frontend`)

| Parameter | Type | Default | Description |
|---|---|---|---|
| `frontend.replicaCount` | integer | `2` | Number of Next.js frontend BFF pods. |
| `frontend.image.repository` | string | `"privguard/frontend"` | Image repository. |
| `frontend.service.port` | integer | `3000` | ClusterIP port for frontend service. |
| `frontend.securityContext.runAsUser` | integer | `1001` | Non-root UID for Next.js container. |
| `frontend.resources.requests.cpu` | string | `"100m"` | CPU request. |
| `frontend.resources.requests.memory` | string | `"128Mi"` | Memory request. |

---

## 4. Worker & Database Values (`worker`, `migration`, `database`, `redis`)

| Parameter | Type | Default | Description |
|---|---|---|---|
| `worker.enabled` | boolean | `true` | Deploy background event worker for outbox relay. |
| `worker.replicaCount` | integer | `2` | Number of worker replicas. |
| `migration.enabled` | boolean | `true` | Run Alembic schema migration Job before upgrade. |
| `database.host` | string | `"postgres.database.svc.cluster.local"` | PostgreSQL endpoint. |
| `database.port` | integer | `5432` | PostgreSQL port. |
| `database.user` | string | `"privguard_app"` | Runtime application database role. |
| `database.migrationUser` | string | `"privguard_migrator"` | Migration Job database role. |
| `database.existingSecret` | string | `"privguard-database-credentials"` | Secret name holding `postgres_password`. |
| `redis.host` | string | `"redis.cache.svc.cluster.local"` | Redis endpoint. |
| `redis.existingSecret` | string | `"privguard-redis-credentials"` | Secret name holding `redis_password`. |
| `secrets.existingSecret` | string | `"privguard-secrets"` | Secret name holding master encryption key. |
