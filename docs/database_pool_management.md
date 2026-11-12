# PostgreSQL Connection Pool Management & Tenant Isolation
## High-Concurrency Sizing, Health Checks & RLS Context Preservation
**Agency**: Moon Sanctum Labs — *Decode. Build. Evolve.*  

---

## 1. Connection Pool Sizing Strategy

PRIVGUARD AI uses SQLAlchemy 2.0 with the `asyncpg` asynchronous PostgreSQL driver. Production workloads are configured with parameters balanced for high concurrency without overwhelming PostgreSQL:

```python
engine = create_async_engine(
    settings.DATABASE_URL,
    pool_size=20,           # Baseline permanent connection pool
    max_overflow=10,        # Additional burst connections during traffic spikes
    pool_timeout=30.0,      # Seconds to wait before raising TimeoutError
    pool_recycle=1800,      # Recycle connections every 30 minutes to prevent stale sockets
    pool_pre_ping=True,     # Verify connection health (SELECT 1) before checkout
)
```

With 3 backend replicas:
- Standard maximum pool per instance: 20 connections + 10 overflow = 30 connections.
- Total cluster connections to PostgreSQL: $3 \times 30 = 90$ connections.
- Fits comfortably within PostgreSQL's default `max_connections = 100` setting (with headroom for migrator and admin connections).

---

## 2. Preventing Cross-Tenant Session Contamination

Because connections are pooled and reused across different web requests, setting connection-level variables without proper cleanup creates severe cross-tenant security vulnerabilities:
If Request A sets `app.current_tenant_id = 'tenant_1'` and the connection is checked back in without reset, Request B might execute with Tenant 1's RLS permissions!

### Safeguards Implemented:
1. **Transaction-Local Setting (`SET LOCAL`)**:
   PRIVGUARD uses `SET LOCAL app.current_tenant_id = '{safe_tenant_id}';`. In PostgreSQL, `SET LOCAL` is automatically discarded when the transaction commits or rolls back.
2. **Deterministic Cleanup in `finally:`**:
   `get_db_session` wraps session lifecycle in a `try...finally` block. Upon session teardown, it explicitly calls `reset_db_tenant_context(session)` executing `RESET app.current_tenant_id;`.
3. **Pre-Ping Verification (`pool_pre_ping=True`)**:
   Ensures dead or aborted connections are recycled before serving new requests.

---

## 3. Real-Time Pool Diagnostics

The operational probe `GET /health/database` and `GET /v1/system/distributed-state` expose real-time metrics from `get_pool_status()`:
```json
{
  "pool_type": "AsyncAdaptedQueuePool",
  "is_postgres": true,
  "pool_size": 20,
  "checked_in": 19,
  "checked_out": 1,
  "overflow": 0
}
```
This allows Kubernetes HPA and Prometheus monitors to track pool saturation and detect connection leaks immediately.
