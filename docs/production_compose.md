# PRIVGUARD AI — Production Compose Architecture

**Moon Sanctum Labs** — *Decode. Build. Evolve.*  
**Author**: [ANIKET NANDI] ([KOLKATA], [IST])  
**Date**: November 2026  

---

## 1. Compose Configuration Files

PRIVGUARD AI provides a layered Docker Compose setup:
- [`compose.yaml`](file:///C:/Users/ANIKET/OneDrive/Documents/RIVA_AI/compose.yaml): Base service definitions, volume mounts, Docker secrets, and three-tier network topologies.
- [`compose.production.yaml`](file:///C:/Users/ANIKET/OneDrive/Documents/RIVA_AI/compose.production.yaml): Hardening overrides containing resource limits, read-only root filesystems, and process confinement.

---

## 2. Service Definitions & Responsibilities

| Service | Image | Network Placement | Published Ports | Responsibility |
|---|---|---|---|---|
| `reverse_proxy` | `caddy:2-alpine` | `edge` | `80:80`, `443:443` | Public TLS ingress, HTTP-to-HTTPS redirect, security headers, reverse proxy to frontend. |
| `frontend` | `privguard/frontend:0.1.0` | `edge`, `application` | None (3000 internal) | Next.js 14 standalone dashboard, server-side BFF route proxying. |
| `backend` | `privguard/backend:0.1.0` | `application`, `data` | None (8000 internal) | FastAPI ASGI security gateway, LLM mediation, privacy engine, policy engine. |
| `migrate` | `privguard/backend:0.1.0` | `data` | None (ephemeral) | One-shot Alembic migration runner (`alembic upgrade head`). |
| `postgres` | `postgres:16-alpine` | `data` | None (5432 internal) | Persistent relational store enforcing PostgreSQL Row-Level Security. |
| `redis` | `redis:7-alpine` | `data` | None (6379 internal) | Isolated cache and coordination store with ACL password authentication. |

---

## 3. Startup Orchestration Graph

To avoid startup race conditions and connection failure loops, PRIVGUARD defines explicit healthcheck-based dependencies:

```
[postgres] (healthy via pg_isready)
     |
     v
[migrate] (alembic upgrade head completes successfully)
     |
     +-----------------------+
     |                       |
     v                       v
[backend] (healthy via /health/live)    [redis] (healthy via redis-cli ping)
     |
     v
[frontend] (healthy via Next.js port probe)
     |
     v
[reverse_proxy] (ready to accept public traffic on 80/443)
```

---

## 4. Resource Allocation & Limits

Configured in `compose.production.yaml`:

| Service | CPU Request | CPU Limit | Memory Request | Memory Limit | Read-Only Root |
|---|---|---|---|---|---|
| `reverse_proxy` | 0.2 CPU | 1.0 CPU | 64 MB | 256 MB | False |
| `frontend` | 0.2 CPU | 1.0 CPU | 128 MB | 512 MB | False |
| `backend` | 0.5 CPU | 2.0 CPU | 256 MB | 1024 MB | **True** (tmpfs on `/tmp`) |
| `migrate` | — | 1.0 CPU | — | 512 MB | **True** (tmpfs on `/tmp`) |
| `postgres` | 0.5 CPU | 2.0 CPU | 512 MB | 2048 MB | False |
| `redis` | 0.2 CPU | 1.0 CPU | 128 MB | 512 MB | False |
