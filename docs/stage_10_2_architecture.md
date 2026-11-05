# PRIVGUARD AI — Stage 10.2: Architecture Specification

**Moon Sanctum Labs** — *Decode. Build. Evolve.*  
**Author**: [ANIKET NANDI] ([KOLKATA], [IST])  
**Baseline Git Commit**: `8a85433`  
**Date**: November 2026  

---

## 1. System Architecture Overview

Stage 10.2 transforms PRIVGUARD AI from a local developer setup into a hardened, reproducible containerized deployment. The target architecture establishes three physically isolated network zones with zero direct public access to backend application services, PostgreSQL databases, or Redis caches.

```
+-----------------------------------------------------------------------------------+
|                                  PUBLIC INTERNET                                  |
+-----------------------------------------------------------------------------------+
                                         |
                                         | HTTPS (Port 443) / HTTP (Port 80 -> TLS Redirect)
                                         v
+-----------------------------------------------------------------------------------+
|  ZONE 1: EDGE NETWORK (Public Facing Ingress)                                     |
|                                                                                   |
|  +-----------------------------------------------------------------------------+  |
|  | reverse_proxy (Caddy 2 on Alpine)                                           |  |
|  | - Automatic TLS (Let's Encrypt / ACME)                                      |  |
|  | - Security Headers: HSTS, CSP, X-Frame-Options: DENY, X-Content-Type: nosniff |  |
|  | - Request Body Size Cap: 10 MB                                               |  |
|  | - Upstream target: frontend:3000 (Internal only)                            |  |
|  +-------------------------------------+---------------------------------------+  |
|                                        |                                          |
+----------------------------------------|------------------------------------------+
                                         | Internal Reverse Proxy (Port 3000)
                                         v
+-----------------------------------------------------------------------------------+
|  ZONE 2: APPLICATION NETWORK (Internal Only)                                      |
|                                                                                   |
|  +-------------------------------------+---------------------------------------+  |
|  | frontend (Next.js 14 Standalone)    |                                       |  |
|  | - Base: node:20-alpine (Non-root)   |                                       |  |
|  | - Dedicated User: nextjs:nodejs     |                                       |  |
|  | - Port 3000 (Exposed internally)   |                                       |  |
|  | - BFF Proxy Handler                 |                                       |  |
|  +-------------------------------------+---------------------------------------+  |
|                                        |                                          |
|                                        | Internal BFF API Traffic (Port 8000)     |
|                                        v                                          |
|  +-----------------------------------------------------------------------------+  |
|  | backend (FastAPI / Uvicorn ASGI)                                            |  |
|  | - Base: python:3.12-slim (Non-root) |                                       |  |
|  | - Dedicated User: privguard:privguard                                       |  |
|  | - Port 8000 (Exposed internally)   |                                       |  |
|  | - Read-only root filesystem         |                                       |  |
|  +-------------------------------------+---------------------------------------+  |
|                                        |                                          |
+----------------------------------------|------------------------------------------+
                                         |
                                         | Internal Data Access (Ports 5432 / 6379)
                                         v
+-----------------------------------------------------------------------------------+
|  ZONE 3: DATA NETWORK (Internal Only, No Internet Egress)                         |
|                                                                                   |
|  +----------------------------+  +-------------------+  +----------------------+  |
|  | postgres (PostgreSQL 16)   |  | redis (Redis 7.x) |  | migrate (Alembic)    |  |
|  | - Row-Level Security (RLS) |  | - ACL Auth        |  | - One-shot runner    |  |
|  | - Runtime User: privguard  |  | - Append-Only AOF |  | - User: migrator     |  |
|  | - Persistent Volume        |  | - Memory limits   |  | - DDL Privileges     |  |
|  +----------------------------+  +-------------------+  +----------------------+  |
+-----------------------------------------------------------------------------------+
```

---

## 2. Security Invariants & Boundaries

1. **Edge Boundary**:
   - Only Caddy publishes public ports (`80` and `443`).
   - Caddy acts as a layer-7 reverse proxy routing exclusively to the Next.js frontend container (`frontend:3000`).
   - The FastAPI backend gateway (`backend:8000`), PostgreSQL database (`postgres:5432`), and Redis server (`redis:6379`) are completely unreachable from outside the Docker host network.

2. **Application Boundary**:
   - The Next.js Backend-For-Frontend (BFF) proxy resides in both the `edge` and `application` networks.
   - Browser clients interact only with `/api/backend/*` routes; API keys and backend tokens remain strictly server-side.
   - The FastAPI backend gateway resides in the `application` and `data` networks.

3. **Data Boundary**:
   - The `data` network is marked `internal: true`, blocking container egress to the public internet.
   - PostgreSQL and Redis accept connections exclusively from containers attached to the `data` network (`backend`, `migrate`).

4. **Principle of Least Privilege for Database Roles**:
   - **Bootstrap Role (`postgres`)**: Used only for initial container initialization and role provisioning.
   - **Migration Role (`privguard_migrator`)**: Has schema ownership and DDL rights; executes one-shot migrations before application startup.
   - **Runtime Application Role (`privguard_app`)**: Granted only DML rights (`SELECT`, `INSERT`, `UPDATE`, `DELETE`). Strictly configured with `NOBYPASSRLS` and `NOSUPERUSER` to guarantee that PostgreSQL Row-Level Security cannot be bypassed.

5. **Non-Root Execution & Read-Only Confinement**:
   - Backend runs as non-root user `privguard:privguard` (UID 10001, GID 10001) with `read_only: true` and temporary scratch storage mounted via tmpfs on `/tmp`.
   - Frontend runs as non-root user `nextjs:nodejs` (UID 1001, GID 1001).
   - Containers enforce `no-new-privileges:true`.
