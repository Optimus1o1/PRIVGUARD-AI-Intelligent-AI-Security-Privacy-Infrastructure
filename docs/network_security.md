# PRIVGUARD AI — Network Security & Isolation Architecture

**Moon Sanctum Labs** — *Decode. Build. Evolve.*  
**Author**: [ANIKET NANDI] ([KOLKATA], [IST])  
**Date**: November 2026  

---

## 1. Multi-Tier Network Segmentation

PRIVGUARD AI establishes three distinct network segments using Docker bridge networks:

```
+-------------------------------------------------------------------------------+
|  EDGE NETWORK (Public Ingress)                                                |
|  - reverse_proxy (Port 80/443 Published)                                      |
|  - frontend (Internal Port 3000)                                              |
+-------------------------------------------------------------------------------+
                                  |
+-------------------------------------------------------------------------------+
|  APPLICATION NETWORK (Internal Bridge, internal: true)                        |
|  - frontend (Client to backend:8000)                                          |
|  - backend (FastAPI ASGI Server)                                              |
+-------------------------------------------------------------------------------+
                                  |
+-------------------------------------------------------------------------------+
|  DATA NETWORK (Internal Bridge, internal: true, No External Egress)           |
|  - backend (Client to postgres:5432 and redis:6379)                           |
|  - migrate (Client to postgres:5432)                                          |
|  - postgres (PostgreSQL 16 Server)                                            |
|  - redis (Redis 7.x Server)                                                   |
+-------------------------------------------------------------------------------+
```

---

## 2. Ingress & Egress Rules

| Service | Inbound Allowed From | Outbound Allowed To | Public Ports |
|---|---|---|---|
| `reverse_proxy` | Public Internet (`0.0.0.0/0`) | `frontend:3000` | `80`, `443` |
| `frontend` | `reverse_proxy:3000` | `backend:8000` | **None** |
| `backend` | `frontend:8000` | `postgres:5432`, `redis:6379`, Upstream LLM APIs | **None** |
| `migrate` | Docker Compose runner | `postgres:5432` | **None** |
| `postgres` | `backend:5432`, `migrate:5432` | None (Isolated data network) | **None** |
| `redis` | `backend:6379` | None (Isolated data network) | **None** |

---

## 3. Defense Against SSRF & Direct Access

1. **No Public Database Exposure**: Neither PostgreSQL nor Redis publishes host ports in `compose.yaml` or `compose.production.yaml`.
2. **Backend Gateway Isolation**: The FastAPI backend cannot be reached directly by external internet traffic; all traffic must pass through the Next.js BFF proxy.
3. **Data Network Confinement**: The `data` network is configured with `internal: true`. A compromised database container cannot establish outbound reverse shells or exfiltrate data to the internet.
