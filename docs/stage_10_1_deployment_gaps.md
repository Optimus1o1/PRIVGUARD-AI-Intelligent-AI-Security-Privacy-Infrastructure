# PRIVGUARD AI — Stage 10.1: Deployment Gaps & Infrastructure Requirements

**Moon Sanctum Labs** — *Decode. Build. Evolve.*  
**Author**: [ANIKET NANDI] ([KOLKATA], [IST])  
**Baseline Git Commit**: `a1f6ae8`  
**Date**: November 2026  

---

## 1. Overview

While PRIVGUARD AI possesses an advanced security and privacy engine, it is currently packaged as a local development workspace. This document specifies the **deployment blockers**, **recommended deployment topologies**, and **infrastructure requirements** necessary to transition PRIVGUARD into production infrastructure.

---

## 2. Deployment Blockers

### Blocker 1: Missing Containerization & Packaging (Stage 10.2)
- **Current State**: Zero Dockerfiles exist in the repository. Running the backend requires a manual Python 3.12 virtual environment; running the frontend requires Node.js and npm directly on the host.
- **Production Impact**: Non-reproducible host dependencies, risk of environment drift, inability to deploy via container registries (GHCR, ECR, GCR), and lack of non-root process confinement.
- **Required Remediation**:
  - Multi-stage `Dockerfile.backend` (distroless/Alpine base, non-root user `privguard:privguard`, pinned dependencies).
  - Multi-stage `Dockerfile.frontend` (Next.js standalone output, non-root user `nextjs:nodejs`).
  - Production `docker-compose.yml` with healthchecks, environment variable loading, volume mounts, and network isolation.

### Blocker 2: Absence of Database Migration Tooling (Stage 10.3)
- **Current State**: Schema creation relies entirely on SQLAlchemy's `Base.metadata.create_all(bind=engine)` during FastAPI startup (`backend/app/main.py:lifespan`).
- **Production Impact**:
  - `create_all` does not modify existing tables, alter column types, add foreign keys, or rename columns without dropping tables and causing data loss.
  - Zero rollback capability if a new deployment encounters database corruption or schema mismatch.
  - In a multi-node horizontal deployment, concurrent startup will trigger race conditions on DDL creation.
- **Required Remediation**:
  - Initialize Alembic (`alembic init -t async migrations`).
  - Auto-generate initial migration baseline capturing all 25 tables.
  - Ensure migrations run as an init-container or pre-deployment job rather than inside web worker lifespans.

### Blocker 3: Lack of Distributed Caching & Coordination (Stage 10.3)
- **Current State**: All state transitions (capability tracking, rate limits, approvals, session contexts) hit the relational database directly or remain process-local in memory.
- **Production Impact**:
  - Under load (e.g. >100 RPS), capability token lookups and audit ledger writes saturate database connection pools.
  - In a multi-replica deployment, agent task taints and fleet sync events cannot be broadcast between nodes without polling the database.
- **Required Remediation**:
  - Integrate Redis 7.x (`redis-py` / `aioredis`).
  - Implement Redis-backed distributed token bucket rate limiter.
  - Implement Redis Pub/Sub for fleet policy broadcast and immediate killswitch distribution.

### Blocker 4: Absence of Automated CI/CD Pipelines (Stage 10.7)
- **Current State**: No `.github/workflows/` or automated verification pipelines exist. Tests and builds are executed manually.
- **Production Impact**: No continuous verification of pull requests, risk of committing breaking changes, lack of automated container vulnerability scanning (Trivy, Grype), and no automated artifact signing (Sigstore/Cosign).
- **Required Remediation**:
  - Build GitHub Actions workflow for backend linting (`ruff`), typechecking (`mypy`), and testing (`pytest`).
  - Build GitHub Actions workflow for frontend linting and Next.js build.
  - Automated container image building and vulnerability scanning.

### Blocker 5: Unpackaged Client SDK (Stage 10.9)
- **Current State**: Internal SDK files exist inside `backend/app/sdk/` but cannot be installed via `pip install privguard`.
- **Production Impact**: Client applications must manually construct HTTP requests and sign headers rather than importing a high-performance Python client SDK.
- **Required Remediation**:
  - Decouple SDK into standalone directory `sdk/python/` with dedicated `pyproject.toml`.
  - Provide asynchronous and synchronous client classes (`PrivGuardClient`, `AsyncPrivGuardClient`).
  - Automated build and packaging scripts for PyPI distribution.

### Blocker 6: Missing Disaster Recovery & Backup Automation (Stage 10.10)
- **Current State**: No database backup or recovery scripts exist.
- **Production Impact**: Failure of the primary database host results in permanent data loss and cryptographic key loss, invalidating encrypted memory vaults and audit hash chains.
- **Required Remediation**:
  - Automated WAL-G or pgBackRest physical backup integration for PostgreSQL.
  - Point-In-Time Recovery (PITR) verification runbooks.
  - Key backup and recovery protocols.

---

## 3. Recommended Deployment Topologies

To accommodate both single-developer deployments and enterprise multi-tenant organizations, PRIVGUARD defines two production topologies:

### Topology A: Single-Node Developer & SMB Deployment (Stage 10.2)
Targeted at independent developers and small teams seeking a self-contained, low-maintenance deployment.

```
                           +----------------------------+
                           |       Reverse Proxy        |
                           |   (Caddy / Nginx / Envoy)  |
                           |  Port 80/443 (Let's Encrypt)|
                           +--------------+-------------+
                                          |
                      +-------------------+-------------------+
                      |                                       |
                      v                                       v
          +-----------------------+               +-----------------------+
          |  Frontend Container   |               |   Backend Container   |
          |  (Next.js Standalone) |  /api/backend |     (FastAPI ASGI)    |
          |       Port 3000       +-------------->+       Port 8000       |
          +-----------------------+               +-----------+-----------+
                                                              |
                                      +-----------------------+-----------------------+
                                      |                                               |
                                      v                                               v
                          +-----------------------+                       +-----------------------+
                          |  PostgreSQL 16 (RLS)  |                       |       Redis 7.x       |
                          |       Port 5432       |                       |       Port 6379       |
                          | (Persistent Volume)   |                       | (Rate Limiting/Cache) |
                          +-----------------------+                       +-----------------------+
```

### Topology B: Enterprise High-Availability Distributed Deployment (Stages 10.3 & 10.4)
Targeted at multi-tenant enterprises requiring horizontal autoscaling, high availability, and geographic redundancy.

```
                           +----------------------------+
                           | Cloud Load Balancer (WAF)  |
                           +--------------+-------------+
                                          |
                                          v
                           +----------------------------+
                           |   Kubernetes Ingress (TLS) |
                           +--------------+-------------+
                                          |
                      +-------------------+-------------------+
                      |                                       |
                      v                                       v
          +-----------------------+               +-----------------------+
          | Frontend Deployment   |               | Backend Deployment    |
          | (3 Replicas - HPA)    |               | (5-20 Replicas - HPA) |
          +-----------------------+               +-----------+-----------+
                                                              |
                                  +---------------------------+---------------------------+
                                  |                                                       |
                                  v                                                       v
                    +---------------------------+                           +---------------------------+
                    | Managed PostgreSQL HA     |                           | Redis Cluster / Sentinel  |
                    | (Primary + Read Replicas) |                           | (Multi-AZ In-Memory Store)|
                    | AWS Aurora / Cloud SQL    |                           | ElastiCache / Memorystore |
                    +---------------------------+                           +---------------------------+
                                  |                                                       |
                                  +---------------------------+---------------------------+
                                                              |
                                                              v
                                                +---------------------------+
                                                | External Key Vault (KMS)  |
                                                | AWS KMS / Vault / CloudKMS|
                                                +---------------------------+
```

---

## 4. Required Infrastructure Specifications

### Minimum Hardware Sizing (Single-Node Compose)
- **CPU**: 2 vCPUs (AMD64 or ARM64).
- **RAM**: 4 GB RAM (1 GB Backend, 512 MB Frontend, 1 GB PostgreSQL, 512 MB Redis, 1 GB System/OS).
- **Disk**: 50 GB SSD (ext4/NVMe), dedicated volume mounts for PostgreSQL `/var/lib/postgresql/data` and audit logs.
- **Network**: 100 Mbps egress, static IPv4/IPv6, inbound ports 80/443.

### Recommended Enterprise Hardware Sizing (Kubernetes)
- **Backend Pods**: 0.5 CPU request, 1.0 CPU limit; 512 MiB RAM request, 1024 MiB RAM limit per replica.
- **Frontend Pods**: 0.25 CPU request, 0.5 CPU limit; 256 MiB RAM request, 512 MiB RAM limit per replica.
- **Database (PostgreSQL 16)**: 4 vCPU, 16 GB RAM, 250 GB IOPS-provisioned SSD storage with daily snapshots and 7-day PITR retention.
- **Cache (Redis 7.x Cluster)**: 3-node cluster, 2 vCPU, 8 GB RAM with AOF persistence.

---

## 5. Summary of Remediation Sequence

1. **Stage 10.2**: Docker Containerization & Production Compose (Remediates Blocker 1).
2. **Stage 10.3**: PostgreSQL HA, Alembic Migrations & Redis Caching (Remediates Blockers 2 & 3).
3. **Stage 10.4**: Kubernetes Deployment & Helm Charts.
4. **Stage 10.5**: Enterprise KMS Key Management.
5. **Stage 10.6**: Observability, OpenTelemetry & Prometheus Metrics.
6. **Stage 10.7**: Supply-Chain Security & GitHub Actions CI/CD (Remediates Blocker 4).
7. **Stage 10.8**: Compliance Readiness & Audit Evidence Engine.
8. **Stage 10.9**: Python SDK Packaging & Distribution (Remediates Blocker 5).
9. **Stage 10.10**: Disaster Recovery, PITR & Production Validation (Remediates Blocker 6).
