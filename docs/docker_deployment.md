# PRIVGUARD AI — Docker Deployment Guide

**Moon Sanctum Labs** — *Decode. Build. Evolve.*  
**Author**: [ANIKET NANDI] ([KOLKATA], [IST])  
**Date**: November 2026  

---

## 1. Prerequisites

Before deploying PRIVGUARD AI via Docker:
- **Docker Engine**: Version 24.0.0 or higher.
- **Docker Compose**: Version 2.20.0 or higher (Compose V2).
- **Architecture**: AMD64 or ARM64 (Apple Silicon / AWS Graviton supported).
- **RAM**: Minimum 4 GB available memory.
- **Disk**: Minimum 20 GB free disk space.

---

## 2. Quickstart Deployment (Local Development)

### Step 1: Initialize Deployment Secrets
Generate cryptographically secure 256-bit secrets using the initialization script:

```bash
python scripts/init_secrets.py --dir ./secrets
```

This creates the required secret files inside `./secrets/`:
- `privguard_master_key.txt`: Master key for Fernet and AES-256-GCM envelope encryption.
- `postgres_password.txt`: Password for PostgreSQL database.
- `migration_password.txt`: Password for Alembic schema migration role.
- `redis_password.txt`: Authentication token for Redis 7.x.
- `privguard_admin_api_key.txt`: Initial administrative API key.
- `ed25519_policy_signing.key`: Asymmetric private key for signing policy bundles.
- `ed25519_policy_signing.pub`: Public key for fleet policy bundle verification.

### Step 2: Configure Environment Variables
Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

Ensure `PRIVGUARD_DOMAIN` is set to your hostname or `localhost`:
```ini
PRIVGUARD_DOMAIN=localhost
PORT_HTTP=80
PORT_HTTPS=443
```

### Step 3: Start Services with Docker Compose
Start the base stack:

```bash
docker compose up -d --build
```

Compose executes the startup sequence:
1. `postgres` starts and completes healthcheck.
2. `migrate` runs `alembic upgrade head` and exits with code 0.
3. `backend` and `redis` start and become healthy.
4. `frontend` starts and becomes healthy.
5. `reverse_proxy` binds to ports 80/443 and routes traffic to the frontend.

### Step 4: Verify Deployment
Check service status:

```bash
docker compose ps
```

Verify backend liveness and readiness:
```bash
curl -i http://localhost/health/live
curl -i http://localhost/health/ready
```

Open the PRIVGUARD Control Center in your browser at:
`https://localhost` (or `http://localhost`).

---

## 3. Production Deployment

For production environments, merge the hardened override configuration:

```bash
docker compose -f compose.yaml -f compose.production.yaml up -d --build
```

### Production Guarantees Enforced:
- **Read-Only Root Filesystem**: Backend and migration containers run with read-only root filesystems and constrained tmpfs mounts.
- **Resource Constraints**: Strict CPU limits and memory quotas prevent noisy neighbor attacks.
- **Process Security**: Enforces `no-new-privileges:true`.
- **Database Role Separation**: Runtime application connects as `privguard_app` with `NOBYPASSRLS`.

---

## 4. Maintenance & Operations

### Viewing Logs
```bash
# Stream all logs
docker compose logs -f

# View backend security gateway logs
docker compose logs -f backend

# View reverse proxy access logs
docker compose logs -f reverse_proxy
```

### Applying Database Migrations
When upgrading to a new release:
```bash
docker compose run --rm migrate alembic upgrade head
```

### Stopping Services
```bash
docker compose down
```

To stop services and remove volumes (Warning: destroys persistent data):
```bash
docker compose down -v
```

### Launching the Observability Stack
To enable OpenTelemetry Collector, Prometheus, Grafana, Loki, and Alertmanager alongside PRIVGUARD:

```bash
docker compose -f compose.yaml -f compose.observability.yaml up -d
```

- **Grafana Dashboards**: Access at `http://localhost:3001` (Default: `admin` / `admin`).
- **Prometheus Metrics**: Scraped at `http://localhost:8000/metrics`.
- **Loki Log Ingestion**: Listening on port `3100`.
- **Alertmanager UI**: Accessible on port `9093`.
- **Next.js Monitoring Console**: Access at `http://localhost:3000/monitoring`.

---

## 5. Moving to Kubernetes (Enterprise Fleet Scale)

For enterprise high-availability deployments requiring horizontal multi-pod scaling, automatic healing, and cloud-neutral deployment on AWS EKS, Google GKE, Azure AKS, or self-managed clusters, use the PRIVGUARD Helm chart:

- Complete guide: [kubernetes_deployment.md](file:///c:/Users/ANIKET/OneDrive/Documents/RIVA_AI/docs/kubernetes_deployment.md)
- Helm chart reference: [helm_chart_reference.md](file:///c:/Users/ANIKET/OneDrive/Documents/RIVA_AI/docs/helm_chart_reference.md)
- Security architecture: [kubernetes_security.md](file:///c:/Users/ANIKET/OneDrive/Documents/RIVA_AI/docs/kubernetes_security.md)
