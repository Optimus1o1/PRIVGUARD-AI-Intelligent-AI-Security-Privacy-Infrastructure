# PRIVGUARD AI

> **Moon Sanctum Labs** — *Decode. Build. Evolve.*

PRIVGUARD AI is an independent security and privacy enforcement layer positioned between AI applications, untrusted data sources, external foundation models, and agent execution tools.

---

## Core Guarantees & Invariants

1. **Security-First & Fail-Closed:** If any inspection subsystem fails or returns an unknown category, requests are unconditionally blocked.
2. **Zero Secrets in Model Context:** API keys (OpenAI, Anthropic, AWS, GitHub, Slack), private keys, and database connection strings are intercepted and blocked before leaving the perimeter.
3. **Reversible PII Minimization:** Personal Identifiable Information (emails, phone numbers, credit cards, SSNs) is replaced with ephemeral placeholders (`<EMAIL_1>`) and de-redacted upon return.
4. **Content-Free Audit Trails:** Raw prompts, completions, and sensitive strings are never stored in audit logs. Logs store cryptographic SHA-256 fingerprints, timestamps, and entity counts.
5. **Ultra-Low Latency Overhead:** Inspection pipeline operates at under **0.25ms P95 latency** locally.

6. **Buffer-Before-Stream SSE Streaming:** Streams are buffered and reconstructed to detect credentials split across chunks before emitting SSE events to the client.
7. **Bidirectional Response Inspection:** Model outputs are treated as untrusted data and scanned for leaked secrets and prompt extraction attacks.
8. **SSRF-Proof Provider Isolation:** Client cannot specify remote upstream URLs; all endpoints resolve through server-side provider registry.
9. **Autonomous AI Threat Defense:** Deterministic prompt injection detection, untrusted content sanitization, sliding-window agent behavior monitoring, and MITRE ATT&CK T1700 exfiltration taint tracking.
10. **Secure Personal AI Memory Vault:** User-controlled personal memory protected by AES-256-GCM envelope encryption, HKDF-SHA256 derived KEKs, staged human consent proposals, and irreversible cryptographic erasure. Zero AI training usage.
11. **MCP 2026-07-28 Security Gateway:** Zero-trust enforcement layer mediating autonomous AI agents and external tools connected via the Model Context Protocol. Enforces Streamable HTTP header routing, destination SSRF validation, tool description poisoning defense, catalog drift quarantine, and sandboxed stdio isolation.
12. **Enterprise Multi-Tenancy & Fleet Governance:** Complete organization-level data isolation via PostgreSQL Row-Level Security (`FORCE ROW LEVEL SECURITY`), enterprise SSO (OIDC/SAML2), SCIM 2.0 provisioning with immediate revocation, 8-role RBAC with separation of duties, departmental workspaces, central Ed25519-signed policy bundles with anti-downgrade defense, fleet drift monitoring, and tamper-evident SHA-256 hash-chained audit ledgers.
13. **Hardened Docker & Production Deployment Packaging:** Multi-stage, non-root container images (`privguard:privguard`, `nextjs:nodejs`), three-tier isolated networks (`edge`, `application`, `data`), one-shot Alembic schema migration runner, PostgreSQL 16 with RLS and non-superuser runtime role (`privguard_app`), Redis 7.x, Caddy reverse proxy with automated TLS, and Docker Compose secret file management.
14. **Distributed State & PostgreSQL-Authoritative Coordination:** Atomic Redis Lua sliding-window rate limiting with fail-safe local fallback, Transactional Outbox pattern with secret sanitization, persistent Redis Streams event bus with consumer group idempotency, cross-replica authoritative agent revocation, monotonic distributed taint tracking (MITRE ATT&CK T1700), connection pool tenant isolation, and dedicated background event worker.
15. **Cloud-Neutral Kubernetes & Helm Deployment Packaging:** Turnkey deployment on AWS EKS, Google GKE, Azure AKS, and self-managed Kubernetes via hardened Helm v3/v4 charts (`deploy/helm/privguard/`). Enforces Kubernetes Restricted Pod Security Standard (`runAsNonRoot: true`, `readOnlyRootFilesystem: true`, capabilities drop `ALL`, runtime seccomp), default-deny micro-segmentation NetworkPolicies, external secret isolation (`existingSecret`), pre-rollout Alembic migration hook Jobs with isolated DDL credentials (`privguard_migrator`), zero-downtime PodDisruptionBudgets, and HPA v2 horizontal autoscaling.
16. **Zero-Content Observability & Active Security Canaries:** Production-grade OpenTelemetry tracing, low-cardinality Prometheus metrics, Loki structured logging with inline credential scrubbing (`RedactionFilter`), and 8 active synthetic security canaries verifying that security controls continuously fail closed. Zero raw prompts, completions, memory plaintext, tool argument secrets, or API keys in telemetry. Includes 7 auto-provisioned Grafana dashboards, multi-window error budget burn rate alerting, SSRF-protected SIEM export (Splunk HEC, Elastic ECS, Microsoft Sentinel), and Next.js 14 Monitoring Control Center.

---

## Quickstart

### Option A: Docker Deployment (Recommended for Single-Node)
```bash
# 1. Initialize cryptographically secure deployment secrets
python scripts/init_secrets.py --dir ./secrets

# 2. Start the isolated multi-service stack
docker compose up -d --build
```
Access the Control Center at `https://localhost` or `http://localhost`.

### Option B: Kubernetes Helm Deployment (Enterprise Multi-Node Production)
```bash
# 1. Provision required secrets
kubectl create namespace privguard
kubectl create secret generic privguard-database-credentials -n privguard \
  --from-literal=postgres_password='<APP_PASSWORD>' \
  --from-literal=migration_password='<MIGRATOR_PASSWORD>'
kubectl create secret generic privguard-redis-credentials -n privguard \
  --from-literal=redis_password='<REDIS_PASSWORD>'
kubectl create secret generic privguard-secrets -n privguard \
  --from-literal=privguard_master_key='<MASTER_KEY>' \
  --from-literal=privguard_admin_api_key='<ADMIN_KEY>'

# 2. Deploy using production values profile
helm install privguard ./deploy/helm/privguard \
  --namespace privguard \
  -f ./deploy/helm/privguard/values/production.yaml
```

### Option C: Local Python Development

#### 1. Requirements
- Python 3.12+
- SQLite (built-in WAL mode) or PostgreSQL 16

#### 2. Setup Environment
```bash
python -m venv .venv
.\.venv\Scripts\activate
pip install -r backend/requirements.txt
```

#### 3. Run Test Suite
```bash
pytest backend/tests -q
```

#### 4. Start the Security Gateway
```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

Interactive API documentation will be available at:
`http://127.0.0.1:8000/docs`

---

## Integration with OpenAI SDK

### Non-Streaming Mode
```python
from openai import OpenAI

client = OpenAI(
    base_url="http://127.0.0.1:8000/v1",
    api_key="your_privguard_api_key",
)

response = client.chat.completions.create(
    model="gpt-4o",
    messages=[
        {"role": "user", "content": "Send a memo to aniket@example.com"}
    ]
)
print(response.choices[0].message.content)
```

### Streaming Mode (Secure Buffer-Before-Stream)
```python
stream = client.chat.completions.create(
    model="gpt-4o",
    messages=[
        {"role": "user", "content": "Explain secure streaming in detail."}
    ],
    stream=True,
)

for chunk in stream:
    if chunk.choices and chunk.choices[0].delta.content:
        print(chunk.choices[0].delta.content, end="", flush=True)
```

### Agent Tool Execution with Capabilities & Approvals
```python
import httpx

# 1. Register agent & initialize task session
# 2. Obtain temporary task-scoped capability token
cap_res = httpx.post(
    "http://127.0.0.1:8000/v1/capabilities/request",
    headers={"X-API-Key": "your_privguard_api_key"},
    json={
        "agent_id": "agent_alpha",
        "task_id": "task_001",
        "tool_name": "send_email",
        "max_uses": 1,
    }
).json()
capability_token = cap_res["capability_token"]

# 3. Attempt execution (High risk -> Held as PENDING approval)
exec_res = httpx.post(
    "http://127.0.0.1:8000/v1/tools/send_email/execute",
    headers={"X-API-Key": "your_privguard_api_key"},
    json={
        "agent_id": "agent_alpha",
        "task_id": "task_001",
        "capability_token": capability_token,
        "parameters": {"recipient": "client@enterprise.com", "subject": "Update", "body": "Report ready."}
    }
)
# Returns 402 with approval_id

# 4. Human operator approves exact action via dashboard / API
# 5. Agent executes with approved ID (tamper-proof action hash verified)
```

---

### 5. Launch the Security Control Center (Frontend Dashboard)
```bash
cd frontend
npm install
npm run dev
```
The Control Center will be accessible at: `http://localhost:3000`

---

## Repository Structure

```
PRIVGUARD-AI/
├── backend/
│   ├── app/
│   │   ├── api/              # Gateway, Privacy, Policies, Audit, Agents, Tasks, Capabilities, Approvals, Tools, Threats, Dashboard, Memory, MCP, Metrics, Monitoring
│   │   ├── observability/    # OTel Tracing, Safe Attributes, Prometheus Low-Cardinality Registry, Redaction Logging, SLOs, 8 Synthetic Canaries
│   │   ├── enterprise/       # SIEM Exporter (Splunk HEC, Elastic ECS, Sentinel) with SSRF Validation
│   │   ├── agent_security/   # Identity, Task Manager, Capability Manager, Permission Engine, Tool Registry, Broker, Sandbox
│   │   ├── approvals/        # Cryptographic Action-Binding, Approval Engine, Anti-Replay
│   │   ├── memory/           # Envelope Encryption, HKDF KEK Provider, Validator, Permissions, Vault, Retrieval Service
│   │   ├── mcp/              # MCP Destination Validator (SSRF), Registry & Drift Defense, stdio Sandbox, Protected Client, Security Proxy
│   │   ├── sdk/              # Python Client SDK (PrivGuardMemoryClient, PrivGuardMCPClient)
│   │   ├── threat_detection/ # Injection Detector, Content Analyzer, Behavior Analyzer, Exfiltration Taint Tracker, Memory & Retrieval Security
│   │   ├── core/             # Config, Authentication, Security, Exceptions
│   │   ├── gateway/          # Upstream proxy, response inspector, secure streaming
│   │   ├── providers/        # Provider abstraction, OpenAI-compatible, registry
│   │   ├── privacy/          # Secret Scanner, PII Detector, Redactor, Classifier
│   │   ├── policies/         # Deterministic Policy Engine
│   │   ├── monitoring/       # Content-free Audit Logger
│   │   └── database/         # Async SQLite models, migrations, WAL mode
│   └── tests/                # 346 automated security, red-team, adversarial, load, API, memory vault, MCP, and observability tests
├── frontend/                 # Next.js 14 App Router, TypeScript, Tailwind CSS, BFF Security Proxy
│   ├── app/                  # Security Overview, Approvals, Agents, Topology Map, Threats, Privacy, Memory Vault, MCP Gateway, Tasks, Activity, Diagnostics, Monitoring (Overview, Platform, Gateway, Security, Fleet, Canaries, Alerts)
│   ├── components/           # Radial Segmented Protection Gauge, Metric Cards, Forecast Charts, Tables, Modals
│   └── lib/                  # Type-safe API client, types, BFF handlers
├── observability/            # Standalone Observability Daemon Configurations
│   ├── otel-collector/       # OpenTelemetry Collector pipelines & redaction
│   ├── prometheus/           # Prometheus scraping & alerting rules
│   ├── loki/                 # Loki structured logging configuration
│   ├── alertmanager/         # Alertmanager routing hierarchy & notification policies
│   └── grafana/              # 7 auto-provisioned production dashboards & datasources
├── compose.observability.yaml # Standalone Observability Docker Compose
├── deploy/                   # Production deployment packaging
│   ├── docker/               # Dockerfiles, Caddyfile, Compose configurations
│   └── helm/privguard/       # Cloud-neutral Kubernetes Helm v3/v4 chart (PSS Restricted, NetworkPolicies, HPA, PDB)
├── docs/                     # Architecture, Threat Model, AISVS Assessment, Kubernetes & Production Guides
└── README.md
```

---

## Roadmap

- [x] **Stage 0:** Architecture, Threat Model & Specification
- [x] **Stage 1:** Backend Foundation, API Contracts, Secret Scanner, PII Redaction, Fail-Closed Pipeline
- [x] **Stage 2:** Live Upstream Model Proxying & Secure Streaming
- [x] **Stage 3:** Agent Security Broker, Capability Tokens & Human Approvals
- [x] **Stage 4:** Advanced Threat Detection (Prompt Injection, Behavioral Analysis, Exfiltration Defense)
- [x] **Stage 5:** Privacy & Security Control Center (Next.js 14 App Router, BFF Security Proxy, OWASP 2026 Telemetry)
- [x] **Stage 6:** End-to-End Integration, Red Teaming & Security Validation (OWASP AISVS 1.0, 142 Automated Tests)
- [x] **Stage 7:** Secure Personal AI Memory Vault (AES-256-GCM Envelope Encryption, Consent Proposals, Memory Poisoning Defense, Bounded Retrieval, Cryptographic Erasure, 171 Automated Tests)
- [x] **Stage 8:** MCP Security Integration (Model Context Protocol 2026-07-28 Gateway, SSRF Destination Defense, Tool Poisoning & Drift Quarantine, Sandboxed stdio Isolation, 213 Automated Tests)
- [x] **Stage 9:** Enterprise Governance, Multi-Tenancy & Fleet Policy Management (Tenant-aware RLS, 8-Role RBAC, SCIM 2.0, Signed Policy Bundles, 255 Automated Tests)
- [x] **Stage 10.1:** Production Readiness Assessment & Operational Gap Analysis
- [x] **Stage 10.2:** Docker Containerization, Production Compose & Security Hardening (Multi-stage non-root images, isolated networks, role-separated PostgreSQL, 263 Automated Tests)
- [x] **Stage 10.3:** PostgreSQL, Redis & Distributed State Management (Atomic Lua rate limiting, transactional outbox, Redis streams, cross-replica revocation, 276 Automated Tests)
- [x] **Stage 10.4:** Kubernetes & Helm Deployment Packaging (Cloud-neutral Helm chart, Restricted PSS, NetworkPolicies, HPA v2, PDB, pre-upgrade migration Jobs, 286 Automated Tests)
- [x] **Stage 10.5:** Enterprise Secrets & Cryptographic Key Management (Provider-independent KMS abstraction for AWS/GCP/Azure/Vault/Local, non-destructive legacy V1-to-V2 DEK rewrap, automated KEK rotation, Ed25519 signing key separation, decoupled approval HMAC, zero plaintext secret metadata, 314 Automated Tests)
- [x] **Stage 10.6:** Production Observability, Monitoring, Security Telemetry & Intelligent Alerting (OpenTelemetry distributed tracing with safe exception scrubbing, low-cardinality Prometheus metrics, 7 provisioned Grafana dashboards, Loki structured JSON logging with regex credential scrubbing, Alertmanager multi-tier routing hierarchy, SSRF-validated SIEM export for Splunk HEC/Elastic ECS/Sentinel, 8 active synthetic security canaries verifying fail-closed controls, 346 Automated Tests)
- [ ] **Stage 10.7:** Supply-Chain Security and CI/CD
- [ ] **Stage 10.8:** Compliance Readiness and Evidence Engine
- [ ] **Stage 10.9:** Python SDK Packaging and Distribution
- [ ] **Stage 10.10:** Disaster Recovery and Production Validation


