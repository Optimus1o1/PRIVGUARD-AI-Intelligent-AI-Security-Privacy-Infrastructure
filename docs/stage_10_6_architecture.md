# PRIVGUARD AI — Stage 10.6 Architecture Specification
## Observability, Security Telemetry & Intelligent Alerting

Organization: **Moon Sanctum Labs**  
Slogan: **Decode. Build. Evolve.**  
System: **PRIVGUARD AI — Independent Security & Privacy Enforcement Layer for Agentic AI**  
Stage: **10.6 — Production Observability, Monitoring & Security Telemetry**  

---

## 1. Executive Overview

Stage 10.6 equips PRIVGUARD AI with a comprehensive, enterprise-ready observability, monitoring, and intelligent alerting plane. Designed from first principles to enforce strict zero-content privacy and bounded-cardinality metrics, this infrastructure enables SecOps, SRE, and compliance teams to monitor operational health and verify security enforcement continuously across distributed instances.

### Key Tenets
1. **Zero-Content Privacy Invariant**: Under no circumstance are raw prompts, LLM responses, memory plaintext, tool arguments containing secrets, or API keys written to spans, metrics, or structured logs.
2. **Low-Cardinality Metric Invariant**: Prometheus metric labels are strictly bounded. Dynamic identifiers (tenant IDs, agent IDs, user IDs, request IDs, email addresses, IP addresses, raw URLs) are prohibited in metric dimensions to eliminate timeseries explosion.
3. **Decoupled Telemetry vs. Tamper-Evident Audit Ledger**: Operational telemetry (OTel spans, Prometheus metrics, Loki logs) serves runtime diagnostics and SRE alerting. The Stage 9 cryptographic hash-chained audit ledger (`EnterpriseAuditEvent`) remains independent, tamper-evident, and cryptographically verified.
4. **Active Security Canary Verification**: 8 synthetic canaries continuously execute simulated attack patterns and security operations, verifying that detection, redaction, revocation, and cryptographic safeguards fail closed.

---

## 2. Target Telemetry Architecture

```
                                  [ INGRESS / USERS / AGENTS ]
                                               │
                                               ▼
                              ┌───────────────────────────────────┐
                              │     PRIVGUARD REVERSE PROXY       │
                              │            (Nginx/TLS)            │
                              └─────────────────┬─────────────────┘
                                                │
                 ┌──────────────────────────────┴──────────────────────────────┐
                 ▼                                                             ▼
┌───────────────────────────────────┐                         ┌───────────────────────────────────┐
│     NEXT.JS CONTROL CENTER        │                         │       FASTAPI BACKEND FLEET       │
│         (Node.js / BFF)           │                         │      (ObservabilityMiddleware)    │
│  - Monitoring Console Pages       │                         │  - Request ID Correlation         │
│  - Canary Trigger & Visualizer    │                         │  - W3C Trace Context Propagation  │
│  - SLI / SLO Scorecards           │                         │  - Sanitized Span Attributes      │
└───────────────────────────────────┘                         │  - Low-Cardinality Metric Updates │
                                                              │  - Redacted JSON Logs             │
                                                              └─────────────────┬─────────────────┘
                                                                                │
                                        ┌───────────────────────────────────────┴──────────────────────────────┐
                                        ▼                                                                      ▼
                       ┌──────────────────────────────────┐                                   ┌──────────────────────────────────┐
                       │     OPENTELEMETRY COLLECTOR      │                                   │          AUDIT ENGINE            │
                       │   - Sensitive Key Redaction      │                                   │   - Stage 9 Hash Chaining        │
                       │   - Prometheus Scrape Endpoint   │                                   │   - SIEM Format Exporter         │
                       └────────────────┬─────────────────┘                                   └────────────────┬─────────────────┘
                                        │                                                                      │
        ┌───────────────────────────────┼───────────────────────────────┐                                      │
        ▼                               ▼                               ▼                                      ▼
┌──────────────┐                ┌──────────────┐                ┌──────────────┐                      ┌──────────────────┐
│  PROMETHEUS  │                │  TEMPO/OTEL  │                │  GRAFANA     │                      │   EXTERNAL SIEM  │
│ - 15s Scrape │                │ - Trace Store│                │    LOKI      │                      │ - Splunk HEC     │
│ - Alert Rules│                │ - Distributed│                │ - JSON Logs  │                      │ - Elastic ECS    │
│ - SLI Records│                │   Spans      │                │ - Redacted   │                      │ - MS Sentinel    │
└───────┬──────┘                └──────────────┘                └──────┬───────┘                      └──────────────────┘
        │                                                              │
        ▼                                                              │
┌──────────────┐                                                       │
│ ALERTMANAGER │                                                       │
│ - PagerDuty  │                                                       │
│ - Slack / MS │                                                       │
│ - Webhooks   │                                                       │
└──────────────┘                                                       │
        ▲                                                              │
        └───────────────────────────────┬──────────────────────────────┘
                                        ▼
                         ┌─────────────────────────────┐
                         │      GRAFANA 10.x           │
                         │  - 7 Production Dashboards  │
                         │  - Security & Canary Visuals│
                         └─────────────────────────────┘
```

---

## 3. Core Subsystems

### 3.1 Tracing & OpenTelemetry Instrumentation
- **Request Context (`app.observability.correlation`)**: Generates cryptographically secure `pg_req_<uuid16>` identifiers for each request and binds them to Python `contextvars.ContextVar`.
- **Span Lifecycle (`app.observability.tracing`)**: Implements `trace_span()` context manager that safely wraps execution without leaking exception descriptions into span status. Exceptions record type and clean message via `record_safe_exception()`.
- **Allowed Attributes (`app.observability.attributes`)**: Defines strict `SAFE_ATTRIBUTE_ALLOWLIST` and `PROHIBITED_KEY_PATTERNS`. Any forbidden or unapproved key is omitted from traces.

### 3.2 Metrics & Prometheus Aggregation
- **Isolated Registry (`app.observability.metrics`)**: Dedicated `CollectorRegistry` preventing default Python metric pollution.
- **Normalized Route Paths (`app.observability.middleware`)**: Dynamically normalizes path variables (e.g. `/v1/agents/agent_12345/tasks` $\to$ `/v1/agents/{id}/tasks`), enforcing strict low cardinality.
- **Categorized Collectors**:
  - HTTP & Gateway (Throughput, Latency, Status Codes, Redactions).
  - Security & Threat (Injection detections, Action verifications, Policy blocks).
  - Agent & MCP (Tool invocations, Approvals, SSRF blocks).
  - Memory & KMS (DEK wrap/unwrap, Vault lookups).
  - Infrastructure (DB pool status, Redis state, Outbox lag).
  - Synthetic Canaries (Execution count, Latency, Pass/Fail status).

### 3.3 Structured Logging & Loki Pipeline
- **Redaction Filter (`app.observability.logging`)**: Intercepts log records and strips API keys (Bearer tokens, `sk-proj-`, `sk-ant-`, `ghp_`, passwords).
- **JSON Formatter**: Emits standardized schema containing `timestamp`, `level`, `logger`, `message`, `request_id`, `trace_id`, `span_id`, and `service_name`.
- **Loki Integration**: Configured for high-throughput ingestion with structured labels (`service`, `environment`, `level`) and searchable indexed log contents.

### 3.4 Active Security Canaries
- Autonomous synthetic tests executed on schedule or on demand via `POST /v1/monitoring/canaries/run`.
- Directly exercises detection algorithms, cryptography, authorization checks, and network barriers.
- Emits dedicated metrics `privguard_canary_executions_total` and `privguard_canary_failures_total`.

### 3.5 SIEM & Enterprise Audit Integration
- `SIEMExporter` serializes Stage 9 tamper-evident audit ledger events into compliant schemas:
  - Splunk HTTP Event Collector (HEC).
  - Elasticsearch Common Schema (ECS).
  - Microsoft Sentinel log format.
  - Generic Webhook.
- Validates export endpoints against `MCPDestinationValidator` to eliminate Server-Side Request Forgery (SSRF) threats.

---

## 4. Security & Privacy Guarantees

| Invariant | Implementation Mechanism | Verification Test |
| :--- | :--- | :--- |
| **No Prompt / Content Leakage** | Strict attribute allowlist; spans record only counts and boolean status. | `test_stage_10_6_telemetry_privacy.py` |
| **No Credential Leakage in Logs** | Regex token redaction filter on root logging handler. | `test_stage_10_6_telemetry_privacy.py` |
| **Low Cardinality Guarantee** | Regex route normalizer replacing UUIDs, prefixes, and canary names with `{id}`. | `test_stage_10_6_metric_cardinality.py` |
| **Fail-Closed Verification** | Canaries assert that unauthorized or malicious payloads are rejected. | `test_stage_10_6_canaries.py` |
| **Tamper-Evident Decoupling** | Operational metrics use separate registry; audit log uses cryptographic hash chains. | `test_stage_9_tamper_evident_audit.py` |
| **SSRF Prevention on SIEM Outbound** | Destination validator blocks private IP ranges, metadata endpoints, and internal TLDs. | `test_stage_10_6_siem.py` |

---

## 5. Architectural Deliverables Map

```
RIVA_AI/
├── backend/app/observability/         # Complete Python Telemetry Engine
│   ├── attributes.py                 # OTel Semantic Conventions & Allowlist
│   ├── correlation.py                # Request / Trace / Span ContextVar State
│   ├── tracing.py                    # TracerProvider & Safe Span Lifecycle
│   ├── metrics.py                    # Low-Cardinality Prometheus Registry
│   ├── middleware.py                 # Route Normalization & Observability ASGI
│   ├── logging.py                    # RedactionFilter & StructuredJsonFormatter
│   ├── slo.py                        # Service Level Objective Evaluator
│   ├── canary/                       # 8 Synthetic Security Canaries & Runner
│   └── setup.py                      # Lifecycle Initialization
├── backend/app/api/
│   ├── metrics.py                    # GET /metrics Scrape Handler
│   └── monitoring.py                 # REST APIs for Monitoring Console
├── backend/app/enterprise/
│   └── siem_exporter.py              # Splunk/ECS/Sentinel SSRF-Protected Exporter
├── observability/                     # Container & Daemon Configuration
│   ├── otel-collector/               # OpenTelemetry Collector Pipelines
│   ├── prometheus/                   # Scrape Targets & Rules
│   ├── loki/                         # Structured Logging Config
│   ├── alertmanager/                 # Routing Hierarchy & Notification Policies
│   └── grafana/                      # 7 Provisioned Production Dashboards
├── compose.observability.yaml         # Standalone Observability Docker Compose
├── deploy/helm/privguard/             # Helm Chart ServiceMonitor & Scrape Config
└── frontend/app/monitoring/           # Next.js 14 Monitoring Control Center
```
