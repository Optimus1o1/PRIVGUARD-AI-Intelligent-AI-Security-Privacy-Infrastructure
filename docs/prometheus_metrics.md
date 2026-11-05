# Prometheus Metrics & Low-Cardinality Telemetry Catalogue

Organization: **Moon Sanctum Labs**  
Slogan: **Decode. Build. Evolve.**  
System: **PRIVGUARD AI**  
Document: **Prometheus Metrics Reference**  

---

## 1. Overview & Cardinality Invariants

Prometheus is PRIVGUARD AI's primary operational metrics collection and alerting engine. 

### Strict Low-Cardinality Invariant
To prevent metric timeseries explosion, CPU spikes, and memory bloat on monitoring nodes, PRIVGUARD enforces strict limits on metric label dimensions:
- **Prohibited Labels**: `user_id`, `tenant_id`, `agent_id`, `request_id`, `email`, `ip_address`, `raw_url`, `prompt_hash`, `memory_id`.
- **Allowed Dynamic Labels**: Strictly normalized routes (e.g. `/v1/agents/{id}/tasks`), discrete HTTP methods (`GET`, `POST`, `DELETE`), discrete status classes (`2xx`, `4xx`, `5xx`), and bounded enum categories (`allowed`, `blocked`, `redacted`).

---

## 2. Metric Catalogue

### 2.1 HTTP & API Gateway Metrics
| Metric Name | Type | Labels | Description |
| :--- | :--- | :--- | :--- |
| `privguard_http_requests_total` | Counter | `method`, `route`, `status_class` | Total inbound HTTP requests served. |
| `privguard_http_request_duration_seconds` | Histogram | `method`, `route`, `status_class` | Request latency distribution in seconds. |
| `privguard_gateway_requests_total` | Counter | `model`, `action`, `status` | Total LLM gateway requests processed. |
| `privguard_gateway_latency_seconds` | Histogram | `model`, `action` | Gateway roundtrip latency in seconds. |

### 2.2 Privacy & Data Protection Metrics
| Metric Name | Type | Labels | Description |
| :--- | :--- | :--- | :--- |
| `privguard_privacy_inspections_total` | Counter | `entity_type`, `outcome` | PII inspection passes by entity type. |
| `privguard_privacy_redactions_total` | Counter | `entity_type`, `action` | PII entity redactions executed. |
| `privguard_privacy_policy_decisions_total` | Counter | `policy_name`, `decision` | Policy decisions (`permit`, `deny`, `redact`). |

### 2.3 Threat Detection & Agent Security Metrics
| Metric Name | Type | Labels | Description |
| :--- | :--- | :--- | :--- |
| `privguard_threat_detections_total` | Counter | `threat_type`, `severity` | Injection and jailbreak detections. |
| `privguard_action_verifications_total` | Counter | `action_category`, `outcome` | Dual-authorization and verification events. |
| `privguard_agent_tool_invocations_total` | Counter | `tool_category`, `status` | Tool executions by authorized agents. |
| `privguard_agent_approvals_total` | Counter | `approval_type`, `decision` | Human-in-the-loop approval decisions. |

### 2.4 MCP & Infrastructure Connectivity
| Metric Name | Type | Labels | Description |
| :--- | :--- | :--- | :--- |
| `privguard_mcp_requests_total` | Counter | `server_category`, `status` | Outbound MCP connector requests. |
| `privguard_mcp_ssrf_blocks_total` | Counter | `target_type` | SSRF destination validation rejections. |
| `privguard_memory_operations_total` | Counter | `operation`, `status` | Memory vault encrypt/decrypt operations. |
| `privguard_kms_operations_total` | Counter | `provider`, `operation`, `status` | KMS key wrapping and unwrapping calls. |

### 2.5 Reliability & Infrastructure Metrics
| Metric Name | Type | Labels | Description |
| :--- | :--- | :--- | :--- |
| `privguard_database_pool_connections` | Gauge | `state` (`active`, `idle`) | PostgreSQL connection pool size. |
| `privguard_redis_connected` | Gauge | None | Redis connection status (1 = connected, 0 = disconnected). |
| `privguard_outbox_queue_depth` | Gauge | None | Number of pending transactional outbox events. |
| `privguard_slo_burn_rate` | Gauge | `slo_name`, `window` | Real-time multi-window error budget burn rate. |

### 2.6 Synthetic Security Canaries
| Metric Name | Type | Labels | Description |
| :--- | :--- | :--- | :--- |
| `privguard_canary_executions_total` | Counter | `canary_name`, `status` | Total synthetic canary runs. |
| `privguard_canary_duration_seconds` | Histogram | `canary_name` | Canary execution duration distribution. |
| `privguard_canary_failures_total` | Counter | `canary_name`, `failure_type` | Number of security canary failures detected. |

---

## 3. Route Normalization Architecture

The `ObservabilityMiddleware` in `app/observability/middleware.py` automatically normalizes dynamic URL parameters before recording metric labels.

### Examples of Normalization
- `/v1/agents/agent_01j7xyz.../tools` $\to$ `/v1/agents/{id}/tools`
- `/v1/memories/mem_987654` $\to$ `/v1/memories/{id}`
- `/v1/approvals/appr_12345/decision` $\to$ `/v1/approvals/{id}/decision`
- `/v1/monitoring/canaries/gateway_protection` $\to$ `/v1/monitoring/canaries/{id}`
- Dynamic UUIDs: `/[0-9a-f]{8}-[0-9a-f]{4}-...` $\to$ `/{id}`
- Dynamic integer IDs: `/[0-9]+` $\to$ `/{id}`

---

## 4. Scrape Configuration & Kubernetes ServiceMonitor

### 4.1 FastAPI Scrape Endpoint
Prometheus scrapes the backend via `GET /metrics`:
```bash
curl -X GET http://backend:8000/metrics
```
Output conforms to standard OpenMetrics / Prometheus text representation:
```text
# HELP privguard_http_requests_total Total inbound HTTP requests served.
# TYPE privguard_http_requests_total counter
privguard_http_requests_total{method="GET",route="/health",status_class="2xx"} 42.0
privguard_http_requests_total{method="POST",route="/v1/gateway/process",status_class="2xx"} 158.0
```

### 4.2 Prometheus Job Definition
```yaml
# In observability/prometheus/prometheus.yml
scrape_configs:
  - job_name: "privguard-backend"
    scrape_interval: 15s
    scrape_timeout: 10s
    metrics_path: "/metrics"
    static_configs:
      - targets: ["backend:8000"]
        labels:
          environment: "production"
          service: "privguard-backend"
```

### 4.3 Kubernetes ServiceMonitor Resource
```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: privguard-backend
  namespace: privguard
  labels:
    release: prometheus-operator
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: privguard
      app.kubernetes.io/component: backend
  endpoints:
    - port: http
      path: /metrics
      interval: 15s
      scrapeTimeout: 10s
```
