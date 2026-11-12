# Alerting Rules, Incident Management & Routing Hierarchy

Organization: **Moon Sanctum Labs**  
Slogan: **Decode. Build. Evolve.**  
System: **PRIVGUARD AI**  
Document: **Alerting & Incident Management Specification**  

---

## 1. Overview

PRIVGUARD AI integrates Prometheus alerting rules with **Prometheus Alertmanager** to deliver proactive incident response. The alerting engine separates operational infrastructure incidents from security enforcement failures, routing critical security breaches to on-call responders immediately.

---

## 2. Alert Routing Hierarchy

Alerts are routed according to severity tags (`critical`, `high`, `medium`, `low`):

```
                                 [ PROMETHEUS ALERTS ]
                                           │
                                           ▼
                              ┌─────────────────────────┐
                              │      ALERTMANAGER       │
                              │ - Grouping (5m)         │
                              │ - Inhibition Rules      │
                              │ - Repeat Interval (4h)  │
                              └────────────┬────────────┘
                                           │
         ┌─────────────────────────────────┼─────────────────────────────────┐
         │ severity = critical             │ severity = high                 │ severity = medium / low
         ▼                                 ▼                                 ▼
┌──────────────────┐              ┌──────────────────┐              ┌──────────────────┐
│    PAGERDUTY     │              │   SLACK / TEAMS  │              │   EMAIL / DIGEST │
│ (Immediate Page) │              │  (#secops-alerts)│              │ (#ops-monitoring)│
└──────────────────┘              └──────────────────┘              └──────────────────┘
```

---

## 3. Core Alert Rules Catalogue

Defined in `observability/prometheus/rules/alert_rules.yml`:

### 3.1 Security & Canary Alerts
| Alert Name | Severity | Condition | Description |
| :--- | :--- | :--- | :--- |
| `PrivGuardSecurityCanaryFailed` | `critical` | `privguard_canary_failures_total > 0` for 1m | A synthetic security canary detected that a security control did not fail closed. Immediate investigation required. |
| `PrivGuardPromptInjectionSpike` | `high` | `rate(privguard_threat_detections_total{threat_type="prompt_injection"}[5m]) > 5` for 2m | Elevated rate of prompt injection attempts detected across gateways. |
| `PrivGuardSSRFBlockSpike` | `high` | `rate(privguard_mcp_ssrf_blocks_total[5m]) > 2` for 2m | Agents or tools attempting to reach internal or cloud metadata endpoints. |

### 3.2 Gateway & API Performance Alerts
| Alert Name | Severity | Condition | Description |
| :--- | :--- | :--- | :--- |
| `PrivGuardHigh5xxErrorRate` | `critical` | `sum(rate(privguard_http_requests_total{status_class="5xx"}[5m])) / sum(rate(privguard_http_requests_total[5m])) * 100 > 5` for 3m | More than 5% of API requests returning 5xx server errors. |
| `PrivGuardGatewayLatencySpike` | `high` | `histogram_quantile(0.95, rate(privguard_gateway_latency_seconds_bucket[5m])) > 2.0` for 5m | Gateway P95 latency exceeds 2.0 seconds. |
| `PrivGuardSLOBurnRateCritical` | `critical` | `privguard_slo_burn_rate{window="1h"} > 14.4` for 2m | 1-hour burn rate indicates 2% of 30-day error budget consumed in 1 hour. |

### 3.3 Infrastructure & Reliability Alerts
| Alert Name | Severity | Condition | Description |
| :--- | :--- | :--- | :--- |
| `PrivGuardRedisDisconnected` | `critical` | `privguard_redis_connected == 0` for 1m | Redis distributed cache/lock layer unreachable. Cluster falling back to local state. |
| `PrivGuardDBPoolSaturation` | `high` | `privguard_database_pool_connections{state="active"} / 20 > 0.85` for 5m | PostgreSQL connection pool utilization exceeds 85%. |
| `PrivGuardOutboxLagHigh` | `medium` | `privguard_outbox_queue_depth > 1000` for 10m | Transactional outbox event delivery falling behind. |

---

## 4. Alertmanager Configuration (`alertmanager.yml`)

```yaml
global:
  resolve_timeout: 5m

route:
  group_by: ["alertname", "cluster", "service"]
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 4h
  receiver: "slack-notifications"
  routes:
    - match:
        severity: critical
      receiver: "pagerduty-critical"
      continue: true
    - match:
        severity: high
      receiver: "slack-secops"

inhibit_rules:
  # Inhibit application alerts if the entire backend instance is reported down
  - source_match:
      alertname: "InstanceDown"
    target_match_re:
      alertname: "PrivGuard.*"
    equal: ["instance"]

receivers:
  - name: "pagerduty-critical"
    pagerduty_configs:
      - service_key: "${PAGERDUTY_SERVICE_KEY}"
        severity: "critical"

  - name: "slack-secops"
    slack_configs:
      - channel: "#secops-alerts"
        api_url: "${SLACK_WEBHOOK_URL}"
        title: "PRIVGUARD Alert: {{ .CommonAnnotations.summary }}"
        text: "{{ .CommonAnnotations.description }}"

  - name: "slack-notifications"
    slack_configs:
      - channel: "#ops-notifications"
        api_url: "${SLACK_WEBHOOK_URL}"
```

---

## 5. Incident Runbooks & Triaging

When an alert triggers, responders should follow standard procedures:
1. **Canary Failures**: Access Next.js Control Center at `/monitoring/canaries` and review the failure details. Run `POST /v1/monitoring/canaries/run` to re-verify in isolation.
2. **5xx Error Spikes**: Query Loki logs via Grafana:
   `{service="privguard-backend"} |= "ERROR" | json`
3. **Database Pool Saturation**: Check active queries in PostgreSQL:
   `SELECT pid, now() - query_start AS duration, query FROM pg_stat_activity WHERE state = 'active';`
