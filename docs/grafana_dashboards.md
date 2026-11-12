# Grafana Dashboards Specification & Provisioning Guide

Organization: **Moon Sanctum Labs**  
Slogan: **Decode. Build. Evolve.**  
System: **PRIVGUARD AI**  
Document: **Grafana Dashboards Reference**  

---

## 1. Overview & Auto-Provisioning

PRIVGUARD AI provides 7 production-grade Grafana dashboards pre-configured for automated provisioning. When deployed via `compose.observability.yaml` or Helm, Grafana automatically discovers and registers these dashboards without requiring manual import.

Provisioning configuration:
- Datasource: `observability/grafana/provisioning/datasources/datasources.yaml` (Prometheus & Loki)
- Dashboards Provider: `observability/grafana/provisioning/dashboards/dashboards.yaml` pointing to `/etc/grafana/dashboards/`.

---

## 2. Production Dashboards Catalogue

### 2.1 Platform Overview (`platform-overview.json`)
- **Target Audience**: SREs, SecOps Lead, Platform Engineering.
- **Key Visualizations**:
  - Global Availability & SLI Status (Gauge, Target: 99.9%).
  - Total Request Volume & Error Rate (Timeseries, PromQL: `sum(rate(privguard_http_requests_total[5m]))`).
  - P95 / P99 Latency by Route (Timeseries).
  - Active Security Canary Health Scorecard (Stat grid: 8 Canaries).
  - Outbox Queue Depth & Redis Connection Status.

### 2.2 AI Gateway Performance & Redaction (`ai-gateway.json`)
- **Target Audience**: AI Engineers, SecOps, Data Governance.
- **Key Visualizations**:
  - Gateway Throughput by Model (e.g. `gpt-4o`, `claude-3-5-sonnet`, `gemini-1-5-pro`).
  - Latency Breakdown: Inspection vs. Upstream Generation.
  - PII Detection Volume by Entity Type (`EMAIL`, `PHONE`, `SSN`, `API_KEY`).
  - Redaction vs. Masking vs. Pass-Through Ratios (Pie chart).
  - Upstream Provider Error Rates (5xx / Rate Limits).

### 2.3 Security Operations & Threat Analytics (`security-operations.json`)
- **Target Audience**: SOC Analysts, Security Engineers, Compliance Officers.
- **Key Visualizations**:
  - Prompt Injection & Jailbreak Attempts over Time.
  - Threat Severity Distribution (`HIGH`, `CRITICAL`, `MEDIUM`, `LOW`).
  - Action Verification Breakdown: Denied vs. Dual-Approved vs. Auto-Passed.
  - SSRF Block Events by Destination Type.
  - Live Security Incident Stream (Loki log viewer filtered by `level="ERROR"` and `security_event=true`).

### 2.4 Agent Fleet & MCP Diagnostics (`agent-mcp-fleet.json`)
- **Target Audience**: Agent Developers, System Integrators.
- **Key Visualizations**:
  - Active Agent Invocations by Tool Category (`filesystem`, `database`, `shell`, `network`).
  - Human-in-the-Loop Approval Latency & Pending Approvals.
  - MCP Server Connectors: Requests, Failures, and Circuit Breaker Trippings.
  - Revocation Propagation Lag across Distributed Nodes.

### 2.5 Personal Memory Vault & KMS (`memory-kms.json`)
- **Target Audience**: Cryptography Engineers, Platform Security, SRE.
- **Key Visualizations**:
  - Memory Read/Write Operations by Category.
  - DEK Wrapping / Unwrapping Latency (P99).
  - KMS Provider Health (AWS KMS, GCP KMS, Vault, Local).
  - Key Rotation Status & Expiration Alerts.
  - Failed Envelope Decryption Attempts (Potential Breach Indicator).

### 2.6 Infrastructure Health & Resource Saturation (`infrastructure.json`)
- **Target Audience**: SREs, Database Administrators.
- **Key Visualizations**:
  - PostgreSQL Connection Pool Utilization (`active` vs. `idle` vs. `max_overflow`).
  - Redis Memory Usage, Hit Rate, and Command Throughput.
  - CPU & Memory Footprint across Frontend and Backend Pods.
  - Transactional Outbox Lag and Event Delivery Rate.

### 2.7 Enterprise Operations & Compliance (`enterprise-operations.json`)
- **Target Audience**: CISO, Compliance Auditors, Governance Board.
- **Key Visualizations**:
  - 30-Day SLO Budget Burn Rate & Remaining Error Budget.
  - Multi-Tenant Volume & Policy Enforcement Ratios.
  - SIEM Exporter Queue & Delivery Latency.
  - Cryptographic Hash Chain Audit Ledger Verification Status.

---

## 3. PromQL Query Reference

```promql
# Overall HTTP Error Rate
sum(rate(privguard_http_requests_total{status_class=~"5.*"}[5m]))
/
sum(rate(privguard_http_requests_total[5m])) * 100

# Gateway Latency 99th Percentile
histogram_quantile(0.99, sum by (le) (rate(privguard_gateway_latency_seconds_bucket[5m])))

# Active Canary Failures
sum(privguard_canary_failures_total) by (canary_name)

# Database Pool Saturation Ratio
privguard_database_pool_connections{state="active"}
/
(privguard_database_pool_connections{state="active"} + privguard_database_pool_connections{state="idle"})
```

---

## 4. Dashboard Import & Customization

All dashboard JSON files are located in `observability/grafana/dashboards/`. To manually update or export:
1. Open Grafana at `http://localhost:3001` (Default credentials: `admin` / `admin`).
2. Make changes via the Grafana UI.
3. Use `Dashboard Settings -> JSON Model` to export the updated configuration back into `observability/grafana/dashboards/`.
