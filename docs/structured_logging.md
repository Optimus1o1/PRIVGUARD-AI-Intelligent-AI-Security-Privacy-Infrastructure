# Structured JSON Logging & Loki Ingestion Guide

Organization: **Moon Sanctum Labs**  
Slogan: **Decode. Build. Evolve.**  
System: **PRIVGUARD AI**  
Document: **Structured Logging Specification**  

---

## 1. Overview

PRIVGUARD AI utilizes structured JSON logging across all backend services. Every log line is formatted as a single-line JSON object containing correlation metadata and subjected to an inline redaction filter that strips credentials and API keys before writes occur.

The logging subsystem integrates with **Grafana Loki** for search, indexing, and visualization.

---

## 2. Structured JSON Schema

Every log line output by `StructuredJsonFormatter` adheres to this standard schema:

```json
{
  "timestamp": "2026-11-06T02:10:00.123456Z",
  "level": "INFO",
  "logger": "app.api.gateway",
  "message": "Gateway prompt inspected successfully",
  "request_id": "pg_req_9f3b8c2d1e0a4f5b",
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
  "span_id": "00f067aa0ba902b7",
  "service_name": "privguard-backend",
  "environment": "production",
  "extra": {
    "action": "inspect_prompt",
    "entities_detected": 2,
    "model": "gpt-4o"
  }
}
```

### Field Definitions
- `timestamp`: ISO-8601 formatted UTC timestamp with microsecond precision.
- `level`: Standard Python log levels (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`).
- `logger`: The Python module emitting the log record (`app.observability...`).
- `message`: Human-readable summary of the event (redacted).
- `request_id`: The correlation identifier `pg_req_<uuid16>` assigned to the HTTP or background transaction.
- `trace_id`: The 128-bit W3C OpenTelemetry trace ID.
- `span_id`: The 64-bit W3C OpenTelemetry span ID.
- `service_name`: Identifier for the deployment component (`privguard-backend`, `privguard-worker`).

---

## 3. Inline Redaction Engine (`RedactionFilter`)

To enforce the zero-credential leakage invariant, `app.observability.logging.RedactionFilter` inspects log records prior to emission and applies aggressive regex substitution rules.

### Redaction Rules
| Credential Type | Regex Pattern | Replacement |
| :--- | :--- | :--- |
| **Bearer Tokens** | `Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*` | `Bearer [REDACTED_CREDENTIAL]` |
| **OpenAI API Keys** | `sk-[A-Za-z0-9_\-]{20,}` | `[REDACTED_CREDENTIAL]` |
| **Anthropic API Keys** | `sk-ant-[A-Za-z0-9_\-]{20,}` | `[REDACTED_CREDENTIAL]` |
| **GitHub Tokens** | `ghp_[A-Za-z0-9]{36}` | `[REDACTED_CREDENTIAL]` |
| **Password Arguments** | `(?i)(password\|secret\|api_key)[\s:=]+([^\s,;]+)` | `\1: [REDACTED_CREDENTIAL]` |

### Code Implementation
```python
# In app/observability/logging.py
class RedactionFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = sanitize_string_value(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: sanitize_string_value(str(v)) for k, v in record.args.items()}
            elif isinstance(record.args, tuple):
                record.args = tuple(sanitize_string_value(str(a)) for a in record.args)
        return True
```

---

## 4. Loki Pipeline & Configuration

Loki receives logs scraped by Promtail or forwarded via Docker logging drivers.

### Loki Configuration (`observability/loki/loki-config.yaml`)
```yaml
auth_enabled: false

server:
  http_listen_port: 3100

common:
  path_prefix: /loki
  storage:
    filesystem:
      chunks_directory: /loki/chunks
      rules_directory: /loki/rules
  replication_factor: 1
  ring:
    kvstore:
      store: inmemory

schema_config:
  configs:
    - from: 2020-10-24
      store: tsdb
      object_store: filesystem
      schema: v13
      index:
        prefix: index_
        period: 24h

limits_config:
  reject_old_samples: true
  reject_old_samples_max_age: 168h
  max_query_length: 721h
```

### Querying Logs with LogQL in Grafana
```logql
# Search for errors in backend logs
{service="privguard-backend"} |= "ERROR" | json

# Search logs by correlation request ID
{service="privguard-backend"} | json | request_id = "pg_req_9f3b8c2d1e0a4f5b"

# Count security threat warnings
rate({service="privguard-backend"} |= "threat_detected" [5m])
```
