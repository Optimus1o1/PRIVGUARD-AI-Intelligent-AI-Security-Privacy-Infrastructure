# Observability & Telemetry Validation Under Chaos

**PRIVGUARD AI** — *Independent Security & Privacy Enforcement Layer for Agentic AI*  
**Organization:** Moon Sanctum Labs — *Decode. Build. Evolve.*  
**Lead Engineer:** ANIKET NANDI (Kolkata, IST)

---

## 1. Observability Under Failure

Observability must remain accurate, actionable, and non-polluting even when the system is subjected to aggressive chaos and resource exhaustion attacks:
1. **Metrics Must Classify Failures Accurately:** HTTP 413, 429, 502, 503, and 504 errors must increment appropriate error counters without crashing the metrics scraper.
2. **Traces Must Capture Abort Spans:** Root spans must capture HTTP error classifications and status codes with high-precision duration measurements.
3. **Structured Logs Must Never Leak Sensitive Payloads:** Even when requests are rejected for containing malformed data, secrets, or oversized buffers, log records must only contain metadata and content fingerprints.
4. **Metric Cardinality Must Remain Bounded:** Attack traffic containing dynamic URLs or randomized user paths must be normalized to prevent Prometheus memory exhaustion.

---

## 2. Telemetry Behavior Across Chaos Scenarios

### 2.1 Oversized Request & Streaming Aborts (HTTP 413)
- **Trace Span:**
  - `span_name`: `HTTP POST /v1/chat/completions`
  - `http.status_code`: `413`
  - `http.status_class`: `4xx`
  - `error`: `false` (classified as client error, preventing false 5xx alarm triggers)
- **Prometheus Metrics:**
  - `privguard_http_requests_total{method="POST",route="/v1/chat/completions",status_class="4xx"}` incremented.
  - `privguard_http_request_duration_seconds` records sub-5ms rejection latency.
- **Log Record:**
  - Level: `WARNING`
  - Message: `Request rejected: Payload exceeds maximum allowed size`
  - Payload bytes: Not logged. Only `content_length_bytes` and `max_allowed_bytes` logged.

### 2.2 Runaway Agent Task Quota Exceeded (HTTP 429)
- **Prometheus Metrics:**
  - `privguard_agent_tasks_step_limit_exceeded_total{agent_id="...",app_id="..."}` incremented.
  - `privguard_agent_tasks_active` gauge decremented.
- **Audit Event:**
  - Event Type: `TASK_STEP_LIMIT_EXCEEDED`
  - Action Taken: `CANCEL_TASK_AND_REVOKE_CAPABILITIES`
  - Risk Level: `HIGH`

### 2.3 Upstream MCP Tool Timeout (HTTP 504)
- **Trace Span:**
  - `span_name`: `TOOL_EXECUTION mcp_remote_query`
  - `status.code`: `ERROR`
  - `exception.type`: `asyncio.TimeoutError`
  - `http.status_code`: `504`
  - `http.status_class`: `5xx`
- **Prometheus Metrics:**
  - `privguard_tool_execution_timeouts_total{tool_name="mcp_remote_query"}` incremented.
  - `privguard_http_errors_total{error_type="TOOL_EXECUTION_TIMEOUT"}` incremented.

### 2.4 Upstream Poisoned Credential Interception (HTTP 502)
- **Secret Scanner Filter:**
  - Detection Type: `AWS_ACCESS_KEY_ID`
  - Masked Preview: `AKIAIOSF...MPLE`
- **Audit Event:**
  - Event Type: `TOOL_OUTPUT_SECRET_BLOCKED`
  - Risk Level: `CRITICAL`
  - Raw secret content: Excluded. Only SHA-256 fingerprint of the output payload is retained.

---

## 3. Metric Cardinality Controls

To prevent Denial-of-Service attacks targeting Prometheus metric storage via high-cardinality path injection:
- `normalize_route_path()` sanitizes dynamic URL parameters (UUIDs, IDs, tokens) into parameterized route templates (e.g. `/v1/agents/{id}`, `/v1/tasks/{id}`).
- Metric labels are strictly bounded to finite enumerations:
  - `method`: `["GET", "POST", "PUT", "PATCH", "DELETE"]`
  - `status_class`: `["2xx", "3xx", "4xx", "5xx"]`
  - `route`: Pre-registered route patterns.
- High-volume malicious probes against non-existent paths are bucketed into `/404_unmatched`.
