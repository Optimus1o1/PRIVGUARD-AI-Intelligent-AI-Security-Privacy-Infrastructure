# Resource Exhaustion & Denial-of-Service Defense Architecture

**PRIVGUARD AI** — *Independent Security & Privacy Enforcement Layer for Agentic AI*  
**Organization:** Moon Sanctum Labs — *Decode. Build. Evolve.*  
**Lead Engineer:** ANIKET NANDI (Kolkata, IST)

---

## 1. Threat Profile

Agentic AI systems are uniquely vulnerable to resource exhaustion attacks:
1. **Volumetric Payload Attacks:** Transmitting massive JSON payloads (> 100 MB) to crash server memory.
2. **Chunked Streaming Slowloris:** Sending endless streams of small chunks without `Content-Length` headers, starving server connection buffers.
3. **Runaway Tool Loops:** Prompts or adversarial tools that cause an agent to repeatedly invoke tools thousands of times in an uncontrolled loop.
4. **Hanging Upstream Dependencies:** Slow or malicious MCP servers that open TCP connections and never respond, holding worker threads hostage.

---

## 2. Layered Edge Defenses

### 2.1 Edge Request Size Bounding (`RequestSizeLimitMiddleware`)
Located in [`backend/app/core/middleware.py`](file:///c:/Users/ANIKET/OneDrive/Documents/RIVA_AI/backend/app/core/middleware.py):

```python
class RequestSizeLimitMiddleware:
    """
    ASGI middleware enforcing strict request payload size limits.
    Prevents memory exhaustion and Denial-of-Service (DoS) attacks from oversized payloads.
    Evaluates both Content-Length headers and active streaming byte counters.
    """
    def __init__(self, app: ASGIApp, max_bytes: Optional[int] = None):
        self.app = app
        self.max_bytes = max_bytes if max_bytes is not None else settings.MAX_REQUEST_SIZE_BYTES
```

#### Dual-Phase Enforcement Mechanism:
1. **Phase 1 — Content-Length Fast Path:**
   - Reads the raw ASGI `scope["headers"]` before the request body is buffered into memory.
   - If `content-length > self.max_bytes` (10 MB default), it returns HTTP 413 `PAYLOAD_TOO_LARGE` immediately (< 2 ms latency).
2. **Phase 2 — Streaming Chunk Byte Bounding:**
   - For chunked or streaming requests without a declared `Content-Length`, `limited_receive()` tracks cumulative bytes:
     ```python
     async def limited_receive():
         nonlocal bytes_received
         message = await receive()
         if message["type"] == "http.request":
             body = message.get("body", b"")
             bytes_received += len(body)
             if bytes_received > self.max_bytes:
                 raise PayloadTooLargeException(self.max_bytes)
         return message
     ```
   - When cumulative bytes exceed `MAX_REQUEST_SIZE_BYTES`, `PayloadTooLargeException` aborts the stream and terminates the HTTP connection with HTTP 413.

### 2.2 Runaway Agent Task Step Quotas
Located in [`backend/app/agent_security/task_manager.py`](file:///c:/Users/ANIKET/OneDrive/Documents/RIVA_AI/backend/app/agent_security/task_manager.py):

1. **Step Budget Configuration:**
   - Each `AgentTask` includes `step_count` (current steps taken) and `max_steps` (budget, default: 100).
2. **Deterministic Step Tracking:**
   - `tool_broker.execute()` calls `task_manager.record_step(db, task_id, app.id)` on every tool invocation attempt.
3. **Automated Escalation & Revocation:**
   - When `step_count >= max_steps`:
     - Task transitions to `STEP_LIMIT_EXCEEDED`.
     - Active capability tokens assigned to the task are marked `is_revoked = True`.
     - Pending human approvals are transitioned to `EXPIRED`.
     - The tool broker rejects execution with HTTP 429:
       ```json
       {
         "error": {
           "code": "TASK_STEP_LIMIT_EXCEEDED",
           "message": "Task 'task_xyz' has reached its maximum execution step limit of 100 steps."
         }
       }
       ```

### 2.3 Sandboxed Tool Execution Timeouts
Located in [`backend/app/agent_security/tool_registry.py`](file:///c:/Users/ANIKET/OneDrive/Documents/RIVA_AI/backend/app/agent_security/tool_registry.py):

- Every registered tool definition specifies a `timeout_seconds` parameter (default: 5.0 to 10.0 seconds).
- Execution is strictly wrapped via `asyncio.wait_for()`:
  ```python
  raw_output = await asyncio.wait_for(handler(exec_params), timeout=tool.timeout_seconds)
  ```
- If an upstream tool or MCP server fails to respond within the timeout, the connection is aborted and HTTP 504 `TOOL_EXECUTION_TIMEOUT` is returned to the agent without hanging the worker.
