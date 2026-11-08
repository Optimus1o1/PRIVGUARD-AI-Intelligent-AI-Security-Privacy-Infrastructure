# PRIVGUARD AI — Python SDK Error Handling & Retry Architecture

**Organization**: Moon Sanctum Labs  
**Motto**: Decode. Build. Evolve.  
**Package**: `privguard-sdk` (import: `privguard_sdk`)  
**Specification Version**: 1.0.0 (SDK Version: 0.1.0)  

---

## 1. Exception Class Hierarchy

All exceptions raised by `privguard-sdk` derive from `PrivGuardError`. This provides developers with granular catch blocks or high-level safety nets across agent workflows:

```
PrivGuardError (Base Exception)
├── AuthenticationError          (401 Unauthorized - invalid or missing API key)
├── AuthorizationError           (403 Forbidden - permission denied or tenant mismatch)
├── NotFoundError                (404 Not Found - resource does not exist)
├── ConflictError                (409 Conflict - state conflict or duplicate identity)
├── PayloadTooLargeError         (413 Payload Too Large - payload exceeds size limit)
├── RateLimitError               (429 Too Many Requests - rate limit exceeded)
├── ValidationError              (400 / 422 - invalid input parameters or schema error)
├── ServerError                  (500, 502, 503, 504 - backend error)
├── ConnectionError              (Transport level socket disconnection / DNS failure)
├── TimeoutError                 (Read/write/connect timeout exceeded)
├── StreamingError               (Premature disconnect or broken SSE stream)
└── SignatureVerificationError   (Cryptographic verification failure on offline export)
```

---

## 2. HTTP Status Code Mapping

When an HTTP response indicates failure (`status_code >= 400`), the transport engine parses the JSON body (extracting `detail`, `error_code`, and `request_id`) and maps it to a specific typed exception:

| Status Code | Exception Class | Common Cause | Recommended Action |
| :--- | :--- | :--- | :--- |
| `401` | `AuthenticationError` | Invalid, expired, or missing API key | Refresh or reconfigure `PRIVGUARD_API_KEY` |
| `403` | `AuthorizationError` | Tenant mismatch or insufficient RBAC scope | Verify tenant ID and agent capability bounds |
| `404` | `NotFoundError` | Entity ID (agent, task, token, memory) missing | Verify entity ID or recreate entity |
| `409` | `ConflictError` | Duplicate registration or state clash | Re-sync entity state or update existing entity |
| `413` | `PayloadTooLargeError` | Input text exceeds maximum token context | Truncate or chunk input text before submission |
| `429` | `RateLimitError` | Rate limit or concurrency quota exceeded | Honor `retry_after` header or back off |
| `422` | `ValidationError` | Malformed parameters or schema mismatch | Inspect `details` dictionary for failing fields |
| `500+` | `ServerError` | Transient infrastructure or service degradation | Safe to retry if idempotent; report to admin |

---

## 3. Idempotent Retry Policy & Non-Idempotent Safety

The SDK implements an strict idempotency-aware retry engine (`privguard_sdk.transport.retries.RetryPolicy`):

### Safe Operations (`is_idempotent() == True`)
- HTTP methods: `GET`, `HEAD`, `OPTIONS`.
- Retryable status codes: `429` (Rate Limited), `502` (Bad Gateway), `503` (Service Unavailable), `504` (Gateway Timeout).
- Retryable transport events: `httpx.ConnectTimeout`, `httpx.ReadTimeout`, `httpx.ConnectError`.

### Unsafe Operations (`is_idempotent() == False`)
- HTTP methods: `POST`, `PATCH`, `DELETE`, `PUT`.
- **Under no circumstances does the SDK automatically retry mutation calls on network timeouts.**  
  *Rationale*: If a network connection drops after PRIVGUARD AI processes a `POST /v1/tools/execute` or `POST /v1/capabilities/mint` call, retrying the request could result in double tool execution, redundant token generation, or corrupted agent audit logs.

### Exponential Backoff with Full Jitter

When a retry is eligible, delay is calculated using exponential backoff with full randomized jitter to prevent thundering herd spikes:

$$\text{sleep} = \text{random.uniform}(0, \min(\text{max\_delay}, \text{initial\_delay} \times 2^{\text{attempt}}))$$

If the server provides an explicit `Retry-After` header, that value takes precedence.

---

## 4. Exception Handling Patterns

### Granular Error Handling in Agent Workflows

```python
import time
from privguard_sdk import (
    PrivGuardClient,
    AuthenticationError,
    RateLimitError,
    ConflictError,
    ServerError,
    PrivGuardError,
)

client = PrivGuardClient()

try:
    response = client.privacy.analyze("Customer phone number is 9876543210")
    print("Risk score:", response.risk_score)

except AuthenticationError as e:
    # Fatal authentication problem - halt execution
    logger.critical("Authentication failed: %s (request_id=%s)", e.message, e.request_id)
    raise SystemExit(1)

except RateLimitError as e:
    # Graceful wait-and-retry
    wait_seconds = e.retry_after or 5.0
    logger.warning("Rate limited. Waiting %.1f seconds...", wait_seconds)
    time.sleep(wait_seconds)

except ConflictError as e:
    logger.warning("State conflict: %s (code=%s)", e.message, e.error_code)

except ServerError as e:
    logger.error("PRIVGUARD server error (%d): %s", e.status_code, e.message)

except PrivGuardError as e:
    logger.error("General PRIVGUARD error: %s", e)
```

