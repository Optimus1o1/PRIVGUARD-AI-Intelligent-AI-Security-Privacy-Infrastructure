# Distributed Rate Limiting in PRIVGUARD AI
## Atomic Sliding-Window Enforcement with Redis Lua & Fail-Safe Fallbacks
**Agency**: Moon Sanctum Labs — *Decode. Build. Evolve.*  

---

## 1. Overview

In a distributed deployment with multiple backend replicas behind a load balancer, standard in-memory rate limiters allow attackers to bypass limits by spreading requests across different replica nodes. PRIVGUARD AI implements an **atomic distributed sliding-window rate limiter** backed by Redis sorted sets (`ZSET`) and evaluated via an atomic Lua script.

---

## 2. Quota Categories

PRIVGUARD categorizes traffic into discrete enforcement tiers:

| Tier | Category | Quota | Window | Description |
|---|---|---|---|---|
| **Auth** | `AUTHENTICATION` | 10 requests | 60 seconds | Login, SSO authentication, and API key issuance. |
| **Gateway** | `GATEWAY` | 60 requests | 60 seconds | General AI proxy requests and LLM gateway completions. |
| **Tools** | `TOOL_EXECUTION` | 30 requests | 60 seconds | Agent tool invocation mediation. |
| **Memory** | `MEMORY` | 30 requests | 60 seconds | Personal encrypted memory reads, proposals, and writes. |
| **MCP** | `MCP` | 60 requests | 60 seconds | MCP gateway client and server protocol requests. |
| **Admin** | `ADMIN` | 20 requests | 60 seconds | Organization management, policy deployment, and fleet actions. |

---

## 3. Atomic Lua Algorithm

The rate limiter executes the following atomic steps within Redis in a single round-trip:

1. **Prune Expired Entries**: Remove timestamps older than `now - window_ms` using `ZREMRANGEBYSCORE`.
2. **Count Active Requests**: Calculate current elements in the sorted set using `ZCARD`.
3. **Evaluate Quota**:
   - If `current_requests < max_requests`: Add current timestamp with unique request ID via `ZADD`, reset key TTL with `PEXPIRE`, and return `allowed = 1`, `remaining = max - current - 1`.
   - If `current_requests >= max_requests`: Retrieve oldest timestamp in window via `ZRANGE 0 0 WITHSCORES`, calculate exact `retry_after_seconds = (oldest_ts + window_ms - now) / 1000`, and return `allowed = 0`, `remaining = 0`, `retry_after`.

```lua
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window_ms = tonumber(ARGV[2])
local max_requests = tonumber(ARGV[3])
local req_id = ARGV[4]
local clear_before = now - window_ms

redis.call('ZREMRANGEBYSCORE', key, 0, clear_before)
local current_requests = redis.call('ZCARD', key)

if current_requests < max_requests then
    redis.call('ZADD', key, now, req_id)
    redis.call('PEXPIRE', key, window_ms)
    local remaining = max_requests - current_requests - 1
    return {1, remaining, 0}
else
    local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
    local retry_after_ms = window_ms
    if #oldest > 0 then
        local oldest_ts = tonumber(oldest[2])
        retry_after_ms = math.max(0, (oldest_ts + window_ms) - now)
    end
    local retry_after_sec = math.ceil(retry_after_ms / 1000)
    return {0, 0, math.max(1, retry_after_sec)}
end
```

---

## 4. Key Namespacing & Privacy

Redis keys follow strict tenant-isolated formatting:
```
rl:{tenant_id}:{category}:{sha256(identifier)[:32]}
```
Identifiers (such as API keys, IP addresses, or user tokens) are hashed using SHA-256 before inclusion in Redis keys, preventing credential leakage or plaintext PII from appearing in Redis dumps or telemetry.

---

## 5. Fail-Safe Local Fallback

If Redis becomes temporarily unreachable or encounters network partitioning:
- The rate limiter automatically falls back to an in-memory sliding-window cache on the active node.
- Critical operations (`AUTHENTICATION` and `ADMIN`) strictly enforce quota limits in local memory to prevent brute-force attacks during degradation.
- When Redis recovers, distributed coordination automatically resumes.
