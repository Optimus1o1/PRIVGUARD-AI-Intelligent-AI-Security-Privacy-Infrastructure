"""Atomic Redis-Backed Sliding-Window Rate Limiter.
Moon Sanctum Labs - Decode. Build. Evolve.
"""

import time
import uuid
from dataclasses import dataclass
from typing import Dict, Optional, Tuple
import redis.asyncio as aioredis
from app.infrastructure.redis_client import RedisNamespace, format_redis_key, get_redis, hash_identifier

# Atomic sliding window rate limiter Lua script
SLIDING_WINDOW_LUA = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window_ms = tonumber(ARGV[2])
local max_requests = tonumber(ARGV[3])
local req_id = ARGV[4]
local clear_before = now - window_ms

-- 1. Remove expired timestamps outside current sliding window
redis.call('ZREMRANGEBYSCORE', key, 0, clear_before)

-- 2. Count requests in active window
local current_requests = redis.call('ZCARD', key)

if current_requests < max_requests then
    -- 3. Within quota: Record current request timestamp
    redis.call('ZADD', key, now, req_id)
    redis.call('PEXPIRE', key, window_ms)
    local remaining = max_requests - current_requests - 1
    return {1, remaining, 0}
else
    -- 4. Quota exceeded: Calculate retry-after based on oldest entry
    local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
    local retry_after_ms = window_ms
    if #oldest > 0 then
        local oldest_ts = tonumber(oldest[2])
        retry_after_ms = math.max(0, (oldest_ts + window_ms) - now)
    end
    local retry_after_sec = math.ceil(retry_after_ms / 1000)
    if retry_after_sec <= 0 then
        retry_after_sec = 1
    end
    return {0, 0, retry_after_sec}
end
"""


@dataclass
class RateLimitPolicy:
    """Rate limit configuration for an endpoint or resource category."""
    max_requests: int
    window_seconds: int

    @property
    def limit(self) -> int:
        return self.max_requests


DEFAULT_POLICIES: Dict[str, RateLimitPolicy] = {
    "AUTHENTICATION": RateLimitPolicy(max_requests=10, window_seconds=60),
    "GATEWAY": RateLimitPolicy(max_requests=60, window_seconds=60),
    "TOOL_EXECUTION": RateLimitPolicy(max_requests=30, window_seconds=60),
    "MEMORY": RateLimitPolicy(max_requests=30, window_seconds=60),
    "MCP": RateLimitPolicy(max_requests=60, window_seconds=60),
    "ADMIN": RateLimitPolicy(max_requests=20, window_seconds=60),
}

RATE_LIMIT_QUOTAS = DEFAULT_POLICIES


@dataclass
class RateLimitResult:
    """Outcome of rate limit evaluation."""
    allowed: bool
    limit: int
    remaining: int
    reset_seconds: int
    retry_after: int = 0
    backend_mode: str = "redis"  # redis or in_memory_fallback


class DistributedRateLimiter:
    """Atomic multi-instance sliding window rate limiter backed by Redis."""

    def __init__(self, custom_redis: Optional[aioredis.Redis] = None) -> None:
        self._custom_redis = custom_redis
        # Process-local fallback cache if Redis is offline
        self._local_windows: Dict[str, list] = {}

    def _get_client(self) -> Optional[aioredis.Redis]:
        return self._custom_redis or get_redis()

    async def check_rate_limit(
        self,
        tenant_id: str,
        category: str,
        identifier: str,
        custom_policy: Optional[RateLimitPolicy] = None,
    ) -> RateLimitResult:
        """
        Evaluates atomic sliding window rate limit for subject within tenant.
        Identifier is automatically hashed to prevent leaking credentials or PII in Redis.
        """
        policy = custom_policy or DEFAULT_POLICIES.get(category, RateLimitPolicy(60, 60))
        subject_hash = hash_identifier(identifier)
        redis_key = format_redis_key(RedisNamespace.RATE_LIMIT, tenant_id, category.lower(), subject_hash)

        client = self._get_client()

        # If Redis is unavailable, execute fail-safe fallback
        if not client:
            return self._fallback_local_rate_limit(redis_key, category, policy)

        try:
            now_ms = int(time.time() * 1000)
            window_ms = policy.window_seconds * 1000
            req_id = f"{now_ms}_{uuid.uuid4().hex[:8]}"

            res = await client.eval(
                SLIDING_WINDOW_LUA,
                1,
                redis_key,
                now_ms,
                window_ms,
                policy.max_requests,
                req_id,
            )

            is_allowed = bool(res[0])
            remaining = int(res[1])
            retry_after = int(res[2])

            return RateLimitResult(
                allowed=is_allowed,
                limit=policy.max_requests,
                remaining=remaining,
                reset_seconds=policy.window_seconds,
                retry_after=retry_after,
                backend_mode="redis",
            )
        except Exception as exc:
            # Fall back safely
            return self._fallback_local_rate_limit(redis_key, category, policy)

    def _fallback_local_rate_limit(
        self, key: str, category: str, policy: RateLimitPolicy
    ) -> RateLimitResult:
        """
        Process-local sliding window fallback when Redis is offline.
        Sensitive authentication and admin mutations fail closed if degraded limits exceeded.
        """
        now = time.time()
        window = self._local_windows.setdefault(key, [])
        cutoff = now - policy.window_seconds

        # Prune expired
        self._local_windows[key] = [ts for ts in window if ts > cutoff]
        window = self._local_windows[key]

        if len(window) < policy.max_requests:
            window.append(now)
            remaining = policy.max_requests - len(window)
            return RateLimitResult(
                allowed=True,
                limit=policy.max_requests,
                remaining=remaining,
                reset_seconds=policy.window_seconds,
                retry_after=0,
                backend_mode="in_memory_fallback",
            )
        else:
            # Sensitive categories fail closed in degraded mode
            oldest = window[0] if window else now
            retry_after = max(1, int((oldest + policy.window_seconds) - now))
            return RateLimitResult(
                allowed=False,
                limit=policy.max_requests,
                remaining=0,
                reset_seconds=policy.window_seconds,
                retry_after=retry_after,
                backend_mode="in_memory_fallback",
            )
