"""Centralized Asynchronous Redis Client & Connection Pool.
Moon Sanctum Labs - Decode. Build. Evolve.
"""

import hashlib
import logging
from typing import Optional
import redis.asyncio as aioredis
from app.core.config import settings

logger = logging.getLogger("privguard.redis")

# Global connection pool and client singleton
_redis_pool: Optional[aioredis.ConnectionPool] = None
_redis_client: Optional[aioredis.Redis] = None


class RedisNamespace:
    """Standard Redis key namespaces for tenant-isolated distributed state."""
    RATE_LIMIT = "rl"
    TAINT = "taint"
    POLICY = "policy"
    REVOCATIONS = "revocations"
    STREAM_EVENTS = "stream:events"
    CHANNEL_EVENTS = "channel:events"
    SYSTEM = "system"


def format_redis_key(namespace: str, tenant_id: str, *parts: str) -> str:
    """
    Constructs a normalized, tenant-isolated Redis key.
    Format: {namespace}:{tenant_id}:{subpart_1}:{subpart_2}
    """
    clean_tenant = tenant_id.strip() if tenant_id else "default_tenant"
    key_parts = [namespace, clean_tenant] + [str(p).strip() for p in parts if str(p).strip()]
    return ":".join(key_parts)


def hash_identifier(val: str) -> str:
    """Computes a non-reversible SHA-256 hash for sensitive Redis keys."""
    return hashlib.sha256(val.encode("utf-8")).hexdigest()[:32]


async def init_redis() -> Optional[aioredis.Redis]:
    """Initializes the Redis connection pool and validates liveness."""
    global _redis_pool, _redis_client

    if not settings.REDIS_URL:
        logger.info("REDIS_URL not configured. Operating in standalone local mode.")
        return None

    try:
        _redis_pool = aioredis.ConnectionPool.from_url(
            settings.REDIS_URL,
            max_connections=50,
            socket_timeout=5.0,
            socket_connect_timeout=5.0,
            retry_on_timeout=True,
            health_check_interval=30,
            decode_responses=True,
        )
        _redis_client = aioredis.Redis(connection_pool=_redis_pool)
        # Verify connectivity
        await _redis_client.ping()
        logger.info("Connected to Redis successfully.")
        return _redis_client
    except Exception as exc:
        logger.warning("Failed to connect to Redis: %s. Distributed features running in degraded mode.", exc)
        _redis_client = None
        return None


async def close_redis() -> None:
    """Closes Redis connections gracefully during application shutdown."""
    global _redis_pool, _redis_client
    if _redis_client:
        await _redis_client.close()
        _redis_client = None
    if _redis_pool:
        await _redis_pool.disconnect()
        _redis_pool = None
    logger.info("Redis connection pool disconnected.")


def get_redis() -> Optional[aioredis.Redis]:
    """Returns the shared async Redis client instance, or None if offline."""
    return _redis_client


async def check_redis_health() -> dict:
    """Probes Redis connectivity, response latency, and memory stats."""
    client = get_redis()
    if not client:
        return {"connected": False, "error": "Redis client not initialized"}

    import time
    t0 = time.perf_counter()
    try:
        await client.ping()
        latency_ms = round((time.perf_counter() - t0) * 1000, 2)
        info = {}
        try:
            info = await client.info(section="all")
        except Exception:
            pass

        return {
            "connected": True,
            "latency_ms": latency_ms,
            "used_memory_human": info.get("used_memory_human", "N/A"),
            "connected_clients": info.get("connected_clients", 1),
        }
    except Exception as exc:
        return {
            "connected": False,
            "error": str(exc),
        }
