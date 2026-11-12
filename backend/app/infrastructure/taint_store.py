"""Distributed Task Taint Store & Provenance Synchronization.
Moon Sanctum Labs - Decode. Build. Evolve.
"""

import json
import logging
from typing import List, Optional, Set
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
import redis.asyncio as aioredis
from app.database.models import ActiveTaint, utcnow
from app.infrastructure.redis_client import RedisNamespace, format_redis_key, get_redis

logger = logging.getLogger("privguard.taint")


class DistributedTaintStore:
    """Manages task taint tracking across multiple backend replicas."""

    def __init__(self, custom_redis: Optional[aioredis.Redis] = None) -> None:
        self._custom_redis = custom_redis
        # Process-local fallback cache if Redis is unavailable
        self._local_cache: dict[str, Set[str]] = {}

    def _get_client(self) -> Optional[aioredis.Redis]:
        return self._custom_redis or get_redis()

    async def add_taint(
        self,
        db: AsyncSession,
        task_id: str,
        resource: str,
        tenant_id: str = "default_tenant",
        classification: str = "CONFIDENTIAL",
    ) -> None:
        """
        Durable and distributed taint propagation.
        Writes to PostgreSQL ActiveTaint table and updates Redis fast cache.
        """
        # 1. Authoritative persistence in PostgreSQL
        taint_record = ActiveTaint(
            task_id=task_id,
            resource=resource,
            taint_level=classification,
            created_at=utcnow(),
        )
        db.add(taint_record)
        await db.commit()

        # 2. Redis fast cache
        redis_key = format_redis_key(RedisNamespace.TAINT, tenant_id, task_id)
        client = self._get_client()

        if client:
            try:
                await client.sadd(redis_key, resource)
                await client.expire(redis_key, 86400)  # 24 hour TTL
            except Exception as exc:
                logger.warning("Failed to cache taint in Redis: %s", exc)

        # 3. Local fallback cache
        local_set = self._local_cache.setdefault(f"{tenant_id}:{task_id}", set())
        local_set.add(resource)

    async def is_task_tainted(
        self,
        db: AsyncSession,
        task_id: str,
        tenant_id: str = "default_tenant",
    ) -> bool:
        """
        Evaluates whether a task context carries confidential taint across any replica.
        Checks Redis cache first, falling back monotonically to PostgreSQL.
        """
        redis_key = format_redis_key(RedisNamespace.TAINT, tenant_id, task_id)
        client = self._get_client()

        if client:
            try:
                count = await client.scard(redis_key)
                if count > 0:
                    return True
            except Exception:
                pass

        # Check process local cache
        local_set = self._local_cache.get(f"{tenant_id}:{task_id}", set())
        if len(local_set) > 0:
            return True

        # Fallback to authoritative PostgreSQL
        query = select(ActiveTaint).where(ActiveTaint.task_id == task_id).limit(1)
        res = await db.execute(query)
        record = res.scalar_one_or_none()
        if record:
            # Rehydrate cache
            if client:
                try:
                    await client.sadd(redis_key, record.resource)
                    await client.expire(redis_key, 86400)
                except Exception:
                    pass
            return True

        return False

    async def get_task_taints(
        self,
        db: AsyncSession,
        task_id: str,
        tenant_id: str = "default_tenant",
    ) -> List[str]:
        """Returns all tainted resources associated with an active task."""
        redis_key = format_redis_key(RedisNamespace.TAINT, tenant_id, task_id)
        client = self._get_client()

        if client:
            try:
                members = await client.smembers(redis_key)
                if members:
                    return list(members)
            except Exception:
                pass

        # Fallback to PostgreSQL
        query = select(ActiveTaint).where(ActiveTaint.task_id == task_id)
        res = await db.execute(query)
        records = res.scalars().all()
        return [r.resource for r in records]

    async def clear_task_taint(
        self,
        db: AsyncSession,
        task_id: str,
        tenant_id: str = "default_tenant",
    ) -> None:
        """Removes taint from both PostgreSQL and distributed cache."""
        redis_key = format_redis_key(RedisNamespace.TAINT, tenant_id, task_id)
        client = self._get_client()

        if client:
            try:
                await client.delete(redis_key)
            except Exception:
                pass

        self._local_cache.pop(f"{tenant_id}:{task_id}", None)

        query = delete(ActiveTaint).where(ActiveTaint.task_id == task_id)
        await db.execute(query)
        await db.commit()

    clear_task_taints = clear_task_taint
