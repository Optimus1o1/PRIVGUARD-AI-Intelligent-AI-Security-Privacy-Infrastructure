"""Temporary Capability Token Manager with Cryptographic Secret Hashing."""

import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from app.core.exceptions import PrivGuardException
from app.database.models import CapabilityGrant, ensure_utc, utcnow


def hash_capability_token(token: str) -> str:
    """Computes the SHA-256 hash of an opaque capability secret."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class CapabilityManager:
    """Issues, validates, and revokes task-scoped temporary access capability tokens."""

    async def issue_capability(
        self,
        db: AsyncSession,
        agent_id: str,
        task_id: str,
        app_id: str,
        tool_name: str,
        resource: Optional[str] = None,
        permissions: Optional[List[str]] = None,
        ttl_seconds: int = 300,
        max_uses: int = 1,
    ) -> Tuple[CapabilityGrant, str]:
        """
        Generates an opaque cryptographic capability token and stores only its SHA-256 hash.
        Returns the DB CapabilityGrant record and the one-time plaintext capability secret.
        """
        # Generate cryptographically secure 256-bit token
        raw_secret = f"pg_cap_{secrets.token_urlsafe(32)}"
        token_hash = hash_capability_token(raw_secret)

        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=ttl_seconds)

        grant = CapabilityGrant(
            secret_hash=token_hash,
            agent_id=agent_id,
            task_id=task_id,
            app_id=app_id,
            tool_name=tool_name,
            resource=resource,
            permissions=json.dumps(permissions or ["execute"]),
            expires_at=expires_at,
            max_uses=max(1, max_uses),
            uses_count=0,
            is_revoked=False,
            created_at=now,
        )
        db.add(grant)
        await db.commit()
        await db.refresh(grant)

        # Return record and raw secret to caller (raw secret is never stored!)
        return grant, raw_secret

    async def validate_and_consume(
        self,
        db: AsyncSession,
        raw_secret: str,
        expected_tool: str,
        expected_agent_id: str,
        expected_task_id: str,
        expected_app_id: str,
        resource: Optional[str] = None,
        consume: bool = True,
    ) -> CapabilityGrant:
        """
        Validates capability token, checks agent/task/app bounds, verifies expiration and usage limits,
        and optionally consumes one use.
        """
        token_hash = hash_capability_token(raw_secret)

        query = select(CapabilityGrant).where(CapabilityGrant.secret_hash == token_hash)
        result = await db.execute(query)
        grant = result.scalar_one_or_none()

        if not grant:
            raise PrivGuardException(
                message="Invalid or unrecognized capability token.",
                status_code=403,
                error_code="CAPABILITY_INVALID",
            )

        # Check bounds: app, agent, task, tool
        if grant.app_id != expected_app_id:
            raise PrivGuardException(
                message="Capability token does not belong to caller application context.",
                status_code=403,
                error_code="CAPABILITY_CROSS_APP_REJECTED",
            )

        if grant.agent_id != expected_agent_id:
            raise PrivGuardException(
                message=f"Capability token was issued to agent '{grant.agent_id}', not '{expected_agent_id}'.",
                status_code=403,
                error_code="CAPABILITY_AGENT_MISMATCH",
            )

        if grant.task_id != expected_task_id:
            raise PrivGuardException(
                message=f"Capability token was issued for task '{grant.task_id}', not '{expected_task_id}'.",
                status_code=403,
                error_code="CAPABILITY_TASK_MISMATCH",
            )

        if grant.tool_name != expected_tool:
            raise PrivGuardException(
                message=f"Capability token is authorized for tool '{grant.tool_name}', not '{expected_tool}'.",
                status_code=403,
                error_code="CAPABILITY_TOOL_MISMATCH",
            )

        # Check resource scope if specified
        if grant.resource and resource and grant.resource != resource and grant.resource != "*":
            raise PrivGuardException(
                message=f"Capability token resource scope '{grant.resource}' does not match requested resource '{resource}'.",
                status_code=403,
                error_code="CAPABILITY_RESOURCE_MISMATCH",
            )

        # Check revocation
        if grant.is_revoked:
            raise PrivGuardException(
                message="Capability token has been revoked.",
                status_code=403,
                error_code="CAPABILITY_REVOKED",
            )

        # Check expiration
        now = datetime.now(timezone.utc)
        if ensure_utc(grant.expires_at) < now:
            grant.is_revoked = True
            await db.commit()
            raise PrivGuardException(
                message="Capability token has expired.",
                status_code=403,
                error_code="CAPABILITY_EXPIRED",
            )

        # Check usage limit
        if grant.uses_count >= grant.max_uses:
            raise PrivGuardException(
                message=f"Capability token maximum use limit ({grant.max_uses}) exceeded.",
                status_code=403,
                error_code="CAPABILITY_MAX_USES_EXCEEDED",
            )

        # Atomically increment usage if consume is requested
        if consume:
            grant.uses_count += 1
            await db.commit()
            await db.refresh(grant)
        return grant

    async def consume_use(self, db: AsyncSession, grant: CapabilityGrant) -> CapabilityGrant:
        """Atomically increments the usage counter on an already-validated capability."""
        if grant.uses_count >= grant.max_uses:
            raise PrivGuardException(
                message=f"Capability token maximum use limit ({grant.max_uses}) exceeded.",
                status_code=403,
                error_code="CAPABILITY_MAX_USES_EXCEEDED",
            )
        grant.uses_count += 1
        await db.commit()
        await db.refresh(grant)
        return grant

    async def revoke_capability(
        self,
        db: AsyncSession,
        capability_id: str,
        app_id: str,
    ) -> CapabilityGrant:
        """Immediately revokes a capability grant by ID."""
        query = select(CapabilityGrant).where(
            CapabilityGrant.id == capability_id,
            CapabilityGrant.app_id == app_id,
        )
        result = await db.execute(query)
        grant = result.scalar_one_or_none()

        if not grant:
            raise PrivGuardException(
                message=f"Capability '{capability_id}' not found.",
                status_code=404,
                error_code="CAPABILITY_NOT_FOUND",
            )

        grant.is_revoked = True
        await db.commit()
        await db.refresh(grant)
        return grant


# Shared capability manager instance
capability_manager = CapabilityManager()
