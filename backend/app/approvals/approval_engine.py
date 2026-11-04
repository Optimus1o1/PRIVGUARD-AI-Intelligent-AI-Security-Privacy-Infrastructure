"""Human-in-the-Loop Approval Engine with Cryptographic Action Binding."""

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.exceptions import ApprovalRequiredError, PrivGuardException
from app.database.models import ApprovalRequest, ensure_utc, utcnow


def compute_action_hash(
    tool_name: str,
    target_resource: Optional[str],
    parameters: Dict[str, Any],
) -> str:
    """
    Computes a deterministic cryptographic SHA-256 fingerprint of the exact proposed action.
    Binds tool name, target resource, and canonical JSON parameters.
    """
    canonical_params = json.dumps(parameters, sort_keys=True, separators=(",", ":"))
    payload = f"{tool_name.strip()}|{(target_resource or '').strip()}|{canonical_params}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class ApprovalEngine:
    """Manages the lifecycle and verification of human approval requests."""

    async def create_request(
        self,
        db: AsyncSession,
        task_id: str,
        agent_id: str,
        app_id: str,
        tool_name: str,
        target_resource: Optional[str],
        parameters: Dict[str, Any],
        risk_level: str = "HIGH",
        ttl_seconds: int = 300,
    ) -> ApprovalRequest:
        """Creates a pending human approval request bound cryptographically to the exact action."""
        action_hash = compute_action_hash(tool_name, target_resource, parameters)
        canonical_params = json.dumps(parameters, sort_keys=True, separators=(",", ":"))
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)

        approval = ApprovalRequest(
            task_id=task_id,
            agent_id=agent_id,
            app_id=app_id,
            tool_name=tool_name,
            target_resource=target_resource,
            action_parameters=canonical_params,
            action_hash=action_hash,
            risk_level=risk_level,
            status="PENDING",
            created_at=datetime.now(timezone.utc),
            expires_at=expires_at,
        )
        db.add(approval)
        await db.commit()
        await db.refresh(approval)
        return approval

    async def approve(
        self,
        db: AsyncSession,
        approval_id: str,
        app_id: str,
        approver_id: str = "human_operator",
    ) -> ApprovalRequest:
        """Authorizes a pending approval request."""
        query = select(ApprovalRequest).where(
            ApprovalRequest.id == approval_id,
            ApprovalRequest.app_id == app_id,
        )
        result = await db.execute(query)
        req = result.scalar_one_or_none()

        if not req:
            raise PrivGuardException(
                message=f"Approval request '{approval_id}' not found.",
                status_code=404,
                error_code="APPROVAL_NOT_FOUND",
            )

        if req.status != "PENDING":
            raise PrivGuardException(
                message=f"Cannot approve request in status '{req.status}'.",
                status_code=400,
                error_code="APPROVAL_INVALID_STATE",
            )

        # Check expiration
        now = datetime.now(timezone.utc)
        if ensure_utc(req.expires_at) < now:
            req.status = "EXPIRED"
            await db.commit()
            raise PrivGuardException(
                message="Approval request has expired.",
                status_code=400,
                error_code="APPROVAL_EXPIRED",
            )

        req.status = "APPROVED"
        req.approver_id = approver_id
        req.resolved_at = now
        await db.commit()
        await db.refresh(req)
        return req

    async def reject(
        self,
        db: AsyncSession,
        approval_id: str,
        app_id: str,
        approver_id: str = "human_operator",
    ) -> ApprovalRequest:
        """Rejects a pending approval request."""
        query = select(ApprovalRequest).where(
            ApprovalRequest.id == approval_id,
            ApprovalRequest.app_id == app_id,
        )
        result = await db.execute(query)
        req = result.scalar_one_or_none()

        if not req:
            raise PrivGuardException(
                message=f"Approval request '{approval_id}' not found.",
                status_code=404,
                error_code="APPROVAL_NOT_FOUND",
            )

        if req.status != "PENDING":
            raise PrivGuardException(
                message=f"Cannot reject request in status '{req.status}'.",
                status_code=400,
                error_code="APPROVAL_INVALID_STATE",
            )

        req.status = "REJECTED"
        req.approver_id = approver_id
        req.resolved_at = datetime.now(timezone.utc)
        await db.commit()
        await db.refresh(req)
        return req

    async def verify_and_consume(
        self,
        db: AsyncSession,
        approval_id: str,
        tool_name: str,
        target_resource: Optional[str],
        parameters: Dict[str, Any],
        app_id: str,
    ) -> bool:
        """
        Validates approval state, anti-tampering hash match, and atomically consumes the approval.
        Raises an exception if parameters were altered, status is not APPROVED, or approval expired.
        """
        query = select(ApprovalRequest).where(
            ApprovalRequest.id == approval_id,
            ApprovalRequest.app_id == app_id,
        )
        result = await db.execute(query)
        req = result.scalar_one_or_none()

        if not req:
            raise PrivGuardException(
                message=f"Approval request '{approval_id}' not found.",
                status_code=404,
                error_code="APPROVAL_NOT_FOUND",
            )

        if req.status == "CONSUMED":
            raise PrivGuardException(
                message="Approval has already been consumed (anti-replay violation).",
                status_code=403,
                error_code="APPROVAL_ALREADY_CONSUMED",
            )

        if req.status != "APPROVED":
            raise PrivGuardException(
                message=f"Approval '{approval_id}' is not in APPROVED state (current: {req.status}).",
                status_code=403,
                error_code="APPROVAL_NOT_GRANTED",
            )

        now = datetime.now(timezone.utc)
        if ensure_utc(req.expires_at) < now:
            req.status = "EXPIRED"
            await db.commit()
            raise PrivGuardException(
                message="Approval has expired before execution.",
                status_code=403,
                error_code="APPROVAL_EXPIRED",
            )

        # CRITICAL ANTI-TAMPERING INVARIANT: Action Hash Verification
        current_hash = compute_action_hash(tool_name, target_resource, parameters)
        if current_hash != req.action_hash:
            raise PrivGuardException(
                message="Action parameter tampering detected: parameters do not match approved action hash.",
                status_code=403,
                error_code="APPROVAL_TAMPERING_DETECTED",
            )

        # Atomic State Transition: APPROVED -> CONSUMED
        req.status = "CONSUMED"
        req.consumed_at = now
        await db.commit()
        return True

    async def list_pending(
        self,
        db: AsyncSession,
        app_id: str,
        agent_id: Optional[str] = None,
    ) -> List[ApprovalRequest]:
        """Lists active pending approval requests for an application."""
        query = select(ApprovalRequest).where(
            ApprovalRequest.app_id == app_id,
            ApprovalRequest.status == "PENDING",
            ApprovalRequest.expires_at > datetime.now(timezone.utc),
        )
        if agent_id:
            query = query.where(ApprovalRequest.agent_id == agent_id)

        result = await db.execute(query)
        return list(result.scalars().all())


# Shared approval engine instance
approval_engine = ApprovalEngine()
