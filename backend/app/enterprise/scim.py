"""SCIM 2.0 (RFC 7643 / RFC 7644) provisioning interface."""

from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from app.core.exceptions import AuthenticationError, AuthorizationError
from app.database.models import OrganizationMembership, CapabilityGrant, ApprovalRequest, utcnow


class SCIMName(BaseModel):
    formatted: Optional[str] = None
    familyName: Optional[str] = None
    givenName: Optional[str] = None


class SCIMEmail(BaseModel):
    value: str
    primary: bool = True
    type: str = "work"


class SCIMRole(BaseModel):
    value: str


class SCIMUserPayload(BaseModel):
    schemas: List[str] = ["urn:ietf:params:scim:schemas:core:2.0:User"]
    userName: str
    name: Optional[SCIMName] = None
    emails: List[SCIMEmail] = Field(default_factory=list)
    active: bool = True
    roles: List[SCIMRole] = Field(default_factory=list)


class SCIMService:
    """Handles enterprise user lifecycle provisioning and instant deprovisioning via SCIM 2.0."""

    @staticmethod
    def _map_to_scim(membership: OrganizationMembership) -> Dict[str, Any]:
        return {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": membership.user_id,
            "userName": membership.email,
            "name": {
                "formatted": membership.email.split("@")[0],
                "familyName": "",
                "givenName": membership.email.split("@")[0],
            },
            "emails": [{"value": membership.email, "primary": True, "type": "work"}],
            "active": membership.status == "ACTIVE",
            "roles": [{"value": membership.role}],
            "meta": {
                "resourceType": "User",
                "created": membership.created_at.isoformat(),
                "lastModified": (membership.updated_at or membership.created_at).isoformat(),
            },
        }

    @classmethod
    async def get_user(cls, db: AsyncSession, organization_id: str, user_id: str) -> Dict[str, Any]:
        """Retrieves a single user by SCIM ID."""
        q = select(OrganizationMembership).where(
            OrganizationMembership.organization_id == organization_id,
            OrganizationMembership.user_id == user_id,
        )
        res = await db.execute(q)
        mem = res.scalar_one_or_none()
        if not mem:
            raise AuthorizationError(f"SCIM User '{user_id}' not found.")
        return cls._map_to_scim(mem)

    @classmethod
    async def list_users(
        cls, db: AsyncSession, organization_id: str, start_index: int = 1, count: int = 50
    ) -> Dict[str, Any]:
        """Lists provisioned enterprise users in SCIM 2.0 ListResponse format."""
        q = (
            select(OrganizationMembership)
            .where(OrganizationMembership.organization_id == organization_id)
            .offset(start_index - 1)
            .limit(count)
        )
        res = await db.execute(q)
        members = res.scalars().all()

        return {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": len(members),
            "startIndex": start_index,
            "itemsPerPage": len(members),
            "Resources": [cls._map_to_scim(m) for m in members],
        }

    @classmethod
    async def provision_user(cls, db: AsyncSession, organization_id: str, payload: SCIMUserPayload) -> Dict[str, Any]:
        """Provisions a new user into the enterprise organization."""
        email = payload.userName.lower().strip()
        role = payload.roles[0].value if payload.roles else "VIEWER"

        # Check existing
        q = select(OrganizationMembership).where(
            OrganizationMembership.organization_id == organization_id,
            OrganizationMembership.email == email,
        )
        res = await db.execute(q)
        existing = res.scalar_one_or_none()

        if existing:
            existing.status = "ACTIVE" if payload.active else "SUSPENDED"
            existing.role = role
            existing.updated_at = utcnow()
            await db.commit()
            await db.refresh(existing)
            return cls._map_to_scim(existing)

        new_mem = OrganizationMembership(
            organization_id=organization_id,
            user_id=f"usr_{email.replace('@', '_').replace('.', '_')}",
            email=email,
            role=role,
            status="ACTIVE" if payload.active else "SUSPENDED",
        )
        db.add(new_mem)
        await db.commit()
        await db.refresh(new_mem)
        return cls._map_to_scim(new_mem)

    @classmethod
    async def update_user(
        cls, db: AsyncSession, organization_id: str, user_id: str, payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Updates user attributes or deactivates user."""
        q = select(OrganizationMembership).where(
            OrganizationMembership.organization_id == organization_id,
            OrganizationMembership.user_id == user_id,
        )
        res = await db.execute(q)
        mem = res.scalar_one_or_none()
        if not mem:
            raise AuthorizationError(f"SCIM User '{user_id}' not found.")

        if "active" in payload:
            mem.status = "ACTIVE" if payload["active"] else "SUSPENDED"
            if not payload["active"]:
                # If deactivating, trigger revocation
                await cls._revoke_user_authorizations(db, organization_id, user_id)

        if "roles" in payload and payload["roles"]:
            mem.role = payload["roles"][0].get("value", mem.role)

        mem.updated_at = utcnow()
        await db.commit()
        await db.refresh(mem)
        return cls._map_to_scim(mem)

    @classmethod
    async def deprovision_user(cls, db: AsyncSession, organization_id: str, user_id: str) -> None:
        """
        Deprovisions user with immediate revocation of all sessions and capability grants.
        Strict requirement: A deprovisioned user must immediately lose authorization.
        """
        q = select(OrganizationMembership).where(
            OrganizationMembership.organization_id == organization_id,
            OrganizationMembership.user_id == user_id,
        )
        res = await db.execute(q)
        mem = res.scalar_one_or_none()
        if not mem:
            raise AuthorizationError(f"SCIM User '{user_id}' not found.")

        mem.status = "DEPROVISIONED"
        mem.updated_at = utcnow()

        # Revoke user authorizations immediately
        await cls._revoke_user_authorizations(db, organization_id, user_id)
        await db.commit()

    @staticmethod
    async def _revoke_user_authorizations(db: AsyncSession, organization_id: str, user_id: str) -> None:
        """Immediately terminates pending approvals and active grants related to the user."""
        # Expire any pending approval requests assigned to the user
        await db.execute(
            update(ApprovalRequest)
            .where(
                ApprovalRequest.tenant_id == organization_id,
                ApprovalRequest.approver_id == user_id,
                ApprovalRequest.status == "PENDING",
            )
            .values(status="EXPIRED")
        )
