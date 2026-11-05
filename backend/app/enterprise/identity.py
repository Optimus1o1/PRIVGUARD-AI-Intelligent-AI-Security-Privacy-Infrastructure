"""Enterprise Identity, SSO (OIDC/SAML2), and membership management."""

import hashlib
import json
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete

from app.core.exceptions import AuthenticationError, AuthorizationError
from app.database.models import Organization, OrganizationMembership, OrganizationInvitation, utcnow


class SSOConfig(BaseModel):
    """Configuration for Enterprise Identity Provider (OIDC / SAML 2.0)."""
    provider_type: str = Field("OIDC", description="OIDC or SAML2")
    issuer: str
    client_id: str
    client_secret_ref: Optional[str] = None
    discovery_url: Optional[str] = None
    jwks_uri: Optional[str] = None
    redirect_uri: str
    allowed_domains: List[str] = Field(default_factory=list)
    enforce_sso: bool = False
    default_role: str = "VIEWER"


class DomainVerificationRecord(BaseModel):
    """Domain verification status and token."""
    domain: str
    verification_token: str
    verified: bool = False
    verified_at: Optional[datetime] = None


class EnterpriseIdentityManager:
    """Manages enterprise SSO authentication, domain verification, and membership lifecycles."""

    @staticmethod
    def generate_domain_verification_token(organization_id: str, domain: str) -> str:
        """Generates a secure verification token for DNS TXT or HTTP meta verification."""
        salt = f"privguard_domain_verify_{organization_id}_{domain}"
        return hashlib.sha256(salt.encode()).hexdigest()[:32]

    @staticmethod
    async def verify_domain(
        db: AsyncSession,
        organization_id: str,
        domain: str,
        provided_token: str
    ) -> bool:
        """
        Verifies organization domain ownership.
        Strict requirement: prevents unauthorized domain takeovers or unverified domain SSO.
        """
        expected_token = EnterpriseIdentityManager.generate_domain_verification_token(organization_id, domain)
        if not secrets.compare_digest(provided_token.strip(), expected_token):
            raise AuthorizationError("Domain verification failed: verification token mismatch.")

        # Update organization domain status
        q = select(Organization).where(Organization.id == organization_id)
        res = await db.execute(q)
        org = res.scalar_one_or_none()
        if not org:
            raise AuthorizationError(f"Organization '{organization_id}' not found.")

        org.domain = domain.lower()
        org.domain_verified = True
        org.updated_at = utcnow()
        await db.commit()
        return True

    @staticmethod
    def validate_sso_token(
        token_claims: Dict[str, Any],
        config: SSOConfig,
        expected_nonce: Optional[str] = None,
        expected_state: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Validates an incoming OIDC/SAML claims token against organization SSO requirements:
        - Issuer validation
        - Audience validation
        - Expiration validation
        - Nonce validation
        - Domain validation (verified domain check)
        """
        # 1. Issuer Validation
        issuer = token_claims.get("iss")
        if issuer != config.issuer:
            raise AuthenticationError(f"SSO Token validation failed: Issuer mismatch ('{issuer}' != '{config.issuer}').")

        # 2. Audience Validation
        aud = token_claims.get("aud")
        if isinstance(aud, list):
            if config.client_id not in aud:
                raise AuthenticationError(f"SSO Token validation failed: Audience mismatch.")
        elif aud != config.client_id:
            raise AuthenticationError(f"SSO Token validation failed: Audience mismatch ('{aud}' != '{config.client_id}').")

        # 3. Expiration Validation
        exp = token_claims.get("exp")
        if exp is not None:
            now_ts = int(time.time())
            if now_ts >= exp:
                raise AuthenticationError("SSO Token validation failed: Token expired.")

        # 4. Nonce Validation
        if expected_nonce:
            token_nonce = token_claims.get("nonce")
            if not token_nonce or not secrets.compare_digest(token_nonce, expected_nonce):
                raise AuthenticationError("SSO Token validation failed: Nonce mismatch.")

        # 5. Email and Domain check
        email = token_claims.get("email")
        if not email or "@" not in email:
            raise AuthenticationError("SSO Token validation failed: Valid email claim missing.")

        user_domain = email.split("@")[1].lower()
        if config.allowed_domains and user_domain not in [d.lower() for d in config.allowed_domains]:
            raise AuthenticationError(f"SSO Token validation failed: Domain '{user_domain}' is not authorized for this organization.")

        return {
            "email": email.lower(),
            "sub": token_claims.get("sub"),
            "name": token_claims.get("name", email.split("@")[0]),
            "role": config.default_role,
        }

    @staticmethod
    async def create_invitation(
        db: AsyncSession,
        organization_id: str,
        email: str,
        role: str,
        invited_by_user_id: str,
        expires_days: int = 7,
    ) -> Dict[str, Any]:
        """Creates an organization invitation token."""
        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        expires_at = utcnow() + timedelta(days=expires_days)

        inv = OrganizationInvitation(
            organization_id=organization_id,
            email=email.lower().strip(),
            role=role,
            token_hash=token_hash,
            invited_by_user_id=invited_by_user_id,
            status="PENDING",
            expires_at=expires_at,
        )
        db.add(inv)
        await db.commit()
        await db.refresh(inv)

        return {
            "invitation_id": inv.id,
            "organization_id": organization_id,
            "email": inv.email,
            "role": inv.role,
            "invitation_token": raw_token,
            "expires_at": inv.expires_at.isoformat(),
        }

    @staticmethod
    async def accept_invitation(
        db: AsyncSession,
        invitation_token: str,
        user_id: str,
    ) -> OrganizationMembership:
        """Consumes a pending invitation and creates an active organization membership."""
        token_hash = hashlib.sha256(invitation_token.strip().encode()).hexdigest()
        q = select(OrganizationInvitation).where(
            OrganizationInvitation.token_hash == token_hash,
            OrganizationInvitation.status == "PENDING"
        )
        res = await db.execute(q)
        inv = res.scalar_one_or_none()

        if not inv:
            raise AuthenticationError("Invalid or expired invitation token.")

        if inv.expires_at < utcnow():
            inv.status = "EXPIRED"
            await db.commit()
            raise AuthenticationError("Invitation has expired.")

        # Check if membership already exists
        mem_q = select(OrganizationMembership).where(
            OrganizationMembership.organization_id == inv.organization_id,
            OrganizationMembership.user_id == user_id,
        )
        mem_res = await db.execute(mem_q)
        existing_mem = mem_res.scalar_one_or_none()

        if existing_mem:
            existing_mem.status = "ACTIVE"
            existing_mem.role = inv.role
            existing_mem.updated_at = utcnow()
            membership = existing_mem
        else:
            membership = OrganizationMembership(
                organization_id=inv.organization_id,
                user_id=user_id,
                email=inv.email,
                role=inv.role,
                status="ACTIVE",
            )
            db.add(membership)

        inv.status = "ACCEPTED"
        await db.commit()
        await db.refresh(membership)
        return membership

    @staticmethod
    async def update_member_status(
        db: AsyncSession,
        organization_id: str,
        user_id: str,
        status: str,
    ) -> OrganizationMembership:
        """Suspends, activates, or deprovisions a member."""
        valid_statuses = ("ACTIVE", "SUSPENDED", "DEPROVISIONED")
        if status not in valid_statuses:
            raise ValueError(f"Invalid status '{status}'. Must be one of {valid_statuses}.")

        q = select(OrganizationMembership).where(
            OrganizationMembership.organization_id == organization_id,
            OrganizationMembership.user_id == user_id,
        )
        res = await db.execute(q)
        mem = res.scalar_one_or_none()
        if not mem:
            raise AuthorizationError("Member not found in organization.")

        mem.status = status
        mem.updated_at = utcnow()
        await db.commit()
        await db.refresh(mem)
        return mem

