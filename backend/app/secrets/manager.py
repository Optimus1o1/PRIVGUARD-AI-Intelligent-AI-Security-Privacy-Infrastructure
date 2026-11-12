"""Manager for application secret metadata and lifecycle operations."""

from datetime import datetime, timezone
from typing import Dict, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from app.core.exceptions import PrivGuardException
from app.database.models import SecretMetadataRecord, SecretRotationJob, utcnow
from app.secrets.base import SecretMetadata, SecretStatus, SecretType


class SecretManager:
    """
    Manages application secret metadata and rotation lifecycle.

    SECURITY INVARIANTS:
    - Never stores plaintext credentials in the database metadata table.
    - Never exposes secret values in API metadata responses.
    - Enforces tenant isolation across all secret queries.
    """

    @classmethod
    async def register_secret(
        cls,
        db: AsyncSession,
        name: str,
        secret_type: SecretType,
        tenant_id: str = "default_tenant",
        provider_ref: Optional[str] = None,
        workspace_id: Optional[str] = None,
        expires_at: Optional[datetime] = None,
    ) -> SecretMetadataRecord:
        """Registers metadata for an application credential."""
        now = utcnow()
        record = SecretMetadataRecord(
            tenant_id=tenant_id,
            workspace_id=workspace_id,
            name=name,
            secret_type=secret_type.value,
            provider_ref=provider_ref,
            version=1,
            status=SecretStatus.ACTIVE.value,
            expires_at=expires_at,
            last_rotated_at=now,
            created_at=now,
        )
        db.add(record)
        await db.commit()
        await db.refresh(record)
        return record

    @classmethod
    async def list_secrets(
        cls,
        db: AsyncSession,
        tenant_id: str = "default_tenant",
        workspace_id: Optional[str] = None,
    ) -> List[SecretMetadata]:
        """Lists metadata for all secrets within the tenant (zero plaintext values)."""
        q = select(SecretMetadataRecord).where(SecretMetadataRecord.tenant_id == tenant_id)
        if workspace_id:
            q = q.where(SecretMetadataRecord.workspace_id == workspace_id)
        res = await db.execute(q)
        records = res.scalars().all()
        return [
            SecretMetadata(
                id=r.id,
                tenant_id=r.tenant_id,
                name=r.name,
                secret_type=SecretType(r.secret_type),
                version=r.version,
                status=SecretStatus(r.status),
                expires_at=r.expires_at.isoformat() if r.expires_at else None,
                created_at=r.created_at.isoformat(),
                last_rotated_at=r.last_rotated_at.isoformat(),
            )
            for r in records
        ]

    @classmethod
    async def rotate_secret(
        cls,
        db: AsyncSession,
        secret_id: str,
        tenant_id: str = "default_tenant",
    ) -> SecretRotationJob:
        """Initiates a rotation lifecycle for a secret."""
        q = select(SecretMetadataRecord).where(
            SecretMetadataRecord.id == secret_id,
            SecretMetadataRecord.tenant_id == tenant_id,
        )
        res = await db.execute(q)
        record = res.scalar_one_or_none()
        if not record:
            raise PrivGuardException(f"Secret '{secret_id}' not found.", status_code=404)

        now = utcnow()
        record.status = SecretStatus.ROTATING.value
        record.version += 1
        record.last_rotated_at = now

        job = SecretRotationJob(
            tenant_id=tenant_id,
            secret_id=secret_id,
            status="COMPLETED",  # In metadata tier, advance version and record job
            created_at=now,
            completed_at=now,
        )
        db.add(job)
        record.status = SecretStatus.ACTIVE.value
        await db.commit()
        await db.refresh(job)
        return job

    @classmethod
    async def revoke_secret(
        cls,
        db: AsyncSession,
        secret_id: str,
        tenant_id: str = "default_tenant",
    ) -> bool:
        """Revokes an operational credential, preventing any further usage."""
        q = select(SecretMetadataRecord).where(
            SecretMetadataRecord.id == secret_id,
            SecretMetadataRecord.tenant_id == tenant_id,
        )
        res = await db.execute(q)
        record = res.scalar_one_or_none()
        if not record:
            raise PrivGuardException(f"Secret '{secret_id}' not found.", status_code=404)

        record.status = SecretStatus.REVOKED.value
        await db.commit()
        return True


# Global singleton instance
secret_manager = SecretManager()
