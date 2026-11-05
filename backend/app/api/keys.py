"""API router for Key Management Service (KMS) operations and metadata."""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.auth import get_current_user_tenant
from app.core.exceptions import PrivGuardException
from app.database.connection import get_db
from app.database.models import KeyMigrationJob, KeyRotationJob, KeyVersion, ManagedKey
from app.key_management.base import KeyAlgorithm, KeyPurpose, KeyStatus
from app.key_management.manager import kms_manager
from app.key_management.migration import legacy_migrator
from app.key_management.rotation import key_rotation_engine

router = APIRouter(prefix="/v1/keys", tags=["Key Management"])


class KeyRegisterRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=128)
    purpose: KeyPurpose
    provider: str = Field(default="local")
    algorithm: KeyAlgorithm = Field(default=KeyAlgorithm.AES_256_GCM)
    external_key_ref: Optional[str] = None
    workspace_id: Optional[str] = None


class KeyMetadataResponse(BaseModel):
    id: str
    tenant_id: str
    name: str
    purpose: str
    provider: str
    algorithm: str
    status: str
    active_version_id: Optional[str] = None
    last_rotated_at: str
    created_at: str


class MigrationStartRequest(BaseModel):
    batch_size: int = Field(default=50, ge=1, le=500)


@router.get("", response_model=List[KeyMetadataResponse])
async def list_keys(
    workspace_id: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    tenant_context: Dict[str, Any] = Depends(get_current_user_tenant),
) -> List[KeyMetadataResponse]:
    """Lists all managed cryptographic keys for the tenant (metadata only, zero key material)."""
    tenant_id = tenant_context.get("tenant_id", "default_tenant")
    q = select(ManagedKey).where(ManagedKey.tenant_id == tenant_id)
    if workspace_id:
        q = q.where(ManagedKey.workspace_id == workspace_id)
    res = await db.execute(q)
    keys = res.scalars().all()

    return [
        KeyMetadataResponse(
            id=k.id,
            tenant_id=k.tenant_id,
            name=k.name,
            purpose=k.purpose,
            provider=k.provider,
            algorithm=k.algorithm,
            status=k.status,
            active_version_id=k.active_version_id,
            last_rotated_at=k.last_rotated_at.isoformat(),
            created_at=k.created_at.isoformat(),
        )
        for k in keys
    ]


@router.post("", response_model=KeyMetadataResponse, status_code=status.HTTP_201_CREATED)
async def register_key(
    req: KeyRegisterRequest,
    db: AsyncSession = Depends(get_db),
    tenant_context: Dict[str, Any] = Depends(get_current_user_tenant),
) -> KeyMetadataResponse:
    """Registers a new managed key in the central catalog."""
    tenant_id = tenant_context.get("tenant_id", "default_tenant")
    mkey = await key_rotation_engine.register_managed_key(
        db=db,
        name=req.name,
        purpose=req.purpose,
        tenant_id=tenant_id,
        provider=req.provider,
        algorithm=req.algorithm,
        external_key_ref=req.external_key_ref,
        workspace_id=req.workspace_id,
    )
    return KeyMetadataResponse(
        id=mkey.id,
        tenant_id=mkey.tenant_id,
        name=mkey.name,
        purpose=mkey.purpose,
        provider=mkey.provider,
        algorithm=mkey.algorithm,
        status=mkey.status,
        active_version_id=mkey.active_version_id,
        last_rotated_at=mkey.last_rotated_at.isoformat(),
        created_at=mkey.created_at.isoformat(),
    )


@router.get("/{key_id}")
async def get_key_details(
    key_id: str,
    db: AsyncSession = Depends(get_db),
    tenant_context: Dict[str, Any] = Depends(get_current_user_tenant),
) -> Dict[str, Any]:
    """Retrieves key metadata and historical version catalog (zero secret material)."""
    tenant_id = tenant_context.get("tenant_id", "default_tenant")
    q = select(ManagedKey).where(ManagedKey.id == key_id, ManagedKey.tenant_id == tenant_id)
    res = await db.execute(q)
    mkey = res.scalar_one_or_none()
    if not mkey:
        raise HTTPException(status_code=404, detail="Key not found")

    vq = select(KeyVersion).where(KeyVersion.key_id == key_id).order_by(KeyVersion.version_num.desc())
    vres = await db.execute(vq)
    versions = vres.scalars().all()

    return {
        "key": {
            "id": mkey.id,
            "tenant_id": mkey.tenant_id,
            "name": mkey.name,
            "purpose": mkey.purpose,
            "provider": mkey.provider,
            "algorithm": mkey.algorithm,
            "status": mkey.status,
            "active_version_id": mkey.active_version_id,
            "last_rotated_at": mkey.last_rotated_at.isoformat(),
            "created_at": mkey.created_at.isoformat(),
        },
        "versions": [
            {
                "id": v.id,
                "version_num": v.version_num,
                "provider_version_id": v.provider_version_id,
                "status": v.status,
                "has_public_key": bool(v.public_key_material),
                "created_at": v.created_at.isoformat(),
            }
            for v in versions
        ],
    }


@router.post("/{key_id}/rotate")
async def rotate_key(
    key_id: str,
    db: AsyncSession = Depends(get_db),
    tenant_context: Dict[str, Any] = Depends(get_current_user_tenant),
) -> Dict[str, Any]:
    """Triggers key rotation to a new version and initiates asynchronous DEK rewrapping."""
    tenant_id = tenant_context.get("tenant_id", "default_tenant")
    q = select(ManagedKey).where(ManagedKey.id == key_id, ManagedKey.tenant_id == tenant_id)
    res = await db.execute(q)
    mkey = res.scalar_one_or_none()
    if not mkey:
        raise HTTPException(status_code=404, detail="Key not found")

    job = await key_rotation_engine.initiate_rotation(db, key_id, mode="MANUAL")
    return {
        "status": "ROTATION_INITIATED",
        "job_id": job.id,
        "from_version": job.from_version,
        "to_version": job.to_version,
        "records_total": job.records_total,
    }


@router.post("/{key_id}/verify")
async def verify_key(
    key_id: str,
    db: AsyncSession = Depends(get_db),
    tenant_context: Dict[str, Any] = Depends(get_current_user_tenant),
) -> Dict[str, Any]:
    """Verifies KMS operational access and authorization to use the key."""
    tenant_id = tenant_context.get("tenant_id", "default_tenant")
    q = select(ManagedKey).where(ManagedKey.id == key_id, ManagedKey.tenant_id == tenant_id)
    res = await db.execute(q)
    mkey = res.scalar_one_or_none()
    if not mkey:
        raise HTTPException(status_code=404, detail="Key not found")

    target_ref = mkey.external_key_ref or mkey.id
    is_healthy = kms_manager.verify_health(target_ref)
    return {"key_id": key_id, "healthy": is_healthy, "provider": mkey.provider}


@router.get("/migration/status")
async def migration_status(
    db: AsyncSession = Depends(get_db),
    tenant_context: Dict[str, Any] = Depends(get_current_user_tenant),
) -> Dict[str, Any]:
    """Returns V1 to V2 KMS migration metrics and retirement readiness."""
    tenant_id = tenant_context.get("tenant_id", "default_tenant")
    unmigrated = await legacy_migrator.get_unmigrated_count(db, tenant_id)
    can_retire, reason = await legacy_migrator.can_retire_legacy_key(db, tenant_id)

    jq = select(KeyMigrationJob).where(KeyMigrationJob.tenant_id == tenant_id).order_by(KeyMigrationJob.created_at.desc())
    jres = await db.execute(jq)
    latest_job = jres.scalars().first()

    return {
        "unmigrated_records": unmigrated,
        "can_retire_legacy_key": can_retire,
        "retirement_check_reason": reason,
        "latest_job": {
            "id": latest_job.id,
            "status": latest_job.status,
            "records_total": latest_job.records_total,
            "records_migrated": latest_job.records_migrated,
        }
        if latest_job
        else None,
    }


@router.post("/migration/start")
async def start_migration(
    req: MigrationStartRequest,
    db: AsyncSession = Depends(get_db),
    tenant_context: Dict[str, Any] = Depends(get_current_user_tenant),
) -> Dict[str, Any]:
    """Starts or resumes a V1 to V2 migration batch."""
    tenant_id = tenant_context.get("tenant_id", "default_tenant")
    job = await legacy_migrator.start_migration_job(db, tenant_id=tenant_id, batch_size=req.batch_size)
    migrated, is_finished = await legacy_migrator.process_batch(db, job.id)
    return {
        "job_id": job.id,
        "status": job.status,
        "migrated_in_batch": migrated,
        "is_finished": is_finished,
    }
