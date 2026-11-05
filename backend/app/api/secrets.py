"""API router for application secret metadata management (zero plaintext)."""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import get_current_user_tenant
from app.database.connection import get_db
from app.secrets.base import SecretMetadata, SecretType
from app.secrets.manager import secret_manager

router = APIRouter(prefix="/v1/secrets", tags=["Secret Management"])


class SecretRegisterRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=128)
    secret_type: SecretType
    provider_ref: Optional[str] = None
    workspace_id: Optional[str] = None


class SecretMetadataResponse(BaseModel):
    id: str
    tenant_id: str
    name: str
    secret_type: str
    version: int
    status: str
    expires_at: Optional[str] = None
    created_at: str
    last_rotated_at: str


@router.get("", response_model=List[SecretMetadataResponse])
async def list_secrets(
    workspace_id: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    tenant_context: Dict[str, Any] = Depends(get_current_user_tenant),
) -> List[SecretMetadataResponse]:
    """Lists operational secret metadata for the tenant (metadata only, zero secret values)."""
    tenant_id = tenant_context.get("tenant_id", "default_tenant")
    items = await secret_manager.list_secrets(db, tenant_id=tenant_id, workspace_id=workspace_id)
    return [
        SecretMetadataResponse(
            id=s.id,
            tenant_id=s.tenant_id,
            name=s.name,
            secret_type=s.secret_type.value,
            version=s.version,
            status=s.status.value,
            expires_at=s.expires_at,
            created_at=s.created_at,
            last_rotated_at=s.last_rotated_at,
        )
        for s in items
    ]


@router.post("", response_model=SecretMetadataResponse, status_code=status.HTTP_201_CREATED)
async def register_secret(
    req: SecretRegisterRequest,
    db: AsyncSession = Depends(get_db),
    tenant_context: Dict[str, Any] = Depends(get_current_user_tenant),
) -> SecretMetadataResponse:
    """Registers metadata for a new operational secret (stores zero secret values)."""
    tenant_id = tenant_context.get("tenant_id", "default_tenant")
    record = await secret_manager.register_secret(
        db=db,
        name=req.name,
        secret_type=req.secret_type,
        tenant_id=tenant_id,
        provider_ref=req.provider_ref,
        workspace_id=req.workspace_id,
    )
    return SecretMetadataResponse(
        id=record.id,
        tenant_id=record.tenant_id,
        name=record.name,
        secret_type=record.secret_type,
        version=record.version,
        status=record.status,
        expires_at=record.expires_at.isoformat() if record.expires_at else None,
        created_at=record.created_at.isoformat(),
        last_rotated_at=record.last_rotated_at.isoformat(),
    )


@router.post("/{secret_id}/rotate")
async def rotate_secret(
    secret_id: str,
    db: AsyncSession = Depends(get_db),
    tenant_context: Dict[str, Any] = Depends(get_current_user_tenant),
) -> Dict[str, Any]:
    """Advances secret version and records a rotation job."""
    tenant_id = tenant_context.get("tenant_id", "default_tenant")
    job = await secret_manager.rotate_secret(db, secret_id, tenant_id=tenant_id)
    return {"status": "ROTATED", "job_id": job.id, "secret_id": secret_id}


@router.post("/{secret_id}/revoke")
async def revoke_secret(
    secret_id: str,
    db: AsyncSession = Depends(get_db),
    tenant_context: Dict[str, Any] = Depends(get_current_user_tenant),
) -> Dict[str, Any]:
    """Revokes secret credentials immediately."""
    tenant_id = tenant_context.get("tenant_id", "default_tenant")
    success = await secret_manager.revoke_secret(db, secret_id, tenant_id=tenant_id)
    return {"status": "REVOKED", "secret_id": secret_id, "success": success}
