"""API router for cryptographic incident response and key compromise containment."""

from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import get_current_user_tenant
from app.database.connection import get_db
from app.key_management.compromise import CompromiseType, key_compromise_manager

router = APIRouter(prefix="/v1/incidents", tags=["Key Compromise Incident Response"])


class CompromiseReportRequest(BaseModel):
    compromise_type: CompromiseType
    target_id: str = Field(..., description="Target memory ID, Key ID, signing Key ID, or HMAC KID")
    notes: Optional[str] = None


@router.post("/compromise", status_code=status.HTTP_200_OK)
async def report_compromise(
    req: CompromiseReportRequest,
    db: AsyncSession = Depends(get_db),
    tenant_context: Dict[str, Any] = Depends(get_current_user_tenant),
) -> Dict[str, Any]:
    """
    Executes emergency compromise containment, revocation, key replacement,
    and necessary re-encryption according to incident type.
    """
    tenant_id = tenant_context.get("tenant_id", "default_tenant")

    if req.compromise_type == CompromiseType.DEK_COMPROMISE:
        res = await key_compromise_manager.handle_dek_compromise(db, memory_id=req.target_id, tenant_id=tenant_id)
    elif req.compromise_type == CompromiseType.KEK_COMPROMISE:
        res = await key_compromise_manager.handle_kek_compromise(db, key_id=req.target_id, tenant_id=tenant_id)
    elif req.compromise_type == CompromiseType.POLICY_SIGNING_KEY_COMPROMISE:
        res = await key_compromise_manager.handle_policy_signing_key_compromise(
            db, signing_key_id=req.target_id, tenant_id=tenant_id
        )
    elif req.compromise_type == CompromiseType.APPROVAL_HMAC_KEY_COMPROMISE:
        res = key_compromise_manager.handle_hmac_key_compromise(kid=req.target_id)
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported compromise type '{req.compromise_type}'")

    res["notes"] = req.notes
    return res
