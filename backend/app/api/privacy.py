"""Privacy inspection and redaction endpoints."""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.authentication import get_current_app
from app.database.connection import get_db_session
from app.database.models import Application
from app.monitoring.audit import audit_logger
from app.privacy.pipeline import inspection_pipeline

router = APIRouter(prefix="/v1/privacy", tags=["Privacy Engine"])


class InspectRequest(BaseModel):
    """Payload to inspect for sensitive information."""
    text: str = Field(..., min_length=1, description="Raw input text to inspect")
    request_id: Optional[str] = Field(None, description="Optional caller correlation ID")


class InspectResponse(BaseModel):
    """Inspection result metadata."""
    category: str
    risk_level: str
    action: str
    is_blocked: bool
    blocking_reason: Optional[str] = None
    detected_secrets: List[Dict[str, Any]]
    detected_pii: List[Dict[str, Any]]
    entity_counts: Dict[str, int]
    content_fingerprint: str


class RedactRequest(BaseModel):
    """Payload to sanitize via redaction."""
    text: str = Field(..., min_length=1)
    reversible: bool = True


class RedactResponse(BaseModel):
    """Sanitized payload and token mapping."""
    sanitized_text: str
    mapping: Dict[str, str]
    entity_counts: Dict[str, int]


@router.post("/inspect", response_model=InspectResponse)
async def inspect_data(
    payload: InspectRequest,
    current_app: Application = Depends(get_current_app),
    db: AsyncSession = Depends(get_db_session),
) -> InspectResponse:
    """
    Inspects text through secret scanning, PII detection, classification, and policy.
    Audits the event without storing the payload.
    """
    verdict = inspection_pipeline.inspect_text(payload.text)

    # Record content-free audit event
    req_id = payload.request_id or f"req_{verdict.content_fingerprint[:12]}"
    await audit_logger.log_event(
        db=db,
        request_id=req_id,
        app_id=current_app.id,
        event_type="DATA_INSPECTED" if not verdict.is_blocked else "SECRET_BLOCKED",
        action_taken=verdict.action.value,
        risk_level=verdict.risk_level.value,
        data_category=verdict.category.value,
        entity_counts=verdict.entity_counts,
        content_fingerprint=verdict.content_fingerprint,
        status="BLOCKED" if verdict.is_blocked else "SUCCESS",
    )

    return InspectResponse(
        category=verdict.category.value,
        risk_level=verdict.risk_level.value,
        action=verdict.action.value,
        is_blocked=verdict.is_blocked,
        blocking_reason=verdict.blocking_reason,
        detected_secrets=verdict.detected_secrets,
        detected_pii=verdict.detected_pii,
        entity_counts=verdict.entity_counts,
        content_fingerprint=verdict.content_fingerprint,
    )


@router.post("/redact", response_model=RedactResponse)
async def redact_data(
    payload: RedactRequest,
    current_app: Application = Depends(get_current_app),
) -> RedactResponse:
    """Sanitizes text by replacing detected sensitive entities with token placeholders."""
    verdict = inspection_pipeline.inspect_text(payload.text)
    return RedactResponse(
        sanitized_text=verdict.sanitized_text if not verdict.is_blocked else "[BLOCKED_CREDENTIAL]",
        mapping=verdict.redaction_mapping if payload.reversible else {},
        entity_counts=verdict.entity_counts,
    )

