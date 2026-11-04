"""Threat Detection & Defense REST API endpoints."""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import desc, select

from app.core.authentication import get_current_app
from app.database.connection import get_db_session
from app.database.models import Application, ThreatEvent
from app.threat_detection import (
    behavior_analyzer,
    content_analyzer,
    exfiltration_detector,
    injection_detector,
    threat_response_engine,
)
from app.threat_detection.schemas import (
    SourceType,
    ThreatAssessment,
    TrustLevel,
)

router = APIRouter(prefix="/v1/threats", tags=["Threat Detection"])


class InspectContentRequest(BaseModel):
    text: str = Field(..., min_length=1, description="Raw input text to inspect")
    source_type: SourceType = Field(default=SourceType.USER_INPUT, description="Origin source type")


class InspectContentResponse(BaseModel):
    assessment: ThreatAssessment
    trust_level: TrustLevel
    sanitized_content: str
    is_quarantined: bool


class EvaluateBehaviorRequest(BaseModel):
    task_id: str = Field(..., description="ID of task to analyze")


class ThreatEventResponse(BaseModel):
    id: str
    application_id: str
    task_id: Optional[str]
    agent_id: Optional[str]
    threat_type: str
    severity: str
    confidence: float
    rule_id: str
    action_taken: str
    content_hash: str
    created_at: str


@router.post("/inspect", response_model=InspectContentResponse)
async def inspect_content(
    payload: InspectContentRequest,
    app: Application = Depends(get_current_app),
    db: AsyncSession = Depends(get_db_session),
) -> InspectContentResponse:

    """Inspects arbitrary content or user prompts for injection and security threats."""
    envelope, assessment = content_analyzer.wrap_and_analyze(
        raw_text=payload.text,
        source_type=payload.source_type,
        tenant_id=app.id,
    )

    if assessment.is_threat:
        await threat_response_engine.log_threat_event(
            db=db,
            application_id=app.id,
            assessment=assessment,
            content_for_hash=payload.text,
        )

    return InspectContentResponse(
        assessment=assessment,
        trust_level=envelope.trust_level,
        sanitized_content=envelope.content,
        is_quarantined=(envelope.trust_level == TrustLevel.QUARANTINED),
    )


@router.post("/evaluate-behavior", response_model=ThreatAssessment)
async def evaluate_task_behavior(
    payload: EvaluateBehaviorRequest,
    app: Application = Depends(get_current_app),
) -> ThreatAssessment:
    """Evaluates the sliding-window tool invocation pattern for an active task."""
    return behavior_analyzer.evaluate_behavior(payload.task_id)


@router.get("/taints/{task_id}")
async def get_task_taints(
    task_id: str,
    app: Application = Depends(get_current_app),
) -> Dict[str, Any]:
    """Returns active taint propagation status for an autonomous task context."""
    is_tainted = exfiltration_detector.is_task_tainted(task_id)
    taints = exfiltration_detector.get_task_taints(task_id)
    return {
        "task_id": task_id,
        "is_tainted": is_tainted,
        "tainted_resources": taints,
    }


@router.get("/events", response_model=List[ThreatEventResponse])
async def list_threat_events(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    severity: Optional[str] = None,
    threat_type: Optional[str] = None,
    app: Application = Depends(get_current_app),
    db: AsyncSession = Depends(get_db_session),
) -> List[ThreatEventResponse]:

    """Queries content-free threat events for the current application."""
    stmt = (
        select(ThreatEvent)
        .where(ThreatEvent.application_id == app.id)
        .order_by(desc(ThreatEvent.created_at))
        .limit(limit)
        .offset(offset)
    )
    if severity:
        stmt = stmt.where(ThreatEvent.severity == severity.upper())
    if threat_type:
        stmt = stmt.where(ThreatEvent.threat_type == threat_type.upper())

    result = await db.execute(stmt)
    records = result.scalars().all()

    return [
        ThreatEventResponse(
            id=r.id,
            application_id=r.application_id,
            task_id=r.task_id,
            agent_id=r.agent_id,
            threat_type=r.threat_type,
            severity=r.severity,
            confidence=r.confidence,
            rule_id=r.rule_id,
            action_taken=r.action_taken,
            content_hash=r.content_hash,
            created_at=r.created_at.isoformat(),
        )
        for r in records
    ]
