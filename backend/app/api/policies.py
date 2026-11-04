"""Policy configuration and evaluation endpoints."""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import delete, select

from app.core.authentication import get_current_app
from app.core.exceptions import PrivGuardException
from app.database.connection import get_db_session
from app.database.models import Application, PolicyRule
from app.monitoring.audit import audit_logger
from app.policies.engine import DEFAULT_POLICY_RULES, policy_engine
from app.policies.schemas import PolicyDecision, PolicyEvaluationRequest

router = APIRouter(prefix="/v1/policies", tags=["Policies"])


class CreatePolicyRuleRequest(BaseModel):
    category: str = Field(..., description="Data category: PUBLIC, INTERNAL, PERSONAL, CONFIDENTIAL, CRITICAL")
    action: str = Field(..., description="Action: ALLOW, REDACT, BLOCK, REQUIRE_APPROVAL")
    risk_level: str = Field(..., description="Risk level: LOW, MEDIUM, HIGH, CRITICAL")
    description: Optional[str] = Field(None, max_length=255)
    is_enabled: bool = True


class UpdatePolicyRuleRequest(BaseModel):
    action: Optional[str] = None
    risk_level: Optional[str] = None
    description: Optional[str] = None
    is_enabled: Optional[bool] = None


class PolicyRuleResponse(BaseModel):
    id: str
    category: str
    action: str
    risk_level: str
    is_enabled: bool
    description: Optional[str]


@router.get("/")
@router.get("")
async def list_policies(
    current_app: Application = Depends(get_current_app),
    db: AsyncSession = Depends(get_db_session),
):
    """Lists active baseline and application-specific security policies."""
    query = select(PolicyRule).where(
        (PolicyRule.app_id == current_app.id) | (PolicyRule.app_id.is_(None))
    )
    result = await db.execute(query)
    custom_rules = result.scalars().all()

    baseline = [
        {
            "category": cat,
            "action": action.value,
            "risk_level": risk,
            "description": desc,
            "is_baseline": True,
        }
        for cat, (action, risk, desc) in DEFAULT_POLICY_RULES.items()
    ]

    return {
        "baseline_policies": baseline,
        "custom_rules": [
            {
                "id": r.id,
                "category": r.category,
                "action": r.action,
                "risk_level": r.risk_level,
                "is_enabled": r.is_enabled,
                "description": r.description,
            }
            for r in custom_rules
        ],
    }


@router.post("", response_model=PolicyRuleResponse)
async def create_policy_rule(
    payload: CreatePolicyRuleRequest,
    current_app: Application = Depends(get_current_app),
    db: AsyncSession = Depends(get_db_session),
) -> PolicyRuleResponse:
    """Creates a custom policy rule with security boundary checks."""
    cat = payload.category.upper()
    act = payload.action.upper()
    risk = payload.risk_level.upper()

    # Invariant: CRITICAL secrets cannot be configured to ALLOW
    if cat == "CRITICAL" and act == "ALLOW":
        raise PrivGuardException(
            message="Security invariant violation: CRITICAL category cannot be set to ALLOW.",
            status_code=400,
            error_code="INVALID_POLICY_INVARIANT",
        )

    rule = PolicyRule(
        app_id=current_app.id,
        category=cat,
        action=act,
        risk_level=risk,
        is_enabled=payload.is_enabled,
        description=payload.description,
    )
    db.add(rule)
    await db.commit()
    await db.refresh(rule)

    # Log policy creation in audit trail
    await audit_logger.log_event(
        db=db,
        request_id=f"pol_create_{rule.id}",
        app_id=current_app.id,
        event_type="POLICY_RULE_CREATED",
        action_taken=act,
        risk_level=risk,
        data_category=cat,
        entity_counts={"CUSTOM_POLICY": 1},
        content_fingerprint=rule.id,
        status="SUCCESS",
    )
    await db.commit()

    return PolicyRuleResponse(
        id=rule.id,
        category=rule.category,
        action=rule.action,
        risk_level=rule.risk_level,
        is_enabled=rule.is_enabled,
        description=rule.description,
    )


@router.put("/{rule_id}", response_model=PolicyRuleResponse)
async def update_policy_rule(
    rule_id: str,
    payload: UpdatePolicyRuleRequest,
    current_app: Application = Depends(get_current_app),
    db: AsyncSession = Depends(get_db_session),
) -> PolicyRuleResponse:
    """Updates an existing application-specific policy rule."""
    stmt = select(PolicyRule).where(
        PolicyRule.id == rule_id, PolicyRule.app_id == current_app.id
    )
    res = await db.execute(stmt)
    rule = res.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Policy rule not found.")

    if payload.action is not None:
        act = payload.action.upper()
        if rule.category == "CRITICAL" and act == "ALLOW":
            raise PrivGuardException(
                message="Security invariant violation: CRITICAL category cannot be set to ALLOW.",
                status_code=400,
                error_code="INVALID_POLICY_INVARIANT",
            )
        rule.action = act

    if payload.risk_level is not None:
        rule.risk_level = payload.risk_level.upper()
    if payload.description is not None:
        rule.description = payload.description
    if payload.is_enabled is not None:
        rule.is_enabled = payload.is_enabled

    await db.commit()
    await db.refresh(rule)

    await audit_logger.log_event(
        db=db,
        request_id=f"pol_upd_{rule.id}",
        app_id=current_app.id,
        event_type="POLICY_RULE_UPDATED",
        action_taken=rule.action,
        risk_level=rule.risk_level,
        data_category=rule.category,
        entity_counts={"CUSTOM_POLICY": 1},
        content_fingerprint=rule.id,
        status="SUCCESS",
    )
    await db.commit()

    return PolicyRuleResponse(
        id=rule.id,
        category=rule.category,
        action=rule.action,
        risk_level=rule.risk_level,
        is_enabled=rule.is_enabled,
        description=rule.description,
    )


@router.delete("/{rule_id}")
async def delete_policy_rule(
    rule_id: str,
    current_app: Application = Depends(get_current_app),
    db: AsyncSession = Depends(get_db_session),
):
    """Deletes an application-specific custom policy rule."""
    stmt = select(PolicyRule).where(
        PolicyRule.id == rule_id, PolicyRule.app_id == current_app.id
    )
    res = await db.execute(stmt)
    rule = res.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Policy rule not found.")

    await db.delete(rule)
    await db.commit()

    await audit_logger.log_event(
        db=db,
        request_id=f"pol_del_{rule_id}",
        app_id=current_app.id,
        event_type="POLICY_RULE_DELETED",
        action_taken="DELETE",
        risk_level="HIGH",
        data_category=rule.category,
        entity_counts={"CUSTOM_POLICY": 1},
        content_fingerprint=rule_id,
        status="SUCCESS",
    )
    await db.commit()

    return {"status": "SUCCESS", "message": f"Policy rule '{rule_id}' deleted."}


@router.post("/evaluate", response_model=PolicyDecision)
async def test_evaluate_policy(
    payload: PolicyEvaluationRequest,
    current_app: Application = Depends(get_current_app),
) -> PolicyDecision:
    """Evaluates arbitrary inputs against configured policy rules."""
    has_secrets = len(payload.detected_secrets) > 0
    category = "CRITICAL" if has_secrets else ("PERSONAL" if payload.detected_entities else "PUBLIC")

    return policy_engine.evaluate(
        category=category,
        has_secrets=has_secrets,
        detected_entities=payload.detected_entities,
    )
