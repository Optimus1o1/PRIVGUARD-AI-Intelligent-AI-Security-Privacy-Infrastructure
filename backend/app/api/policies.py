"""Policy configuration and evaluation endpoints."""

from typing import List
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.authentication import get_current_app
from app.database.connection import get_db_session
from app.database.models import Application, PolicyRule
from app.policies.engine import DEFAULT_POLICY_RULES, policy_engine
from app.policies.schemas import PolicyDecision, PolicyEvaluationRequest

router = APIRouter(prefix="/v1/policies", tags=["Policies"])


@router.get("/")
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
