"""Integration tests for Tenant Applicability Scoping and Role Decisions."""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.compliance.applicability import applicability_manager
from app.compliance.schemas import (
    ApplicabilityDecision,
    ApplicabilityUpdateRequest,
    OrganizationRole,
)


@pytest.mark.asyncio
async def test_applicability_crud(db_session: AsyncSession):
    """Verifies creating and updating tenant applicability decisions."""
    req = ApplicabilityUpdateRequest(
        framework_id="dpdp-2023",
        requirement_id=None,
        decision=ApplicabilityDecision.APPLICABLE,
        role=OrganizationRole.DATA_FIDUCIARY,
        justification="Operating as primary data fiduciary for Indian consumer memory processing.",
    )

    rec = await applicability_manager.set_applicability_decision(
        db=db_session,
        tenant_id="tenant_alpha",
        update_req=req,
        reviewed_by="auditor_jane",
    )

    assert rec.tenant_id == "tenant_alpha"
    assert rec.framework_id == "dpdp-2023"
    assert rec.role == "DATA_FIDUCIARY"
    assert rec.decision == "APPLICABLE"

    # Query
    records = await applicability_manager.get_tenant_applicability(
        db=db_session, tenant_id="tenant_alpha", framework_id="dpdp-2023"
    )
    assert len(records) == 1
    assert records[0].justification == req.justification

    # Update decision to NOT_APPLICABLE
    update_req2 = ApplicabilityUpdateRequest(
        framework_id="dpdp-2023",
        requirement_id=None,
        decision=ApplicabilityDecision.NOT_APPLICABLE,
        role=OrganizationRole.DATA_PROCESSOR,
        justification="Re-scoped to pure data processor under enterprise B2B agreement.",
    )
    rec2 = await applicability_manager.set_applicability_decision(
        db=db_session,
        tenant_id="tenant_alpha",
        update_req=update_req2,
        reviewed_by="auditor_jane",
    )
    assert rec2.decision == "NOT_APPLICABLE"
    assert rec2.role == "DATA_PROCESSOR"

