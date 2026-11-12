"""Integration tests for Compliance Gap Analysis."""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.compliance.gap_analysis import gap_analyzer


@pytest.mark.asyncio
async def test_gap_analysis_detects_unmapped_and_missing_evidence(db_session: AsyncSession):
    """Verifies that gap analysis correctly detects missing evidence for an uncollected tenant."""
    result = await gap_analyzer.analyze_gaps(
        db=db_session, tenant_id="new_uncollected_tenant"
    )

    assert result.tenant_id == "new_uncollected_tenant"
    assert result.total_gaps > 0
    assert result.items is not None

    gap_types = {item.gap_type for item in result.items}
    # Uncollected tenant will have MISSING_EVIDENCE
    assert "MISSING_EVIDENCE" in gap_types

    # Ensure every gap item has actionable remediation
    for item in result.items:
        assert item.title
        assert item.remediation_action
        assert item.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")

