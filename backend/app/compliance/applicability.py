"""Tenant Applicability Scoping and Role Modeling for PRIVGUARD AI (Stage 10.9).

Handles organizational role assignments (Data Fiduciary, Data Processor, AI Deployer, AI Provider)
and framework/requirement applicability decisions with reviewer justification.
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.compliance.models import ComplianceApplicabilityRecord
from app.compliance.schemas import (
    ApplicabilityDecision,
    ApplicabilityRecordResponse,
    ApplicabilityUpdateRequest,
    OrganizationRole,
)


class ApplicabilityManager:
    """Manages tenant-scoped framework and clause applicability determinations."""

    async def get_tenant_applicability(
        self,
        db: AsyncSession,
        tenant_id: str,
        framework_id: Optional[str] = None,
    ) -> List[ComplianceApplicabilityRecord]:
        """Queries applicability records for a tenant with optional framework filter."""
        stmt = select(ComplianceApplicabilityRecord).where(ComplianceApplicabilityRecord.tenant_id == tenant_id)
        if framework_id:
            stmt = stmt.where(ComplianceApplicabilityRecord.framework_id == framework_id.strip().lower())

        res = await db.execute(stmt)
        return list(res.scalars().all())

    async def set_applicability_decision(
        self,
        db: AsyncSession,
        tenant_id: str,
        update_req: ApplicabilityUpdateRequest,
        reviewed_by: str = "compliance_officer",
    ) -> ComplianceApplicabilityRecord:
        """Creates or updates an applicability determination for a tenant."""
        stmt = select(ComplianceApplicabilityRecord).where(
            ComplianceApplicabilityRecord.tenant_id == tenant_id,
            ComplianceApplicabilityRecord.framework_id == update_req.framework_id.strip().lower(),
            ComplianceApplicabilityRecord.requirement_id == update_req.requirement_id,
        )
        res = await db.execute(stmt)
        record = res.scalar_one_or_none()

        now = datetime.now(timezone.utc)
        if record:
            record.decision = update_req.decision.value
            record.role = update_req.role.value
            record.justification = update_req.justification.strip()
            record.reviewed_by = reviewed_by
            record.reviewed_at = now
        else:
            record = ComplianceApplicabilityRecord(
                tenant_id=tenant_id,
                framework_id=update_req.framework_id.strip().lower(),
                requirement_id=update_req.requirement_id,
                decision=update_req.decision.value,
                role=update_req.role.value,
                justification=update_req.justification.strip(),
                reviewed_by=reviewed_by,
                reviewed_at=now,
            )
            db.add(record)

        await db.commit()
        await db.refresh(record)
        return record


# Global singleton manager
applicability_manager = ApplicabilityManager()
