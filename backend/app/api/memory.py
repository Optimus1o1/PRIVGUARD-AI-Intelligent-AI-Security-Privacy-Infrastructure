"""PRIVGUARD AI - Personal AI Memory Vault Endpoints.
Provides encrypted storage, lifecycle control, proposal consent, granular permissions,
and privacy-preserving retrieval for personal AI memory.
"""

from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Header, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.authentication import get_current_app
from app.core.exceptions import MemoryNotFoundError, PrivGuardException
from app.database.connection import get_db_session
from app.database.models import (
    Application,
    MemoryRecord,
    MemoryProposal,
    MemoryPermission,
    MemoryAuditEvent,
    MemoryDeletionJob,
    ensure_utc,
)
from app.memory.vault import memory_vault
from app.memory.permissions import memory_permission_engine
from app.memory.retrieval import memory_retrieval_service
from app.memory.validator import memory_validator
from app.memory.crypto import EncryptedMemoryPayload, envelope_encryption

router = APIRouter(prefix="/v1/memory", tags=["Personal AI Memory Vault"])


def get_owner_id(
    x_user_id: Optional[str] = Header(None, alias="X-User-ID"),
    current_app: Application = Depends(get_current_app),
) -> str:
    """Derives owner ID from header or falls back to tenant application default."""
    if x_user_id and x_user_id.strip():
        return x_user_id.strip()
    return f"user_{current_app.id[:8]}"


# --- Pydantic Schemas ---

class ProposalCreateRequest(BaseModel):
    proposed_key: str = Field(..., min_length=1, max_length=128)
    proposed_value: str = Field(..., min_length=1, max_length=10000)
    category: str = Field(default="USER_PREFERENCES")
    agent_id: str = Field(...)
    task_id: str = Field(...)
    ttl_seconds: Optional[int] = Field(default=86400, ge=60, le=2592000)


class ProposalResponse(BaseModel):
    id: str
    app_id: str
    owner_id: str
    agent_id: Optional[str]
    task_id: Optional[str]
    proposed_key: str
    proposed_value: str
    category: str
    status: str
    threat_assessment: Dict[str, Any]
    risk_level: str
    created_at: datetime
    expires_at: Optional[datetime]


class ProposalApproveRequest(BaseModel):
    retention_days: Optional[int] = Field(None, ge=1, le=3650)


class ProposalRejectRequest(BaseModel):
    reason: Optional[str] = Field("User rejected")


class MemoryCreateRequest(BaseModel):
    key: str = Field(..., min_length=1, max_length=128)
    value: str = Field(..., min_length=1, max_length=10000)
    category: str = Field(default="USER_PREFERENCES")
    retention_days: Optional[int] = Field(None, ge=1, le=3650)


class MemoryUpdateRequest(BaseModel):
    new_value: str = Field(..., min_length=1, max_length=10000)
    expected_version: Optional[int] = Field(None, ge=1)


class MemoryRecordResponse(BaseModel):
    id: str
    category: str
    status: str
    provenance: str
    summary: Optional[str]
    version: int
    created_at: datetime
    updated_at: datetime
    expires_at: Optional[datetime]
    retention_days: Optional[int]
    content_fingerprint: str


class MemoryDetailResponse(MemoryRecordResponse):
    owner_id: str
    value: str


class MemoryRetrieveRequest(BaseModel):
    agent_id: Optional[str] = None
    task_id: Optional[str] = None
    capability_token: Optional[str] = None
    query: Optional[str] = None
    categories: Optional[List[str]] = None
    limit: int = Field(default=5, ge=1, le=50)


class MemoryRetrieveResultItem(BaseModel):
    id: str
    category: str
    provenance: str
    summary: Optional[str]
    content: str
    version: int


class MemoryRetrieveResponse(BaseModel):
    memories: List[MemoryRetrieveResultItem]
    retrieved_count: int
    query: Optional[str] = None


class MemoryPermissionGrantRequest(BaseModel):
    agent_id: str
    operation: str = Field(..., description="memory.read, memory.propose_write, memory.update, memory.delete")
    category: Optional[str] = None
    memory_id: Optional[str] = None
    ttl_seconds: Optional[int] = Field(None, ge=60, le=31536000)


class MemoryPermissionResponse(BaseModel):
    id: str
    agent_id: str
    operation: str
    category: Optional[str]
    memory_id: Optional[str]
    is_granted: bool
    created_at: datetime
    expires_at: Optional[datetime]


class MemoryAuditEventResponse(BaseModel):
    id: str
    memory_id: Optional[str]
    agent_id: Optional[str]
    operation: str
    action_taken: str
    status: str
    timestamp: datetime


class MemoryRetentionSummaryResponse(BaseModel):
    active_count: int
    expired_count: int
    revoked_count: int
    quarantined_count: int
    pending_proposals: int
    categories_breakdown: Dict[str, int]


class KeyRotationResponse(BaseModel):
    owner_id: str
    new_key_version: int
    records_rotated: int
    rotated_at: datetime


class VaultPurgeResponse(BaseModel):
    job_id: str
    status: str
    items_deleted: int
    completed_at: Optional[datetime]


# --- Endpoints ---

# 1. Proposals API
@router.post("/proposals", response_model=ProposalResponse, status_code=status.HTTP_201_CREATED)
async def create_memory_proposal(
    payload: ProposalCreateRequest,
    current_app: Application = Depends(get_current_app),
    owner_id: str = Depends(get_owner_id),
    db: AsyncSession = Depends(get_db_session),
) -> ProposalResponse:
    """Agent submits a candidate memory proposal awaiting human consent."""
    proposal = await memory_vault.propose_memory(
        db=db,
        app_id=current_app.id,
        owner_id=owner_id,
        agent_id=payload.agent_id,
        task_id=payload.task_id,
        key=payload.proposed_key,
        value=payload.proposed_value,
        category=payload.category,
        ttl_seconds=payload.ttl_seconds or 86400,
    )
    return ProposalResponse(
        id=proposal.id,
        app_id=proposal.app_id,
        owner_id=proposal.owner_id,
        agent_id=proposal.agent_id,
        task_id=proposal.task_id,
        proposed_key=proposal.proposed_key,
        proposed_value=proposal.proposed_value,
        category=proposal.category,
        status=proposal.status,
        threat_assessment=json.loads(proposal.threat_assessment or "{}"),
        risk_level=proposal.risk_level,
        created_at=proposal.created_at,
        expires_at=proposal.expires_at,
    )


@router.get("/proposals", response_model=List[ProposalResponse])
async def list_proposals(
    status_filter: Optional[str] = Query("PROPOSED", alias="status"),
    current_app: Application = Depends(get_current_app),
    owner_id: str = Depends(get_owner_id),
    db: AsyncSession = Depends(get_db_session),
) -> List[ProposalResponse]:
    """Lists candidate memory proposals for user review and consent."""
    stmt = select(MemoryProposal).where(
        MemoryProposal.app_id == current_app.id,
        MemoryProposal.owner_id == owner_id,
    )
    if status_filter:
        stmt = stmt.where(MemoryProposal.status == status_filter)
    stmt = stmt.order_by(MemoryProposal.created_at.desc())
    res = await db.execute(stmt)
    proposals = res.scalars().all()

    return [
        ProposalResponse(
            id=p.id,
            app_id=p.app_id,
            owner_id=p.owner_id,
            agent_id=p.agent_id,
            task_id=p.task_id,
            proposed_key=p.proposed_key,
            proposed_value=p.proposed_value,
            category=p.category,
            status=p.status,
            threat_assessment=json.loads(p.threat_assessment or "{}"),
            risk_level=p.risk_level,
            created_at=p.created_at,
            expires_at=p.expires_at,
        )
        for p in proposals
    ]


@router.post("/proposals/{proposal_id}/approve", response_model=MemoryRecordResponse)
async def approve_proposal(
    proposal_id: str,
    payload: Optional[ProposalApproveRequest] = None,
    current_app: Application = Depends(get_current_app),
    owner_id: str = Depends(get_owner_id),
    db: AsyncSession = Depends(get_db_session),
) -> MemoryRecordResponse:
    """User approves a proposed memory, encrypting it into the active vault."""
    retention_days = payload.retention_days if payload else None
    record = await memory_vault.approve_proposal(
        db=db,
        app_id=current_app.id,
        owner_id=owner_id,
        proposal_id=proposal_id,
        retention_days=retention_days,
    )
    return MemoryRecordResponse(
        id=record.id,
        category=record.category,
        status=record.status,
        provenance=record.provenance,
        summary=record.summary,
        version=record.version,
        created_at=record.created_at,
        updated_at=record.updated_at,
        expires_at=record.expires_at,
        retention_days=record.retention_days,
        content_fingerprint=record.content_fingerprint,
    )


@router.post("/proposals/{proposal_id}/reject", response_model=ProposalResponse)
async def reject_proposal(
    proposal_id: str,
    payload: Optional[ProposalRejectRequest] = None,
    current_app: Application = Depends(get_current_app),
    owner_id: str = Depends(get_owner_id),
    db: AsyncSession = Depends(get_db_session),
) -> ProposalResponse:
    """User rejects a proposed memory, preventing storage."""
    reason = payload.reason if payload else "User rejected"
    proposal = await memory_vault.reject_proposal(
        db=db,
        app_id=current_app.id,
        owner_id=owner_id,
        proposal_id=proposal_id,
        reason=reason,
    )
    return ProposalResponse(
        id=proposal.id,
        app_id=proposal.app_id,
        owner_id=proposal.owner_id,
        agent_id=proposal.agent_id,
        task_id=proposal.task_id,
        proposed_key=proposal.proposed_key,
        proposed_value=proposal.proposed_value,
        category=proposal.category,
        status=proposal.status,
        threat_assessment=json.loads(proposal.threat_assessment or "{}"),
        risk_level=proposal.risk_level,
        created_at=proposal.created_at,
        expires_at=proposal.expires_at,
    )


# 2. Vault CRUD & Lifecycle API
@router.post("", response_model=MemoryRecordResponse, status_code=status.HTTP_201_CREATED)
async def create_memory(
    payload: MemoryCreateRequest,
    current_app: Application = Depends(get_current_app),
    owner_id: str = Depends(get_owner_id),
    db: AsyncSession = Depends(get_db_session),
) -> MemoryRecordResponse:
    """Directly creates and encrypts a verified memory entry for the owner."""
    record = await memory_vault.create_memory(
        db=db,
        app_id=current_app.id,
        owner_id=owner_id,
        key=payload.key,
        value=payload.value,
        category=payload.category,
        agent_id=None,
        provenance="USER_CONFIRMED",
        retention_days=payload.retention_days,
    )
    return MemoryRecordResponse(
        id=record.id,
        category=record.category,
        status=record.status,
        provenance=record.provenance,
        summary=record.summary,
        version=record.version,
        created_at=record.created_at,
        updated_at=record.updated_at,
        expires_at=record.expires_at,
        retention_days=record.retention_days,
        content_fingerprint=record.content_fingerprint,
    )


@router.get("", response_model=List[MemoryRecordResponse])
async def list_memories(
    category: Optional[str] = Query(None),
    status_filter: Optional[str] = Query("ACTIVE", alias="status"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    current_app: Application = Depends(get_current_app),
    owner_id: str = Depends(get_owner_id),
    db: AsyncSession = Depends(get_db_session),
) -> List[MemoryRecordResponse]:
    """Lists memory records in vault (metadata only, zero plaintext)."""
    stmt = select(MemoryRecord).where(
        MemoryRecord.app_id == current_app.id,
        MemoryRecord.owner_id == owner_id,
    )
    if status_filter:
        stmt = stmt.where(MemoryRecord.status == status_filter)
    if category:
        stmt = stmt.where(MemoryRecord.category == category)
    stmt = stmt.order_by(MemoryRecord.created_at.desc()).offset(offset).limit(limit)

    res = await db.execute(stmt)
    records = res.scalars().all()

    return [
        MemoryRecordResponse(
            id=r.id,
            category=r.category,
            status=r.status,
            provenance=r.provenance,
            summary=r.summary,
            version=r.version,
            created_at=r.created_at,
            updated_at=r.updated_at,
            expires_at=r.expires_at,
            retention_days=r.retention_days,
            content_fingerprint=r.content_fingerprint,
        )
        for r in records
    ]


# 3. Privacy-Preserving Bounded Retrieval API
@router.post("/retrieve", response_model=MemoryRetrieveResponse)
async def retrieve_memories(
    payload: MemoryRetrieveRequest,
    current_app: Application = Depends(get_current_app),
    owner_id: str = Depends(get_owner_id),
    db: AsyncSession = Depends(get_db_session),
) -> MemoryRetrieveResponse:
    """
    Executes bounded, authorized retrieval of personal memory context.
    Supports both agent-scoped capability tokens and direct authorized owner search.
    """
    if payload.capability_token and payload.agent_id and payload.task_id:
        # Agent retrieval through Stage 3 capability manager & retrieval service
        results = await memory_retrieval_service.retrieve_context(
            db=db,
            app_id=current_app.id,
            owner_id=owner_id,
            agent_id=payload.agent_id,
            task_id=payload.task_id,
            capability_token=payload.capability_token,
            query=payload.query,
            categories=payload.categories,
            limit=payload.limit,
        )
        return MemoryRetrieveResponse(
            memories=[
                MemoryRetrieveResultItem(
                    id=item["id"],
                    category=item["category"],
                    provenance=item["provenance"],
                    summary=item.get("summary"),
                    content=item["content"],
                    version=item["version"],
                )
                for item in results
            ],
            retrieved_count=len(results),
            query=payload.query,
        )

    # Direct User / Dashboard retrieval
    stmt = select(MemoryRecord).where(
        MemoryRecord.app_id == current_app.id,
        MemoryRecord.owner_id == owner_id,
        MemoryRecord.status == "ACTIVE",
    )
    if payload.categories:
        stmt = stmt.where(MemoryRecord.category.in_(payload.categories))

    res = await db.execute(stmt)
    records = res.scalars().all()

    now = datetime.now(timezone.utc)
    results = []
    for r in records:
        if r.expires_at and ensure_utc(r.expires_at) < now:
            continue

        # Decrypt memory
        payload_enc = EncryptedMemoryPayload(
            ciphertext_b64=r.encrypted_content,
            nonce_b64=r.nonce,
            wrapped_dek_b64=r.wrapped_dek,
            dek_nonce_b64=r.dek_nonce,
            key_version=r.key_version,
            content_fingerprint=r.content_fingerprint,
        )
        try:
            val = envelope_encryption.decrypt(
                payload=payload_enc,
                owner_id=owner_id,
                memory_id=r.id,
                category=r.category,
            )
        except Exception:
            continue

        if payload.query:
            q = payload.query.lower()
            if q not in val.lower() and (not r.summary or q not in r.summary.lower()):
                continue

        results.append(
            MemoryRetrieveResultItem(
                id=r.id,
                category=r.category,
                provenance=r.provenance,
                summary=r.summary,
                content=val,
                version=r.version,
            )
        )
        if len(results) >= payload.limit:
            break

    return MemoryRetrieveResponse(
        memories=results,
        retrieved_count=len(results),
        query=payload.query,
    )


# 4. Agent Memory Permissions Management API
@router.post("/permissions", response_model=MemoryPermissionResponse, status_code=status.HTTP_201_CREATED)
async def grant_memory_permission(
    payload: MemoryPermissionGrantRequest,
    current_app: Application = Depends(get_current_app),
    owner_id: str = Depends(get_owner_id),
    db: AsyncSession = Depends(get_db_session),
) -> MemoryPermissionResponse:
    """Grants granular memory operation permissions to an AI agent."""
    perm = await memory_permission_engine.grant_permission(
        db=db,
        app_id=current_app.id,
        owner_id=owner_id,
        agent_id=payload.agent_id,
        operation=payload.operation,
        category=payload.category,
        memory_id=payload.memory_id,
        ttl_seconds=payload.ttl_seconds,
    )
    return MemoryPermissionResponse(
        id=perm.id,
        agent_id=perm.agent_id,
        operation=perm.operation,
        category=perm.category,
        memory_id=perm.memory_id,
        is_granted=perm.is_granted,
        created_at=perm.created_at,
        expires_at=perm.expires_at,
    )


@router.get("/permissions", response_model=List[MemoryPermissionResponse])
async def list_memory_permissions(
    agent_id: Optional[str] = Query(None),
    current_app: Application = Depends(get_current_app),
    owner_id: str = Depends(get_owner_id),
    db: AsyncSession = Depends(get_db_session),
) -> List[MemoryPermissionResponse]:
    """Lists active granular memory permissions granted to agents."""
    stmt = select(MemoryPermission).where(
        MemoryPermission.app_id == current_app.id,
        MemoryPermission.owner_id == owner_id,
        MemoryPermission.is_granted.is_(True),
    )
    if agent_id:
        stmt = stmt.where(MemoryPermission.agent_id == agent_id)
    res = await db.execute(stmt)
    perms = res.scalars().all()

    return [
        MemoryPermissionResponse(
            id=p.id,
            agent_id=p.agent_id,
            operation=p.operation,
            category=p.category,
            memory_id=p.memory_id,
            is_granted=p.is_granted,
            created_at=p.created_at,
            expires_at=p.expires_at,
        )
        for p in perms
    ]


@router.delete("/permissions/{permission_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_memory_permission(
    permission_id: str,
    current_app: Application = Depends(get_current_app),
    owner_id: str = Depends(get_owner_id),
    db: AsyncSession = Depends(get_db_session),
) -> None:
    """Revokes an agent memory permission."""
    stmt = select(MemoryPermission).where(
        MemoryPermission.id == permission_id,
        MemoryPermission.app_id == current_app.id,
        MemoryPermission.owner_id == owner_id,
    )
    res = await db.execute(stmt)
    perm = res.scalar_one_or_none()
    if not perm:
        raise MemoryNotFoundError(permission_id)

    perm.is_granted = False
    await db.commit()


# 5. Cryptographic Key Rotation & Vault Purge API
@router.post("/key/rotate", response_model=KeyRotationResponse)
async def rotate_user_kek(
    current_app: Application = Depends(get_current_app),
    owner_id: str = Depends(get_owner_id),
    db: AsyncSession = Depends(get_db_session),
) -> KeyRotationResponse:
    """Rotates user Key Encryption Key (KEK) and re-wraps active DEKs."""
    new_version, count = await memory_vault.rotate_user_key(
        db=db,
        app_id=current_app.id,
        owner_id=owner_id,
    )
    return KeyRotationResponse(
        owner_id=owner_id,
        new_key_version=new_version,
        records_rotated=count,
        rotated_at=datetime.now(timezone.utc),
    )


@router.post("/purge", response_model=VaultPurgeResponse)
async def purge_vault(
    current_app: Application = Depends(get_current_app),
    owner_id: str = Depends(get_owner_id),
    db: AsyncSession = Depends(get_db_session),
) -> VaultPurgeResponse:
    """Executes a permanent cryptographic purge of all user personal memories."""
    job = await memory_vault.purge_vault(
        db=db,
        app_id=current_app.id,
        owner_id=owner_id,
    )
    return VaultPurgeResponse(
        job_id=job.id,
        status=job.status,
        items_deleted=job.items_deleted,
        completed_at=job.completed_at,
    )


# 6. Retention, Stats & Auditing API
@router.get("/retention", response_model=MemoryRetentionSummaryResponse)
async def get_retention_summary(
    current_app: Application = Depends(get_current_app),
    owner_id: str = Depends(get_owner_id),
    db: AsyncSession = Depends(get_db_session),
) -> MemoryRetentionSummaryResponse:
    """Provides memory vault metrics, retention status, and category breakdown."""
    stmt_mem = select(MemoryRecord.status, MemoryRecord.category, func.count(MemoryRecord.id)).where(
        MemoryRecord.app_id == current_app.id,
        MemoryRecord.owner_id == owner_id,
    ).group_by(MemoryRecord.status, MemoryRecord.category)

    res_mem = await db.execute(stmt_mem)
    rows = res_mem.all()

    active_count = 0
    expired_count = 0
    revoked_count = 0
    quarantined_count = 0
    cats: Dict[str, int] = {}

    for status_val, cat_val, cnt in rows:
        if status_val == "ACTIVE":
            active_count += cnt
            cats[cat_val] = cats.get(cat_val, 0) + cnt
        elif status_val == "EXPIRED":
            expired_count += cnt
        elif status_val == "REVOKED":
            revoked_count += cnt
        elif status_val == "QUARANTINED":
            quarantined_count += cnt

    # Proposals count
    stmt_prop = select(func.count(MemoryProposal.id)).where(
        MemoryProposal.app_id == current_app.id,
        MemoryProposal.owner_id == owner_id,
        MemoryProposal.status == "PROPOSED",
    )
    res_prop = await db.execute(stmt_prop)
    pending_proposals = res_prop.scalar() or 0

    return MemoryRetentionSummaryResponse(
        active_count=active_count,
        expired_count=expired_count,
        revoked_count=revoked_count,
        quarantined_count=quarantined_count,
        pending_proposals=pending_proposals,
        categories_breakdown=cats,
    )


@router.get("/audit", response_model=List[MemoryAuditEventResponse])
async def list_memory_audit_events(
    limit: int = Query(50, ge=1, le=100),
    current_app: Application = Depends(get_current_app),
    owner_id: str = Depends(get_owner_id),
    db: AsyncSession = Depends(get_db_session),
) -> List[MemoryAuditEventResponse]:
    """Returns content-free memory vault audit trail."""
    stmt = select(MemoryAuditEvent).where(
        MemoryAuditEvent.app_id == current_app.id,
        MemoryAuditEvent.owner_id == owner_id,
    ).order_by(MemoryAuditEvent.timestamp.desc()).limit(limit)

    res = await db.execute(stmt)
    events = res.scalars().all()

    return [
        MemoryAuditEventResponse(
            id=e.id,
            memory_id=e.memory_id,
            agent_id=e.agent_id,
            operation=e.operation,
            action_taken=e.action_taken,
            status=e.status,
            timestamp=e.timestamp,
        )
        for e in events
    ]


# --- Specific Item Parameterized Operations (Placed at bottom to avoid shadowing literal routes) ---

@router.get("/{memory_id}", response_model=MemoryDetailResponse)
async def get_memory(
    memory_id: str,
    current_app: Application = Depends(get_current_app),
    owner_id: str = Depends(get_owner_id),
    db: AsyncSession = Depends(get_db_session),
) -> MemoryDetailResponse:
    """Retrieves and decrypts a specific personal memory entry."""
    data = await memory_vault.get_memory(
        db=db,
        app_id=current_app.id,
        owner_id=owner_id,
        memory_id=memory_id,
        agent_id=None,
    )
    stmt = select(MemoryRecord).where(MemoryRecord.id == memory_id)
    res = await db.execute(stmt)
    record = res.scalar_one()

    return MemoryDetailResponse(
        id=record.id,
        owner_id=record.owner_id,
        category=record.category,
        status=record.status,
        provenance=record.provenance,
        summary=record.summary,
        value=data["value"],
        version=record.version,
        created_at=record.created_at,
        updated_at=record.updated_at,
        expires_at=record.expires_at,
        retention_days=record.retention_days,
        content_fingerprint=record.content_fingerprint,
    )


@router.patch("/{memory_id}", response_model=MemoryRecordResponse)
async def update_memory(
    memory_id: str,
    payload: MemoryUpdateRequest,
    current_app: Application = Depends(get_current_app),
    owner_id: str = Depends(get_owner_id),
    db: AsyncSession = Depends(get_db_session),
) -> MemoryRecordResponse:
    """Updates memory value with optimistic concurrency CAS and version archival."""
    record = await memory_vault.update_memory(
        db=db,
        app_id=current_app.id,
        owner_id=owner_id,
        memory_id=memory_id,
        new_value=payload.new_value,
        agent_id=None,
        expected_version=payload.expected_version,
    )
    return MemoryRecordResponse(
        id=record.id,
        category=record.category,
        status=record.status,
        provenance=record.provenance,
        summary=record.summary,
        version=record.version,
        created_at=record.created_at,
        updated_at=record.updated_at,
        expires_at=record.expires_at,
        retention_days=record.retention_days,
        content_fingerprint=record.content_fingerprint,
    )


@router.delete("/{memory_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_memory(
    memory_id: str,
    current_app: Application = Depends(get_current_app),
    owner_id: str = Depends(get_owner_id),
    db: AsyncSession = Depends(get_db_session),
) -> None:
    """Cryptographically erases memory (destroys DEK and ciphertext)."""
    await memory_vault.delete_memory(
        db=db,
        app_id=current_app.id,
        owner_id=owner_id,
        memory_id=memory_id,
        agent_id=None,
    )


@router.post("/{memory_id}/revoke", status_code=status.HTTP_200_OK)
async def revoke_memory(
    memory_id: str,
    current_app: Application = Depends(get_current_app),
    owner_id: str = Depends(get_owner_id),
    db: AsyncSession = Depends(get_db_session),
) -> Dict[str, Any]:
    """Revokes a memory, immediately hiding it from retrieval without data wipe."""
    await memory_vault.revoke_memory(
        db=db,
        app_id=current_app.id,
        owner_id=owner_id,
        memory_id=memory_id,
    )
    return {"status": "REVOKED", "memory_id": memory_id}

