"""Secure Personal AI Memory Vault Manager.
Implements the complete user-controlled memory lifecycle with envelope encryption.
"""

import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy import select, update, and_, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import (
    MemoryNotFoundError,
    MemoryPermissionError,
    MemoryPoisoningError,
    MemoryTamperingError,
    PrivGuardException,
)
from app.database.models import (
    MemoryAuditEvent,
    MemoryDeletionJob,
    MemoryPermission,
    MemoryProposal,
    MemoryRecord,
    MemoryVersion,
    ensure_utc,
    utcnow,
)
from app.memory.crypto import EncryptedMemoryPayload, envelope_encryption
from app.memory.key_provider import default_key_provider
from app.memory.permissions import memory_permission_engine
from app.memory.validator import memory_validator


class MemoryVault:
    """Manages secure, encrypted personal AI memory storage, proposals, and lifecycle."""

    def __init__(self):
        self.crypto = envelope_encryption
        self.key_provider = default_key_provider
        self.validator = memory_validator
        self.permissions = memory_permission_engine

    async def log_audit(
        self,
        db: AsyncSession,
        app_id: str,
        owner_id: str,
        operation: str,
        action_taken: str = "ALLOW",
        status: str = "SUCCESS",
        memory_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        category: Optional[str] = None,
        content_fingerprint: Optional[str] = None,
    ) -> None:
        """Records a content-free audit event for memory vault interactions."""
        event = MemoryAuditEvent(
            app_id=app_id,
            owner_id=owner_id,
            agent_id=agent_id,
            memory_id=memory_id,
            operation=operation,
            category=category,
            action_taken=action_taken,
            status=status,
            content_fingerprint=content_fingerprint,
            timestamp=utcnow(),
        )
        db.add(event)
        await db.commit()

    async def propose_memory(
        self,
        db: AsyncSession,
        app_id: str,
        owner_id: str,
        agent_id: str,
        task_id: str,
        key: str,
        value: str,
        category: str = "USER_PREFERENCES",
        ttl_seconds: int = 86400,
    ) -> MemoryProposal:
        """
        Creates a staged memory proposal from an AI agent awaiting user consent.
        Evaluates memory poisoning and instruction smuggling before staging.
        """
        # 1. Permission check: Does agent have propose_write permission?
        await self.permissions.check_permission(
            db=db,
            app_id=app_id,
            owner_id=owner_id,
            agent_id=agent_id,
            operation="memory.propose_write",
            category=category,
        )

        # 2. Poisoning & Security Inspection
        cat = self.validator.validate_category(category)
        _, assessment = self.validator.inspect_content(
            key=key,
            value=value,
            category=cat,
            provenance="AI_PROPOSED",
        )

        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)

        proposal = MemoryProposal(
            app_id=app_id,
            owner_id=owner_id,
            agent_id=agent_id,
            task_id=task_id,
            proposed_key=key.strip(),
            proposed_value=value.strip(),
            category=cat,
            status="PROPOSED",
            threat_assessment=json.dumps(
                {
                    "is_threat": assessment.is_threat,
                    "action": assessment.action.value,
                    "reason": assessment.reason,
                }
            ),
            risk_level=assessment.max_severity.value,
            expires_at=expires_at,
            created_at=utcnow(),
        )
        db.add(proposal)
        await db.commit()
        await db.refresh(proposal)

        await self.log_audit(
            db=db,
            app_id=app_id,
            owner_id=owner_id,
            agent_id=agent_id,
            operation="PROPOSE",
            category=cat,
            content_fingerprint=self.crypto.compute_fingerprint(value),
        )

        return proposal

    async def approve_proposal(
        self,
        db: AsyncSession,
        app_id: str,
        owner_id: str,
        proposal_id: str,
        retention_days: Optional[int] = None,
    ) -> MemoryRecord:
        """
        User grants consent to store an AI-proposed memory.
        Encrypts content with AES-256-GCM envelope encryption and marks ACTIVE.
        """
        stmt = select(MemoryProposal).where(
            MemoryProposal.id == proposal_id,
            MemoryProposal.app_id == app_id,
            MemoryProposal.owner_id == owner_id,
        )
        res = await db.execute(stmt)
        proposal = res.scalar_one_or_none()
        if not proposal:
            raise MemoryNotFoundError(proposal_id)

        if proposal.status != "PROPOSED":
            raise PrivGuardException(
                f"Cannot approve proposal in status '{proposal.status}'",
                status_code=400,
                error_code="PROPOSAL_INVALID_STATE",
            )

        now = datetime.now(timezone.utc)
        if ensure_utc(proposal.expires_at) < now:
            proposal.status = "EXPIRED"
            await db.commit()
            raise PrivGuardException(
                "Memory proposal has expired.",
                status_code=400,
                error_code="PROPOSAL_EXPIRED",
            )

        # Mark proposal approved
        proposal.status = "APPROVED"
        proposal.resolved_at = now
        await db.commit()

        # Create active encrypted memory record
        memory = await self.create_memory(
            db=db,
            app_id=app_id,
            owner_id=owner_id,
            key=proposal.proposed_key,
            value=proposal.proposed_value,
            category=proposal.category,
            agent_id=proposal.agent_id,
            provenance="AI_PROPOSED",
            retention_days=retention_days,
        )

        await self.log_audit(
            db=db,
            app_id=app_id,
            owner_id=owner_id,
            agent_id=proposal.agent_id,
            memory_id=memory.id,
            operation="APPROVE",
            category=proposal.category,
        )

        return memory

    async def reject_proposal(
        self,
        db: AsyncSession,
        app_id: str,
        owner_id: str,
        proposal_id: str,
        reason: str = "User rejected",
    ) -> MemoryProposal:
        """Rejects a memory proposal, preventing storage or access."""
        stmt = select(MemoryProposal).where(
            MemoryProposal.id == proposal_id,
            MemoryProposal.app_id == app_id,
            MemoryProposal.owner_id == owner_id,
        )
        res = await db.execute(stmt)
        proposal = res.scalar_one_or_none()
        if not proposal:
            raise MemoryNotFoundError(proposal_id)

        proposal.status = "REJECTED"
        proposal.resolved_at = datetime.now(timezone.utc)
        await db.commit()

        await self.log_audit(
            db=db,
            app_id=app_id,
            owner_id=owner_id,
            agent_id=proposal.agent_id,
            operation="REJECT",
            action_taken="BLOCK",
        )
        return proposal

    async def create_memory(
        self,
        db: AsyncSession,
        app_id: str,
        owner_id: str,
        key: str,
        value: str,
        category: str = "USER_PREFERENCES",
        agent_id: Optional[str] = None,
        provenance: str = "USER_CONFIRMED",
        retention_days: Optional[int] = None,
    ) -> MemoryRecord:
        """
        Directly creates an active encrypted memory record with verified provenance.
        """
        cat = self.validator.validate_category(category)
        self.validator.inspect_content(key=key, value=value, category=cat, provenance=provenance)

        memory_id = f"mem_{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(days=retention_days) if retention_days else None

        # Envelope Encryption: Plaintext never touches database!
        payload = self.crypto.encrypt(
            plaintext=value,
            owner_id=owner_id,
            memory_id=memory_id,
            category=cat,
            key_version=1,
        )

        record = MemoryRecord(
            id=memory_id,
            app_id=app_id,
            owner_id=owner_id,
            agent_id=agent_id,
            category=cat,
            status="ACTIVE",
            provenance=provenance,
            encrypted_content=payload.ciphertext_b64,
            nonce=payload.nonce_b64,
            wrapped_dek=payload.wrapped_dek_b64,
            dek_nonce=payload.dek_nonce_b64,
            key_version=payload.key_version,
            content_fingerprint=payload.content_fingerprint,
            summary=f"{key[:80]}",
            version=1,
            expires_at=expires_at,
            retention_days=retention_days,
            created_at=now,
            updated_at=now,
        )
        db.add(record)
        await db.commit()
        await db.refresh(record)

        await self.log_audit(
            db=db,
            app_id=app_id,
            owner_id=owner_id,
            agent_id=agent_id,
            memory_id=memory_id,
            operation="CREATE",
            category=cat,
            content_fingerprint=payload.content_fingerprint,
        )
        return record

    async def get_memory(
        self,
        db: AsyncSession,
        app_id: str,
        owner_id: str,
        memory_id: str,
        agent_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Retrieves and decrypts a specific memory record.
        Validates ownership, permission, status, expiration, and cryptographic tag.
        """
        # 1. Fetch memory record with strict application & owner filtering
        stmt = select(MemoryRecord).where(
            MemoryRecord.id == memory_id,
            MemoryRecord.app_id == app_id,
            MemoryRecord.owner_id == owner_id,
        )
        res = await db.execute(stmt)
        record = res.scalar_one_or_none()
        if not record:
            raise MemoryNotFoundError(memory_id)

        # 2. Check active lifecycle status
        if record.status in ("DELETED", "REVOKED", "QUARANTINED"):
            raise MemoryNotFoundError(memory_id)

        now = datetime.now(timezone.utc)
        if record.expires_at and ensure_utc(record.expires_at) < now:
            record.status = "EXPIRED"
            await db.commit()
            raise MemoryNotFoundError(memory_id)

        # 3. Check permission for requesting agent
        await self.permissions.check_permission(
            db=db,
            app_id=app_id,
            owner_id=owner_id,
            agent_id=agent_id,
            operation="memory.read",
            memory_id=memory_id,
            category=record.category,
        )

        # 4. Decrypt in memory using AES-256-GCM envelope
        payload = EncryptedMemoryPayload(
            ciphertext_b64=record.encrypted_content,
            nonce_b64=record.nonce,
            wrapped_dek_b64=record.wrapped_dek,
            dek_nonce_b64=record.dek_nonce,
            key_version=record.key_version,
            content_fingerprint=record.content_fingerprint,
        )

        decrypted_value = self.crypto.decrypt(
            payload=payload,
            owner_id=owner_id,
            memory_id=memory_id,
            category=record.category,
        )

        # Audit retrieval without content exposure
        await self.log_audit(
            db=db,
            app_id=app_id,
            owner_id=owner_id,
            agent_id=agent_id,
            memory_id=memory_id,
            operation="RETRIEVE",
            category=record.category,
        )

        return {
            "id": record.id,
            "owner_id": record.owner_id,
            "category": record.category,
            "status": record.status,
            "provenance": record.provenance,
            "summary": record.summary,
            "value": decrypted_value,
            "version": record.version,
            "created_at": record.created_at.isoformat(),
            "updated_at": record.updated_at.isoformat(),
            "expires_at": record.expires_at.isoformat() if record.expires_at else None,
        }

    async def update_memory(
        self,
        db: AsyncSession,
        app_id: str,
        owner_id: str,
        memory_id: str,
        new_value: str,
        agent_id: Optional[str] = None,
        expected_version: Optional[int] = None,
    ) -> MemoryRecord:
        """
        Updates memory content with optimistic concurrency control (CAS) and archive versioning.
        """
        stmt = select(MemoryRecord).where(
            MemoryRecord.id == memory_id,
            MemoryRecord.app_id == app_id,
            MemoryRecord.owner_id == owner_id,
        )
        res = await db.execute(stmt)
        record = res.scalar_one_or_none()
        if not record or record.status != "ACTIVE":
            raise MemoryNotFoundError(memory_id)

        # Permission check
        await self.permissions.check_permission(
            db=db,
            app_id=app_id,
            owner_id=owner_id,
            agent_id=agent_id,
            operation="memory.update",
            memory_id=memory_id,
            category=record.category,
        )

        # Optimistic concurrency check
        if expected_version is not None and record.version != expected_version:
            raise PrivGuardException(
                f"Concurrent modification conflict: current version is {record.version}, expected {expected_version}",
                status_code=409,
                error_code="MEMORY_VERSION_CONFLICT",
            )

        # Content validation
        self.validator.inspect_content(
            key=record.summary or "memory",
            value=new_value,
            category=record.category,
            provenance="USER_CONFIRMED" if not agent_id else "AI_PROPOSED",
        )

        # 1. Archive current encrypted version into MemoryVersion table
        version_archive = MemoryVersion(
            memory_id=record.id,
            version_num=record.version,
            encrypted_content=record.encrypted_content,
            nonce=record.nonce,
            wrapped_dek=record.wrapped_dek,
            dek_nonce=record.dek_nonce,
            key_version=record.key_version,
            content_fingerprint=record.content_fingerprint,
            created_at=utcnow(),
        )
        db.add(version_archive)

        # 2. Encrypt new value with fresh DEK
        new_payload = self.crypto.encrypt(
            plaintext=new_value,
            owner_id=owner_id,
            memory_id=memory_id,
            category=record.category,
            key_version=record.key_version,
        )

        # 3. Atomic CAS update on record
        new_version_num = record.version + 1
        now = datetime.now(timezone.utc)
        stmt_cas = (
            update(MemoryRecord)
            .where(
                MemoryRecord.id == memory_id,
                MemoryRecord.version == record.version,
            )
            .values(
                encrypted_content=new_payload.ciphertext_b64,
                nonce=new_payload.nonce_b64,
                wrapped_dek=new_payload.wrapped_dek_b64,
                dek_nonce=new_payload.dek_nonce_b64,
                content_fingerprint=new_payload.content_fingerprint,
                version=new_version_num,
                updated_at=now,
            )
        )
        cas_res = await db.execute(stmt_cas)
        await db.commit()

        if cas_res.rowcount == 0:
            raise PrivGuardException(
                "Concurrent update race condition: failed to atomically increment memory version.",
                status_code=409,
                error_code="MEMORY_CONCURRENCY_CONFLICT",
            )

        await db.refresh(record)

        await self.log_audit(
            db=db,
            app_id=app_id,
            owner_id=owner_id,
            agent_id=agent_id,
            memory_id=memory_id,
            operation="UPDATE",
            category=record.category,
            content_fingerprint=new_payload.content_fingerprint,
        )
        return record

    async def delete_memory(
        self,
        db: AsyncSession,
        app_id: str,
        owner_id: str,
        memory_id: str,
        agent_id: Optional[str] = None,
    ) -> bool:
        """
        Cryptographic Erasure:
        Wipes ciphertext, wrapped DEK, and nonces, permanently destroying decryption ability.
        """
        stmt = select(MemoryRecord).where(
            MemoryRecord.id == memory_id,
            MemoryRecord.app_id == app_id,
            MemoryRecord.owner_id == owner_id,
        )
        res = await db.execute(stmt)
        record = res.scalar_one_or_none()
        if not record:
            raise MemoryNotFoundError(memory_id)

        # Permission check
        await self.permissions.check_permission(
            db=db,
            app_id=app_id,
            owner_id=owner_id,
            agent_id=agent_id,
            operation="memory.delete",
            memory_id=memory_id,
            category=record.category,
        )

        # Cryptographic wipe
        record.status = "DELETED"
        record.encrypted_content = "[CRYPTOGRAPHICALLY_ERASED]"
        record.wrapped_dek = "[DEK_DESTROYED]"
        record.nonce = "[WIPED]"
        record.dek_nonce = "[WIPED]"
        record.updated_at = datetime.now(timezone.utc)

        # Cryptographic wipe of all historical archived versions
        stmt_versions = select(MemoryVersion).where(MemoryVersion.memory_id == memory_id)
        versions_res = await db.execute(stmt_versions)
        for ver in versions_res.scalars().all():
            ver.encrypted_content = "[CRYPTOGRAPHICALLY_ERASED]"
            ver.wrapped_dek = "[DEK_DESTROYED]"
            ver.nonce = "[WIPED]"
            ver.dek_nonce = "[WIPED]"

        await db.commit()

        await self.log_audit(
            db=db,
            app_id=app_id,
            owner_id=owner_id,
            agent_id=agent_id,
            memory_id=memory_id,
            operation="DELETE",
        )
        return True

    async def revoke_memory(
        self,
        db: AsyncSession,
        app_id: str,
        owner_id: str,
        memory_id: str,
    ) -> bool:
        """Revokes memory record, instantly removing it from active queries without destroying record."""
        stmt = select(MemoryRecord).where(
            MemoryRecord.id == memory_id,
            MemoryRecord.app_id == app_id,
            MemoryRecord.owner_id == owner_id,
        )
        res = await db.execute(stmt)
        record = res.scalar_one_or_none()
        if not record:
            raise MemoryNotFoundError(memory_id)

        record.status = "REVOKED"
        record.updated_at = datetime.now(timezone.utc)
        await db.commit()

        await self.log_audit(
            db=db,
            app_id=app_id,
            owner_id=owner_id,
            memory_id=memory_id,
            operation="REVOKE",
        )
        return True

    async def purge_vault(
        self,
        db: AsyncSession,
        app_id: str,
        owner_id: str,
    ) -> MemoryDeletionJob:
        """
        Executes a complete cryptographic wipe of all memories for an authenticated user account.
        """
        stmt = select(MemoryRecord).where(
            MemoryRecord.app_id == app_id,
            MemoryRecord.owner_id == owner_id,
            MemoryRecord.status != "DELETED",
        )
        res = await db.execute(stmt)
        active_records = res.scalars().all()
        target_ids = [m.id for m in active_records]

        job = MemoryDeletionJob(
            app_id=app_id,
            owner_id=owner_id,
            target_ids=json.dumps(target_ids),
            deletion_type="PURGE",
            status="PROCESSING",
            items_deleted=0,
            created_at=utcnow(),
        )
        db.add(job)
        await db.commit()

        now = datetime.now(timezone.utc)
        for m in active_records:
            m.status = "DELETED"
            m.encrypted_content = "[CRYPTOGRAPHICALLY_ERASED]"
            m.wrapped_dek = "[DEK_DESTROYED]"
            m.nonce = "[WIPED]"
            m.dek_nonce = "[WIPED]"
            m.updated_at = now

        if target_ids:
            stmt_vers = select(MemoryVersion).where(MemoryVersion.memory_id.in_(target_ids))
            vers_res = await db.execute(stmt_vers)
            for ver in vers_res.scalars().all():
                ver.encrypted_content = "[CRYPTOGRAPHICALLY_ERASED]"
                ver.wrapped_dek = "[DEK_DESTROYED]"
                ver.nonce = "[WIPED]"
                ver.dek_nonce = "[WIPED]"

        job.status = "COMPLETED"
        job.items_deleted = len(target_ids)
        job.completed_at = now
        await db.commit()

        await self.log_audit(
            db=db,
            app_id=app_id,
            owner_id=owner_id,
            operation="PURGE",
        )
        return job

    async def rotate_user_key(
        self,
        db: AsyncSession,
        app_id: str,
        owner_id: str,
    ) -> Tuple[int, int]:
        """
        Rotates user KEK and re-wraps all active DEKs.
        Returns (new_key_version, count_of_records_rotated).
        """
        stmt = select(MemoryRecord).where(
            MemoryRecord.app_id == app_id,
            MemoryRecord.owner_id == owner_id,
            MemoryRecord.status == "ACTIVE",
        )
        res = await db.execute(stmt)
        records = res.scalars().all()

        new_version, _ = self.key_provider.rotate_user_kek(owner_id)
        rotated_count = 0

        for m in records:
            old_version = m.key_version
            new_wrapped, new_dek_nonce = self.crypto.rewrap_dek(
                wrapped_dek_b64=m.wrapped_dek,
                dek_nonce_b64=m.dek_nonce,
                owner_id=owner_id,
                memory_id=m.id,
                old_version=old_version,
                new_version=new_version,
            )
            m.wrapped_dek = new_wrapped
            m.dek_nonce = new_dek_nonce
            m.key_version = new_version
            m.updated_at = datetime.now(timezone.utc)
            rotated_count += 1

        await db.commit()

        await self.log_audit(
            db=db,
            app_id=app_id,
            owner_id=owner_id,
            operation="ROTATE_KEY",
        )
        return new_version, rotated_count


# Global singleton vault manager
memory_vault = MemoryVault()
