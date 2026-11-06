"""Privacy-preserving, bounded memory retrieval service."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.agent_security.capability_manager import capability_manager
from app.core.exceptions import (
    MemoryPermissionError,
    PrivGuardException,
)
from app.database.models import MemoryRecord, ensure_utc
from app.memory.crypto import EncryptedMemoryPayload, envelope_encryption
from app.memory.permissions import memory_permission_engine
from app.memory.vault import memory_vault
from app.threat_detection import injection_detector


class MemoryRetrievalService:
    """Coordinates capability validation, permission checks, in-memory decryption, and bounded context retrieval."""

    def __init__(self):
        self.caps = capability_manager
        self.permissions = memory_permission_engine
        self.crypto = envelope_encryption
        self.vault = memory_vault
        self.threats = injection_detector

    async def retrieve_context(
        self,
        db: AsyncSession,
        app_id: str,
        owner_id: str,
        agent_id: str,
        task_id: str,
        capability_token: str,
        query: Optional[str] = None,
        categories: Optional[List[str]] = None,
        limit: int = 5,
    ) -> List[Dict[str, Any]]:
        """
        Executes bounded, authorized retrieval of personal memory context for an active task.
        Guarantees that:
        1. Capability token is valid, active, unexpired, and bound to this task and agent.
        2. Agent possesses permission for the requested categories or memories.
        3. Only records belonging to the authenticated owner are queried.
        4. Expired, revoked, or quarantined memories are strictly excluded.
        5. Decrypted content undergoes output security verification before returning.
        """
        # 1. Enforce Stage 3 Capability Verification
        grant = await self.caps.validate_and_consume(
            db=db,
            raw_secret=capability_token,
            expected_tool="memory_read",
            expected_agent_id=agent_id,
            expected_task_id=task_id,
            expected_app_id=app_id,
            consume=True,
        )

        # 2. Query active records strictly scoped to app and owner
        now = datetime.now(timezone.utc)
        stmt = select(MemoryRecord).where(
            MemoryRecord.app_id == app_id,
            MemoryRecord.owner_id == owner_id,
            MemoryRecord.status == "ACTIVE",
        )
        if categories:
            clean_cats = [c.strip().upper() for c in categories]
            stmt = stmt.where(MemoryRecord.category.in_(clean_cats))

        res = await db.execute(stmt)
        candidates = res.scalars().all()

        retrieved_items: List[Dict[str, Any]] = []

        for record in candidates:
            # Check expiration
            if record.expires_at and ensure_utc(record.expires_at) < now:
                record.status = "EXPIRED"
                await db.commit()
                continue

            # Check granular permission for agent on this specific category/record
            try:
                await self.permissions.check_permission(
                    db=db,
                    app_id=app_id,
                    owner_id=owner_id,
                    agent_id=agent_id,
                    operation="memory.read",
                    memory_id=record.id,
                    category=record.category,
                )
            except MemoryPermissionError:
                # Agent is not permitted for this specific record; skip
                continue

            # Decrypt in memory
            payload = EncryptedMemoryPayload(
                ciphertext_b64=record.encrypted_content,
                nonce_b64=record.nonce,
                wrapped_dek_b64=record.wrapped_dek,
                dek_nonce_b64=record.dek_nonce,
                key_version=record.key_version,
                content_fingerprint=record.content_fingerprint,
            )

            try:
                decrypted = self.crypto.decrypt(
                    payload=payload,
                    owner_id=owner_id,
                    memory_id=record.id,
                    category=record.category,
                )
            except Exception:
                # Tampered or corrupted key; fail closed for this item
                continue

            # Bounded keyword matching if query is provided
            if query and query.strip():
                q_terms = [t.lower() for t in query.split() if len(t) > 2]
                text_to_search = f"{record.summary or ''} {decrypted}".lower()
                if not any(term in text_to_search for term in q_terms):
                    continue

            # Output security inspection: verify retrieved content is safe contextual data
            threat_eval = self.threats.inspect(decrypted)
            if threat_eval.is_threat and threat_eval.action.value in ("BLOCK", "QUARANTINE"):
                continue

            retrieved_items.append(
                {
                    "memory_id": record.id,
                    "category": record.category,
                    "summary": record.summary,
                    "content": decrypted,
                    "provenance": record.provenance,
                    "created_at": record.created_at.isoformat(),
                }
            )

            if len(retrieved_items) >= limit:
                break

        # Content-free audit of retrieval
        await self.vault.log_audit(
            db=db,
            app_id=app_id,
            owner_id=owner_id,
            agent_id=agent_id,
            operation="RETRIEVE_CONTEXT",
            action_taken="ALLOW",
            status="SUCCESS",
        )

        return retrieved_items


# Global singleton retrieval service
memory_retrieval_service = MemoryRetrievalService()
