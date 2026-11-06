"""Non-destructive legacy V1 to V2 KMS envelope encryption migration engine."""

import base64
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import func, select, update

from app.core.config import settings
from app.core.exceptions import PrivGuardException
from app.database.models import KeyMigrationJob, MemoryRecord, utcnow
from app.key_management.manager import KMSManager, kms_manager as default_kms_manager
from app.memory.crypto import (
    EncryptedMemoryPayload,
    EnvelopeEncryption,
    envelope_encryption as default_envelope_encryption,
)
from app.memory.key_provider import KeyProvider, default_key_provider


class LegacyMemoryMigrator:
    """
    Non-destructive migrator converting Stage 7 V1 memory records to V2 KMS envelopes.

    Guarantees:
    - Zero data payload re-encryption: unwraps legacy DEK and rewraps under target KMS KEK.
    - Preserves data ciphertext, nonce, and original content AAD.
    - Atomic Compare-And-Swap (CAS) database updates.
    - Post-update decryption verification before marking record migrated.
    - Checkpointed, resumable batch processing.
    - Legacy key retirement prevention while unmigrated records exist.
    """

    def __init__(
        self,
        kms_mgr: Optional[KMSManager] = None,
        key_provider: Optional[KeyProvider] = None,
        crypto_engine: Optional[EnvelopeEncryption] = None,
    ) -> None:
        self.kms_manager = kms_mgr or default_kms_manager
        self.key_provider = key_provider or default_key_provider
        self.crypto_engine = crypto_engine or default_envelope_encryption

    async def get_unmigrated_count(self, db: AsyncSession, tenant_id: Optional[str] = None) -> int:
        """Counts remaining V1 records requiring migration."""
        query = select(func.count(MemoryRecord.id)).where(
            (MemoryRecord.encryption_format == "V1") | (MemoryRecord.encryption_format.is_(None))
        )
        if tenant_id:
            query = query.where(MemoryRecord.tenant_id == tenant_id)
        result = await db.execute(query)
        return result.scalar() or 0

    async def can_retire_legacy_key(self, db: AsyncSession, tenant_id: Optional[str] = None) -> Tuple[bool, str]:
        """
        Validates whether the legacy master key can be safely retired.
        Enforces that zero unmigrated records exist.
        """
        count = await self.get_unmigrated_count(db, tenant_id)
        if count > 0:
            return False, f"Cannot retire legacy key: {count} unmigrated V1 records exist in active database."
        return (
            True,
            "All active records migrated to V2 KMS. Ensure backup retention period has elapsed before destroying key.",
        )

    async def start_migration_job(
        self,
        db: AsyncSession,
        tenant_id: str = "default_tenant",
        batch_size: int = 50,
    ) -> KeyMigrationJob:
        """Initializes a new tracked migration job."""
        total = await self.get_unmigrated_count(db, tenant_id)
        job = KeyMigrationJob(
            tenant_id=tenant_id,
            source_format="V1_LOCAL",
            target_format="V2_KMS",
            status="IN_PROGRESS" if total > 0 else "COMPLETED",
            batch_size=batch_size,
            records_total=total,
            records_migrated=0,
            created_at=utcnow(),
        )
        db.add(job)
        await db.commit()
        await db.refresh(job)
        return job

    async def process_batch(
        self,
        db: AsyncSession,
        job_id: str,
        target_key_id: Optional[str] = None,
    ) -> Tuple[int, bool]:
        """
        Processes a single batch of V1 records:
        Rewraps DEK from legacy HKDF to target KMS KEK with CAS check and verification.
        Returns: (records_migrated_in_batch, is_finished)
        """
        query = select(KeyMigrationJob).where(KeyMigrationJob.id == job_id)
        res = await db.execute(query)
        job = res.scalar_one_or_none()
        if not job or job.status in ("COMPLETED", "FAILED"):
            return 0, True

        key_id = target_key_id or settings.KMS_KEY_ID or f"mem_kek_{job.tenant_id}"

        # Fetch batch of unmigrated records
        rec_query = (
            select(MemoryRecord)
            .where(
                MemoryRecord.tenant_id == job.tenant_id,
                (MemoryRecord.encryption_format == "V1") | (MemoryRecord.encryption_format.is_(None)),
            )
            .order_by(MemoryRecord.created_at.asc())
            .limit(job.batch_size)
        )
        records_res = await db.execute(rec_query)
        records: List[MemoryRecord] = records_res.scalars().all()

        if not records:
            job.status = "COMPLETED"
            job.completed_at = utcnow()
            await db.commit()
            return 0, True

        migrated_in_batch = 0

        for record in records:
            try:
                # 1. Unwrap legacy DEK using legacy provider and legacy AAD
                user_kek = self.key_provider.get_user_kek(record.owner_id, key_version=record.key_version)
                aes_kek = AESGCM(user_kek)
                wrapped_dek_bytes = base64.b64decode(record.wrapped_dek)
                dek_nonce_bytes = base64.b64decode(record.dek_nonce)
                dek_aad = f"wrapped_dek:{record.id}:{record.key_version}".encode("utf-8")
                dek = aes_kek.decrypt(dek_nonce_bytes, wrapped_dek_bytes, dek_aad)

                # 2. Rewrap the exact same DEK under target KMS KEK
                wrapped_res = self.kms_manager.wrap_dek_sync(
                    key_id=key_id,
                    plaintext_dek=dek,
                    tenant_id=record.tenant_id,
                    format_version="v2",
                )

                new_wrapped_dek_b64 = base64.b64encode(wrapped_res.wrapped_key).decode("ascii")
                new_dek_nonce_b64 = base64.b64encode(wrapped_res.nonce).decode("ascii") if wrapped_res.nonce else ""
                new_key_version = (
                    int(wrapped_res.key_version) if wrapped_res.key_version.isdigit() else record.key_version
                )

                # 3. Atomic CAS database update
                cas_update = (
                    update(MemoryRecord)
                    .where(MemoryRecord.id == record.id, MemoryRecord.version == record.version)
                    .values(
                        wrapped_dek=new_wrapped_dek_b64,
                        dek_nonce=new_dek_nonce_b64,
                        key_version=new_key_version,
                        encryption_format="V2",
                        key_id=key_id,
                        version=record.version + 1,
                        updated_at=utcnow(),
                    )
                )
                update_res = await db.execute(cas_update)
                if update_res.rowcount == 0:
                    # CAS conflict - concurrent update; skip to retry in next cycle
                    continue

                # 4. Immediate post-update verification: verify V2 payload decrypts cleanly
                verify_payload = EncryptedMemoryPayload(
                    ciphertext_b64=record.encrypted_content,
                    nonce_b64=record.nonce,
                    wrapped_dek_b64=new_wrapped_dek_b64,
                    dek_nonce_b64=new_dek_nonce_b64,
                    key_version=new_key_version,
                    content_fingerprint=record.content_fingerprint,
                    encryption_format="V2",
                    key_id=key_id,
                )
                # Test decryption (raises MemoryTamperingError if invalid)
                self.crypto_engine.decrypt(
                    payload=verify_payload,
                    owner_id=record.owner_id,
                    memory_id=record.id,
                    category=record.category,
                    tenant_id=record.tenant_id,
                )

                migrated_in_batch += 1
                job.checkpoint_id = record.id

            except Exception as exc:
                job.status = "FAILED"
                job.error_message = f"Migration failed on record '{record.id}': {exc}"
                await db.commit()
                raise PrivGuardException(
                    f"Legacy migration aborted due to verification failure on record '{record.id}': {exc}",
                    status_code=500,
                    error_code="MIGRATION_VERIFICATION_FAILED",
                )

        job.records_migrated += migrated_in_batch
        remaining = await self.get_unmigrated_count(db, job.tenant_id)
        if remaining == 0:
            job.status = "COMPLETED"
            job.completed_at = utcnow()

        await db.commit()
        return migrated_in_batch, (remaining == 0)


# Global singleton migrator
legacy_migrator = LegacyMemoryMigrator()
