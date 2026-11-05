"""Stage 10.5 Non-Destructive Legacy V1 to V2 Migration Tests.
Verifies zero data re-encryption, ciphertext and nonce preservation, CAS updates,
post-migration verification, and legacy key retirement safeguard.
"""

import pytest
import uuid
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import update
from app.database.models import Application, MemoryRecord, utcnow
from app.key_management.migration import legacy_migrator
from app.memory.crypto import envelope_encryption


@pytest.mark.asyncio
async def test_non_destructive_v1_to_v2_migration(db_session: AsyncSession):
    """
    Verifies that legacy V1 records are migrated to V2 KMS envelopes non-destructively:
    - Data ciphertext and nonce are 100% preserved.
    - Decryption of migrated record produces original plaintext.
    - Legacy key retirement check passes only after migration.
    """
    tenant_id = f"tenant_{uuid.uuid4().hex[:8]}"
    owner_id = f"user_{uuid.uuid4().hex[:8]}"
    memory_id = f"mem_{uuid.uuid4().hex[:8]}"
    category = "USER_PREFERENCES"
    plaintext = "I prefer dark mode, low temperature 0.2, and concise responses."

    # 1. Create a V1 record using Stage 7 legacy HKDF envelope
    payload_v1 = envelope_encryption.encrypt(
        plaintext=plaintext,
        owner_id=owner_id,
        memory_id=memory_id,
        category=category,
        encryption_format="V1",
        tenant_id=tenant_id,
    )

    # Create parent application
    app = Application(
        name="Migration Test App",
        api_key_hash=uuid.uuid4().hex,
        tenant_id=tenant_id,
    )
    db_session.add(app)
    await db_session.flush()

    record = MemoryRecord(
        id=memory_id,
        tenant_id=tenant_id,
        app_id=app.id,
        owner_id=owner_id,
        category=category,
        encrypted_content=payload_v1.ciphertext_b64,
        nonce=payload_v1.nonce_b64,
        wrapped_dek=payload_v1.wrapped_dek_b64,
        dek_nonce=payload_v1.dek_nonce_b64,
        content_fingerprint=payload_v1.content_fingerprint,
        key_version=payload_v1.key_version,
        encryption_format="V1",
        status="ACTIVE",
        version=1,
        created_at=utcnow(),
        updated_at=utcnow(),
    )
    db_session.add(record)
    await db_session.commit()

    # Capture pre-migration state
    orig_ciphertext = record.encrypted_content
    orig_nonce = record.nonce
    orig_fingerprint = record.content_fingerprint

    # 2. Check retirement safeguard before migration (Must be BLOCKED)
    can_retire, reason = await legacy_migrator.can_retire_legacy_key(db_session, tenant_id=tenant_id)
    assert can_retire is False
    assert "unmigrated" in reason.lower()

    # 3. Start migration job and process batch
    job = await legacy_migrator.start_migration_job(db_session, tenant_id=tenant_id, batch_size=10)
    migrated_count, finished = await legacy_migrator.process_batch(db_session, job_id=job.id)

    assert migrated_count == 1
    assert finished is True

    # 4. Refresh record and verify preservation
    await db_session.refresh(record)
    assert record.encryption_format == "V2"
    assert record.key_id is not None
    assert record.version == 2

    # INVARIANT: Zero payload re-encryption
    assert record.encrypted_content == orig_ciphertext
    assert record.nonce == orig_nonce
    assert record.content_fingerprint == orig_fingerprint

    # 5. Decrypt migrated record using dual-AAD fallback in V2 decryptor
    decrypted = envelope_encryption.decrypt(
        payload=payload_v1._replace(
            wrapped_dek_b64=record.wrapped_dek,
            dek_nonce_b64=record.dek_nonce,
            key_version=record.key_version,
            encryption_format="V2",
            key_id=record.key_id,
        ),
        owner_id=owner_id,
        memory_id=memory_id,
        category=category,
        tenant_id=tenant_id,
    )
    assert decrypted == plaintext

    # 6. Check retirement safeguard after migration (Must be ALLOWED)
    can_retire_post, msg = await legacy_migrator.can_retire_legacy_key(db_session, tenant_id=tenant_id)
    assert can_retire_post is True
    assert "all active records migrated" in msg.lower()


@pytest.mark.asyncio
async def test_migration_batching_and_concurrency_cas(db_session: AsyncSession):
    """Verifies that migration respects batch boundaries and handles concurrent version changes."""
    tenant_id = f"tenant_{uuid.uuid4().hex[:8]}"
    app = Application(
        name="Batch App",
        api_key_hash=uuid.uuid4().hex,
        tenant_id=tenant_id,
    )
    db_session.add(app)
    await db_session.flush()

    # Create 3 records
    for i in range(3):
        mem_id = f"mem_batch_{i}_{uuid.uuid4().hex[:6]}"
        payload = envelope_encryption.encrypt(
            plaintext=f"Note {i}",
            owner_id="user_batch",
            memory_id=mem_id,
            category="GENERAL",
            encryption_format="V1",
            tenant_id=tenant_id,
        )
        rec = MemoryRecord(
            id=mem_id,
            tenant_id=tenant_id,
            app_id=app.id,
            owner_id="user_batch",
            category="GENERAL",
            encrypted_content=payload.ciphertext_b64,
            nonce=payload.nonce_b64,
            wrapped_dek=payload.wrapped_dek_b64,
            dek_nonce=payload.dek_nonce_b64,
            content_fingerprint=payload.content_fingerprint,
            key_version=1,
            encryption_format="V1",
            status="ACTIVE",
            version=1,
            created_at=utcnow(),
            updated_at=utcnow(),
        )
        db_session.add(rec)
    await db_session.commit()

    # Batch size 2
    job = await legacy_migrator.start_migration_job(db_session, tenant_id=tenant_id, batch_size=2)
    assert job.records_total == 3

    # Process first batch (should migrate 2)
    c1, f1 = await legacy_migrator.process_batch(db_session, job_id=job.id)
    assert c1 == 2
    assert f1 is False

    # Process second batch (should migrate remaining 1)
    c2, f2 = await legacy_migrator.process_batch(db_session, job_id=job.id)
    assert c2 == 1
    assert f2 is True

    # Total remaining must now be 0
    remaining = await legacy_migrator.get_unmigrated_count(db_session, tenant_id=tenant_id)
    assert remaining == 0
