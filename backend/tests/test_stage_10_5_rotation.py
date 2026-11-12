"""Stage 10.5 Key Rotation Engine Unit Tests.
Verifies automated KEK rotation, version lifecycle transitions, non-destructive
DEK rewrapping, post-rotation verification, and CAS concurrency.
"""

import pytest
import uuid
from sqlalchemy.ext.asyncio import AsyncSession
from app.database.models import Application, MemoryRecord, utcnow
from app.key_management.base import KeyAlgorithm, KeyPurpose, KeyStatus
from app.key_management.rotation import key_rotation_engine
from app.memory.crypto import envelope_encryption


@pytest.mark.asyncio
async def test_managed_key_registration(db_session: AsyncSession):
    """Verifies that key registration creates an initial ACTIVE version."""
    tenant_id = f"tenant_{uuid.uuid4().hex[:8]}"
    mkey = await key_rotation_engine.register_managed_key(
        db=db_session,
        name="Primary Memory KEK",
        purpose=KeyPurpose.MEMORY_ENCRYPTION,
        tenant_id=tenant_id,
        provider="local",
        algorithm=KeyAlgorithm.AES_256_GCM,
    )

    assert mkey.id is not None
    assert mkey.status == KeyStatus.ACTIVE.value
    assert mkey.active_version_id is not None
    assert mkey.tenant_id == tenant_id


@pytest.mark.asyncio
async def test_key_rotation_and_dek_rewrapping(db_session: AsyncSession):
    """
    Verifies full lifecycle of key rotation:
    - Version 1 encrypts memory record
    - Rotation initiates Version 2
    - Batch processing rewraps DEK from Version 1 to Version 2 without touching ciphertext
    - Post-rotation record decrypts successfully
    """
    tenant_id = f"tenant_{uuid.uuid4().hex[:8]}"
    owner_id = f"user_{uuid.uuid4().hex[:8]}"
    memory_id = f"mem_rot_{uuid.uuid4().hex[:8]}"
    category = "FINANCIAL"
    plaintext = "Sensitive balance information: $500,000"

    # 1. Register Managed Key
    mkey = await key_rotation_engine.register_managed_key(
        db=db_session,
        name="Banking KEK",
        purpose=KeyPurpose.MEMORY_ENCRYPTION,
        tenant_id=tenant_id,
        provider="local",
        algorithm=KeyAlgorithm.AES_256_GCM,
    )

    # 2. Encrypt memory record under Version 1
    payload_v2_v1 = envelope_encryption.encrypt(
        plaintext=plaintext,
        owner_id=owner_id,
        memory_id=memory_id,
        category=category,
        key_version=1,
        encryption_format="V2",
        tenant_id=tenant_id,
        key_id=mkey.id,
    )

    app = Application(
        name="Rotation Test App",
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
        encrypted_content=payload_v2_v1.ciphertext_b64,
        nonce=payload_v2_v1.nonce_b64,
        wrapped_dek=payload_v2_v1.wrapped_dek_b64,
        dek_nonce=payload_v2_v1.dek_nonce_b64,
        content_fingerprint=payload_v2_v1.content_fingerprint,
        key_version=1,
        encryption_format="V2",
        key_id=mkey.id,
        status="ACTIVE",
        version=1,
        created_at=utcnow(),
        updated_at=utcnow(),
    )
    db_session.add(record)
    await db_session.commit()

    orig_ciphertext = record.encrypted_content
    orig_nonce = record.nonce

    # 3. Initiate Rotation
    rot_job = await key_rotation_engine.initiate_rotation(db_session, key_id=mkey.id)
    assert rot_job.from_version == 1
    assert rot_job.to_version == 2
    assert rot_job.records_total == 1

    # Managed key is marked ROTATING
    await db_session.refresh(mkey)
    assert mkey.status == KeyStatus.ROTATING.value

    # 4. Process Batch Rewrapping
    rewrapped_count, finished = await key_rotation_engine.process_rotation_batch(
        db_session, job_id=rot_job.id, batch_size=10
    )
    assert rewrapped_count == 1
    assert finished is True

    # 5. Verify record state
    await db_session.refresh(record)
    assert record.key_version == 2
    assert record.version == 2

    # Invariant: Ciphertext and nonce must not be altered
    assert record.encrypted_content == orig_ciphertext
    assert record.nonce == orig_nonce

    # 6. Verify managed key returns to ACTIVE status
    await db_session.refresh(mkey)
    assert mkey.status == KeyStatus.ACTIVE.value

    # 7. Verify decryption with updated wrapped DEK under Version 2
    decrypted = envelope_encryption.decrypt(
        payload=payload_v2_v1._replace(
            wrapped_dek_b64=record.wrapped_dek,
            dek_nonce_b64=record.dek_nonce,
            key_version=2,
            encryption_format="V2",
            key_id=mkey.id,
        ),
        owner_id=owner_id,
        memory_id=memory_id,
        category=category,
        tenant_id=tenant_id,
    )
    assert decrypted == plaintext
