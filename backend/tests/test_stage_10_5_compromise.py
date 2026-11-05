"""Stage 10.5 Cryptographic Compromise Incident Response Tests.
Verifies emergency containment procedures for DEK, KEK, Policy Signing Keys,
and Approval HMAC Keys.
"""

import pytest
import uuid
import json
from sqlalchemy.ext.asyncio import AsyncSession
from app.database.models import Application, KeyVersion, ManagedKey, MemoryRecord, PolicyBundle, utcnow
from app.key_management.base import KeyAlgorithm, KeyPurpose, KeyStatus
from app.key_management.compromise import key_compromise_manager, CompromiseType
from app.key_management.rotation import key_rotation_engine
from app.memory.crypto import envelope_encryption


@pytest.mark.asyncio
async def test_dek_compromise_re_encryption(db_session: AsyncSession):
    """Verifies that DEK compromise generates a fresh DEK and full re-encryption of payload."""
    tenant_id = f"tenant_{uuid.uuid4().hex[:8]}"
    owner_id = f"user_{uuid.uuid4().hex[:8]}"
    memory_id = f"mem_compromised_{uuid.uuid4().hex[:8]}"
    category = "SECURITY"
    plaintext = "Compromised DEK test secret message."

    app = Application(name="Incident App", api_key_hash=uuid.uuid4().hex, tenant_id=tenant_id)
    db_session.add(app)
    await db_session.flush()

    payload = envelope_encryption.encrypt(
        plaintext=plaintext,
        owner_id=owner_id,
        memory_id=memory_id,
        category=category,
        encryption_format="V2",
        tenant_id=tenant_id,
    )

    record = MemoryRecord(
        id=memory_id,
        tenant_id=tenant_id,
        app_id=app.id,
        owner_id=owner_id,
        category=category,
        encrypted_content=payload.ciphertext_b64,
        nonce=payload.nonce_b64,
        wrapped_dek=payload.wrapped_dek_b64,
        dek_nonce=payload.dek_nonce_b64,
        content_fingerprint=payload.content_fingerprint,
        key_version=payload.key_version,
        encryption_format="V2",
        status="ACTIVE",
        version=1,
        created_at=utcnow(),
        updated_at=utcnow(),
    )
    db_session.add(record)
    await db_session.commit()

    old_ciphertext = record.encrypted_content
    old_nonce = record.nonce
    old_wrapped_dek = record.wrapped_dek

    # Execute emergency DEK compromise containment
    result = await key_compromise_manager.handle_dek_compromise(
        db=db_session,
        memory_id=memory_id,
        tenant_id=tenant_id,
    )

    assert result["status"] == "CONTAINED"
    assert result["action"] == "PAYLOAD_RE_ENCRYPTED_WITH_FRESH_DEK"

    await db_session.refresh(record)
    # INVARIANT: Ciphertext, nonce, and wrapped DEK must all be freshly generated
    assert record.encrypted_content != old_ciphertext
    assert record.nonce != old_nonce
    assert record.wrapped_dek != old_wrapped_dek

    # Plaintext must decrypt correctly from the freshly re-encrypted record
    decrypted = envelope_encryption.decrypt(
        payload=payload._replace(
            ciphertext_b64=record.encrypted_content,
            nonce_b64=record.nonce,
            wrapped_dek_b64=record.wrapped_dek,
            dek_nonce_b64=record.dek_nonce,
        ),
        owner_id=owner_id,
        memory_id=memory_id,
        category=category,
        tenant_id=tenant_id,
    )
    assert decrypted == plaintext


@pytest.mark.asyncio
async def test_kek_compromise_emergency_rotation(db_session: AsyncSession):
    """Verifies that KEK compromise marks key COMPROMISED and initiates emergency rotation."""
    tenant_id = f"tenant_{uuid.uuid4().hex[:8]}"

    mkey = await key_rotation_engine.register_managed_key(
        db=db_session,
        name="Compromised KEK",
        purpose=KeyPurpose.MEMORY_ENCRYPTION,
        tenant_id=tenant_id,
    )

    orig_ver_id = mkey.active_version_id

    # Handle KEK compromise
    res = await key_compromise_manager.handle_kek_compromise(
        db=db_session,
        key_id=mkey.id,
        tenant_id=tenant_id,
    )

    assert res["status"] == "ROTATING"
    assert res["incident_type"] == CompromiseType.KEK_COMPROMISE.value

    # Verify original version is marked COMPROMISED
    vq = await db_session.get(KeyVersion, orig_ver_id)
    assert vq.status == KeyStatus.COMPROMISED.value


def test_hmac_key_compromise():
    """Verifies that HMAC compromise revokes the compromised kid and activates a fresh kid."""
    active_kid = key_compromise_manager.signing_manager.get_active_hmac_kid()

    res = key_compromise_manager.handle_hmac_key_compromise(active_kid)

    assert res["status"] == "CONTAINED"
    assert res["revoked_kid"] == active_kid
    assert res["active_kid"] != active_kid

    # Verify revoked kid is rejected
    assert active_kid not in key_compromise_manager.signing_manager._local_hmac_keys
