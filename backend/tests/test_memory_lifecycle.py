"""Tests for Memory Lifecycle, Optimistic Concurrency Control, and Cryptographic Erasure."""

import pytest
from datetime import datetime, timezone, timedelta
from app.core.exceptions import MemoryNotFoundError, PrivGuardException
from app.database.models import Application, MemoryRecord, MemoryVersion
from app.memory.vault import memory_vault
from sqlalchemy import select


@pytest.fixture
async def setup_life_env(db_session):
    app = Application(id="app_life_test", name="Lifecycle App", api_key_hash="hash_l", is_active=True)
    db_session.add(app)
    await db_session.commit()
    return {"app": app, "owner_id": "user_life_alice"}


@pytest.mark.asyncio
async def test_memory_creation_and_retrieval(db_session, setup_life_env):
    """Verifies direct creation, envelope encryption, and retrieval of memory."""
    env = setup_life_env
    app = env["app"]
    owner_id = env["owner_id"]

    record = await memory_vault.create_memory(
        db=db_session,
        app_id=app.id,
        owner_id=owner_id,
        key="Timezone",
        value="Asia/Kolkata (IST)",
        category="USER_PREFERENCES",
        retention_days=60,
    )

    assert record.id.startswith("mem_")
    assert record.status == "ACTIVE"
    assert record.version == 1
    assert record.retention_days == 60

    # Retrieve and decrypt
    retrieved = await memory_vault.get_memory(db_session, app.id, owner_id, record.id)
    assert retrieved["value"] == "Asia/Kolkata (IST)"


@pytest.mark.asyncio
async def test_memory_update_cas_and_version_archival(db_session, setup_life_env):
    """Verifies optimistic CAS updating and archival of previous encrypted versions."""
    env = setup_life_env
    app = env["app"]
    owner_id = env["owner_id"]

    mem = await memory_vault.create_memory(
        db=db_session,
        app_id=app.id,
        owner_id=owner_id,
        key="Working Hours",
        value="09:00 - 17:00 IST",
        category="WORK_CONTEXT",
    )

    # 1. Update with correct expected_version=1
    updated = await memory_vault.update_memory(
        db=db_session,
        app_id=app.id,
        owner_id=owner_id,
        memory_id=mem.id,
        new_value="10:00 - 18:00 IST",
        expected_version=1,
    )
    assert updated.version == 2

    # Verify decrypted value reflects the update
    res = await memory_vault.get_memory(db_session, app.id, owner_id, mem.id)
    assert res["value"] == "10:00 - 18:00 IST"

    # Verify version 1 was archived in MemoryVersion table
    stmt = select(MemoryVersion).where(MemoryVersion.memory_id == mem.id, MemoryVersion.version_num == 1)
    archive_res = await db_session.execute(stmt)
    archived = archive_res.scalar_one_or_none()
    assert archived is not None
    assert archived.version_num == 1

    # 2. Update with stale expected_version=1 -> raises 409 conflict
    with pytest.raises(PrivGuardException) as exc_info:
        await memory_vault.update_memory(
            db=db_session,
            app_id=app.id,
            owner_id=owner_id,
            memory_id=mem.id,
            new_value="08:00 - 16:00 IST",
            expected_version=1,
        )
    assert exc_info.value.status_code == 409
    assert exc_info.value.error_code == "MEMORY_VERSION_CONFLICT"


@pytest.mark.asyncio
async def test_cryptographic_erasure(db_session, setup_life_env):
    """Verifies that delete_memory permanently destroys DEK and wipes ciphertext."""
    env = setup_life_env
    app = env["app"]
    owner_id = env["owner_id"]

    mem = await memory_vault.create_memory(
        db=db_session,
        app_id=app.id,
        owner_id=owner_id,
        key="Temporary confidential note",
        value="Super sensitive data to be erased immediately",
        category="TASK_CONTEXT",
    )

    # Delete memory
    deleted = await memory_vault.delete_memory(db_session, app.id, owner_id, mem.id)
    assert deleted is True

    # Confirm retrieval raises MemoryNotFoundError
    with pytest.raises(MemoryNotFoundError):
        await memory_vault.get_memory(db_session, app.id, owner_id, mem.id)

    # Inspect underlying database record
    stmt = select(MemoryRecord).where(MemoryRecord.id == mem.id)
    r = (await db_session.execute(stmt)).scalar_one()

    assert r.status == "DELETED"
    assert r.encrypted_content == "[CRYPTOGRAPHICALLY_ERASED]"
    assert r.wrapped_dek == "[DEK_DESTROYED]"
    assert r.nonce == "[WIPED]"
    assert r.dek_nonce == "[WIPED]"


@pytest.mark.asyncio
async def test_soft_revocation(db_session, setup_life_env):
    """Verifies that revoking a memory sets status REVOKED and blocks retrieval."""
    env = setup_life_env
    app = env["app"]
    owner_id = env["owner_id"]

    mem = await memory_vault.create_memory(
        db=db_session,
        app_id=app.id,
        owner_id=owner_id,
        key="Revocable Context",
        value="Context that user wants to temporarily or permanently revoke",
        category="USER_PREFERENCES",
    )

    await memory_vault.revoke_memory(db_session, app.id, owner_id, mem.id)

    with pytest.raises(MemoryNotFoundError):
        await memory_vault.get_memory(db_session, app.id, owner_id, mem.id)


@pytest.mark.asyncio
async def test_account_vault_purge(db_session, setup_life_env):
    """Verifies complete account purge cryptographically erases all user records."""
    env = setup_life_env
    app = env["app"]
    owner_id = env["owner_id"]

    # Create 3 memories
    for i in range(3):
        await memory_vault.create_memory(
            db=db_session,
            app_id=app.id,
            owner_id=owner_id,
            key=f"Purge item {i}",
            value=f"Sensitive content {i}",
            category="USER_PREFERENCES",
        )

    # Purge vault
    job = await memory_vault.purge_vault(db_session, app.id, owner_id)
    assert job.status == "COMPLETED"
    assert job.items_deleted == 3

    # Verify all records for owner are DELETED and keys destroyed
    stmt = select(MemoryRecord).where(MemoryRecord.owner_id == owner_id)
    records = (await db_session.execute(stmt)).scalars().all()
    assert len(records) == 3
    for r in records:
        assert r.status == "DELETED"
        assert r.encrypted_content == "[CRYPTOGRAPHICALLY_ERASED]"
        assert r.wrapped_dek == "[DEK_DESTROYED]"
