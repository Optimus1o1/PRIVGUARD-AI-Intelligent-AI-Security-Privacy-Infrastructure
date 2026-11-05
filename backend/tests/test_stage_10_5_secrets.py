"""Stage 10.5 Secret Metadata Management Unit Tests.
Verifies operational secret metadata registration, rotation, revocation,
zero plaintext exposure, and cross-tenant boundary enforcement.
"""

import pytest
import uuid
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.exceptions import PrivGuardException
from app.secrets.base import SecretStatus, SecretType
from app.secrets.manager import secret_manager


@pytest.mark.asyncio
async def test_secret_registration_and_listing(db_session: AsyncSession):
    """Verifies that secrets can be registered and listed without leaking plaintext."""
    tenant_id = f"tenant_{uuid.uuid4().hex[:8]}"

    record = await secret_manager.register_secret(
        db=db_session,
        name="Production OpenAI Key",
        secret_type=SecretType.LLM_API_KEY,
        tenant_id=tenant_id,
        provider_ref="env:OPENAI_API_KEY",
    )

    assert record.id is not None
    assert record.name == "Production OpenAI Key"
    assert record.version == 1
    assert record.status == SecretStatus.ACTIVE.value

    # List secrets for this tenant
    secrets = await secret_manager.list_secrets(db_session, tenant_id=tenant_id)
    assert len(secrets) == 1
    sec = secrets[0]
    assert sec.id == record.id
    assert sec.name == "Production OpenAI Key"
    assert sec.secret_type == SecretType.LLM_API_KEY

    # Zero plaintext invariant: no secret material attribute on metadata
    assert not hasattr(sec, "plaintext_value")
    assert not hasattr(sec, "value")


@pytest.mark.asyncio
async def test_secret_rotation(db_session: AsyncSession):
    """Verifies secret rotation increments version and generates a rotation job."""
    tenant_id = f"tenant_{uuid.uuid4().hex[:8]}"

    record = await secret_manager.register_secret(
        db=db_session,
        name="Payment Gateway Secret",
        secret_type=SecretType.OAUTH_SECRET,
        tenant_id=tenant_id,
    )

    # Rotate
    job = await secret_manager.rotate_secret(
        db_session, secret_id=record.id, tenant_id=tenant_id
    )
    assert job.secret_id == record.id
    assert job.status == "COMPLETED"

    # Refresh and inspect
    await db_session.refresh(record)
    assert record.version == 2
    assert record.status == SecretStatus.ACTIVE.value


@pytest.mark.asyncio
async def test_secret_revocation(db_session: AsyncSession):
    """Verifies revoking a secret transitions its status to REVOKED."""
    tenant_id = f"tenant_{uuid.uuid4().hex[:8]}"

    record = await secret_manager.register_secret(
        db=db_session,
        name="Deprecated OAuth Client Secret",
        secret_type=SecretType.OAUTH_SECRET,
        tenant_id=tenant_id,
    )

    ok = await secret_manager.revoke_secret(
        db_session, secret_id=record.id, tenant_id=tenant_id
    )
    assert ok is True

    await db_session.refresh(record)
    assert record.status == SecretStatus.REVOKED.value


@pytest.mark.asyncio
async def test_cross_tenant_secret_isolation(db_session: AsyncSession):
    """Verifies that Tenant B cannot access or rotate Tenant A's secrets."""
    tenant_a = f"tenant_a_{uuid.uuid4().hex[:6]}"
    tenant_b = f"tenant_b_{uuid.uuid4().hex[:6]}"

    record_a = await secret_manager.register_secret(
        db=db_session,
        name="Tenant A Secret",
        secret_type=SecretType.DATABASE_CREDENTIAL,
        tenant_id=tenant_a,
    )

    # Tenant B lists secrets -> should be empty
    secrets_b = await secret_manager.list_secrets(db_session, tenant_id=tenant_b)
    assert len(secrets_b) == 0

    # Tenant B tries to rotate Tenant A's secret -> 404 PrivGuardException
    with pytest.raises(PrivGuardException) as exc:
        await secret_manager.rotate_secret(
            db_session, secret_id=record_a.id, tenant_id=tenant_b
        )
    assert exc.value.status_code == 404
