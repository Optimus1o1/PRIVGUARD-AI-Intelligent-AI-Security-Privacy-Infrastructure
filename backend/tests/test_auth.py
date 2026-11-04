"""Tests for application authentication and identity."""

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.security import hash_api_key
from app.database.models import Application


@pytest.mark.asyncio
async def test_health_endpoints_require_no_auth(client: AsyncClient):
    """Health endpoints must be open for orchestrators."""
    res_health = await client.get("/health")
    assert res_health.status_code == 200
    assert res_health.json()["status"] == "healthy"

    res_ready = await client.get("/ready")
    assert res_ready.status_code == 200
    assert res_ready.json()["status"] == "ready"


@pytest.mark.asyncio
async def test_missing_auth_header_rejected(client: AsyncClient):
    """Protected endpoints must reject requests without an API key."""
    res = await client.post("/v1/privacy/inspect", json={"text": "hello"})
    assert res.status_code == 401
    assert res.json()["error"]["code"] == "AUTHENTICATION_FAILED"


@pytest.mark.asyncio
async def test_invalid_api_key_rejected(client: AsyncClient, test_app_record: Application):
    """Invalid credentials must receive 401."""
    res = await client.post(
        "/v1/privacy/inspect",
        json={"text": "hello"},
        headers={"X-API-Key": "invalid_key_xyz"},
    )
    assert res.status_code == 401
    assert res.json()["error"]["code"] == "AUTHENTICATION_FAILED"


@pytest.mark.asyncio
async def test_valid_x_api_key_accepted(
    client: AsyncClient, test_app_record: Application, auth_headers: dict
):
    """Valid X-API-Key header authenticates successfully."""
    res = await client.post(
        "/v1/privacy/inspect",
        json={"text": "Hello, this is public text."},
        headers=auth_headers,
    )
    assert res.status_code == 200
    data = res.json()
    assert data["category"] == "PUBLIC"
    assert data["action"] == "ALLOW"


@pytest.mark.asyncio
async def test_valid_bearer_token_accepted(
    client: AsyncClient, test_app_record: Application
):
    """Authorization: Bearer <key> authenticates successfully."""
    from tests.conftest import TEST_API_KEY
    res = await client.post(
        "/v1/privacy/inspect",
        json={"text": "Hello, public text with bearer token."},
        headers={"Authorization": f"Bearer {TEST_API_KEY}"},
    )
    assert res.status_code == 200
    assert res.json()["action"] == "ALLOW"


@pytest.mark.asyncio
async def test_inactive_application_rejected(
    client: AsyncClient, db_session: AsyncSession
):
    """Deactivated applications must be rejected immediately."""
    inactive_key = "pg_live_inactive_key_000"
    app_record = Application(
        name="Disabled App",
        api_key_hash=hash_api_key(inactive_key),
        is_active=False,
    )
    db_session.add(app_record)
    await db_session.commit()

    res = await client.post(
        "/v1/privacy/inspect",
        json={"text": "Hello"},
        headers={"X-API-Key": inactive_key},
    )
    assert res.status_code == 401
    assert "disabled" in res.json()["error"]["message"]
