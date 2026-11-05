"""Stage 10.5 REST API Integration Tests.
Verifies KMS keys, key rotation, legacy migration, secret metadata,
and compromise incident endpoints via FastAPI test client.
"""

import pytest
import httpx
from app.database.models import Application
from app.key_management.base import KeyAlgorithm, KeyPurpose, KeyStatus


@pytest.mark.asyncio
async def test_keys_api_crud_and_rotation(client: httpx.AsyncClient, test_app_record: Application, auth_headers: dict):
    """Verifies listing, registering, rotating, and verifying managed keys via REST API."""
    # 1. Register a key
    register_res = await client.post(
        "/v1/keys",
        json={
            "name": "API Test Memory KEK",
            "purpose": KeyPurpose.MEMORY_ENCRYPTION.value,
            "provider": "local",
            "algorithm": KeyAlgorithm.AES_256_GCM.value,
        },
        headers=auth_headers,
    )
    assert register_res.status_code == 201
    key_data = register_res.json()
    key_id = key_data["id"]
    assert key_data["status"] == KeyStatus.ACTIVE.value
    assert "key_material" not in key_data

    # 2. List keys
    list_res = await client.get("/v1/keys", headers=auth_headers)
    assert list_res.status_code == 200
    keys = list_res.json()
    assert any(k["id"] == key_id for k in keys)

    # 3. Verify key accessibility
    verify_res = await client.post(f"/v1/keys/{key_id}/verify", headers=auth_headers)
    assert verify_res.status_code == 200
    v_data = verify_res.json()
    assert v_data["healthy"] is True
    assert v_data["key_id"] == key_id

    # 4. Rotate key
    rot_res = await client.post(f"/v1/keys/{key_id}/rotate", headers=auth_headers)
    assert rot_res.status_code == 200
    rot_data = rot_res.json()
    assert rot_data["from_version"] == 1
    assert rot_data["to_version"] == 2


@pytest.mark.asyncio
async def test_secrets_api_lifecycle(client: httpx.AsyncClient, test_app_record: Application, auth_headers: dict):
    """Verifies secret metadata registration, listing, rotation, and revocation via REST API."""
    # 1. Register secret metadata
    reg_res = await client.post(
        "/v1/secrets",
        json={
            "name": "Integration LLM Key",
            "secret_type": "LLM_API_KEY",
            "provider_ref": "env:LLM_API_KEY",
        },
        headers=auth_headers,
    )
    assert reg_res.status_code == 201
    secret_data = reg_res.json()
    secret_id = secret_data["id"]
    assert secret_data["version"] == 1
    assert "plaintext" not in secret_data

    # 2. List secrets
    list_res = await client.get("/v1/secrets", headers=auth_headers)
    assert list_res.status_code == 200
    secrets = list_res.json()
    assert any(s["id"] == secret_id for s in secrets)

    # 3. Rotate secret
    rot_res = await client.post(f"/v1/secrets/{secret_id}/rotate", headers=auth_headers)
    assert rot_res.status_code == 200
    assert rot_res.json()["status"] == "ROTATED"

    # 4. Revoke secret
    rev_res = await client.post(f"/v1/secrets/{secret_id}/revoke", headers=auth_headers)
    assert rev_res.status_code == 200
    assert rev_res.json()["status"] == "REVOKED"


@pytest.mark.asyncio
async def test_migration_and_incidents_api(client: httpx.AsyncClient, test_app_record: Application, auth_headers: dict):
    """Verifies migration status and emergency compromise declaration via REST API."""
    # 1. Migration status
    status_res = await client.get("/v1/keys/migration/status", headers=auth_headers)
    assert status_res.status_code == 200
    s_data = status_res.json()
    assert "unmigrated_records" in s_data
    assert "can_retire_legacy_key" in s_data

    # 2. Incident compromise containment for HMAC
    comp_res = await client.post(
        "/v1/incidents/compromise",
        json={
            "compromise_type": "APPROVAL_HMAC_KEY_COMPROMISE",
            "target_id": "hmac_v1",
            "notes": "Suspected token leakage during developer debugging",
        },
        headers=auth_headers,
    )
    assert comp_res.status_code == 200
    c_data = comp_res.json()
    assert c_data["status"] == "CONTAINED"
    assert c_data["revoked_kid"] == "hmac_v1"
