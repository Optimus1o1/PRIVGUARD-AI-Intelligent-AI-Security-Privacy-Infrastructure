"""Integration tests for Tenant Isolation and Compliance API Endpoints."""

import pytest
from httpx import ASGITransport, AsyncClient

from app.core.security import hash_api_key
from app.database.models import Application
from app.main import app
from tests.conftest import TEST_API_KEY


@pytest.mark.asyncio
async def test_public_signing_key_endpoint_unauthenticated():
    """Verifies that /v1/compliance/signing-keys/public is accessible without API key."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/v1/compliance/signing-keys/public")
        assert res.status_code == 200
        data = res.json()
        assert data["kid"]
        assert data["algorithm"] == "ED25519"
        assert "BEGIN PUBLIC KEY" in data["public_key_pem"]


@pytest.mark.asyncio
async def test_compliance_frameworks_read_only_endpoint(test_app_record: Application):
    """Verifies GET /v1/compliance/frameworks requires valid API key and returns registered frameworks."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Without key -> 401
        res_no_auth = await client.get("/v1/compliance/frameworks")
        assert res_no_auth.status_code in (401, 403)

        # With key -> 200
        headers = {"X-API-Key": TEST_API_KEY}
        res = await client.get("/v1/compliance/frameworks", headers=headers)
        assert res.status_code == 200
        frameworks = res.json()
        assert len(frameworks) >= 7


@pytest.mark.asyncio
async def test_compliance_controls_and_detail(test_app_record: Application):
    """Verifies GET /v1/compliance/controls returns 35 controls."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        headers = {"X-API-Key": TEST_API_KEY}
        res = await client.get("/v1/compliance/controls", headers=headers)
        assert res.status_code == 200
        controls = res.json()
        assert len(controls) == 35

        # Check single control detail
        res_detail = await client.get("/v1/compliance/controls/PG-CONTROL-005", headers=headers)
        assert res_detail.status_code == 200
        detail = res_detail.json()
        assert detail["id"] == "PG-CONTROL-005"
        assert len(detail["mappings"]) >= 1


@pytest.mark.asyncio
async def test_evidence_collection_and_cross_tenant_isolation(db_session):
    """
    Verifies that evidence collected under Tenant A is isolated from Tenant B.
    """
    # 1. Create two separate applications for Tenant A and Tenant B
    app_a = Application(
        name="App Tenant A",
        tenant_id="tenant_isolated_a",
        api_key_hash=hash_api_key("key_tenant_a_12345"),
        is_active=True,
    )
    app_b = Application(
        name="App Tenant B",
        tenant_id="tenant_isolated_b",
        api_key_hash=hash_api_key("key_tenant_b_67890"),
        is_active=True,
    )
    db_session.add(app_a)
    db_session.add(app_b)
    await db_session.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Collect evidence for Tenant A
        headers_a = {"X-API-Key": "key_tenant_a_12345"}
        res_collect = await client.post(
            "/v1/compliance/evidence/collect",
            headers=headers_a,
            json={"collectors": ["canary_collector", "kms_collector"]},
        )
        assert res_collect.status_code == 200
        collect_data = res_collect.json()
        assert collect_data["collected_count"] >= 1

        # Query evidence as Tenant A -> should find records
        res_ev_a = await client.get("/v1/compliance/evidence", headers=headers_a)
        assert res_ev_a.status_code == 200
        ev_list_a = res_ev_a.json()
        assert len(ev_list_a) >= 1
        for item in ev_list_a:
            assert item["tenant_id"] == "tenant_isolated_a"

        # Query evidence as Tenant B -> should see ZERO records from Tenant A
        headers_b = {"X-API-Key": "key_tenant_b_67890"}
        res_ev_b = await client.get("/v1/compliance/evidence", headers=headers_b)
        assert res_ev_b.status_code == 200
        ev_list_b = res_ev_b.json()
        assert len(ev_list_b) == 0  # Tenant B cannot see Tenant A's evidence!


@pytest.mark.asyncio
async def test_applicability_and_gap_analysis_endpoints(test_app_record: Application):
    """Verifies applicability PATCH and gap analysis GET."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        headers = {"X-API-Key": TEST_API_KEY}

        # Update applicability
        patch_res = await client.patch(
            "/v1/compliance/applicability",
            headers=headers,
            json={
                "framework_id": "dpdp-2023",
                "requirement_id": None,
                "decision": "APPLICABLE",
                "role": "DATA_FIDUCIARY",
                "justification": "Primary data fiduciary role for AI memory workloads.",
            },
        )
        assert patch_res.status_code == 200
        assert patch_res.json()["decision"] == "APPLICABLE"

        # Get gaps
        gap_res = await client.get("/v1/compliance/gaps", headers=headers)
        assert gap_res.status_code == 200
        gaps = gap_res.json()
        assert "total_gaps" in gaps

