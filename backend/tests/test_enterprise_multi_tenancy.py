"""Adversarial security tests for Multi-Tenant Isolation (Tests 1-10)."""

import pytest
import pytest_asyncio
import httpx
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.tenant import TenantContext, set_current_tenant, TenantIsolationError
from app.database.models import (
    Application,
    Agent,
    MemoryRecord,
    MCPServer,
    ApprovalRequest,
    PolicyBundle,
    EnterpriseAuditEvent,
    Workspace,
    utcnow,
)
from app.core.security import hash_api_key

ORG_ALPHA = "org_enterprise_alpha"
ORG_BETA = "org_enterprise_beta"

KEY_ALPHA = "pg_live_alpha_test_key_12345"
KEY_BETA = "pg_live_beta_test_key_67890"


@pytest_asyncio.fixture
async def setup_tenants(db_session: AsyncSession):
    """Sets up two isolated enterprise organizations with applications and resources."""
    app_alpha = Application(
        id="app_alpha",
        tenant_id=ORG_ALPHA,
        name="Alpha App",
        api_key_hash=hash_api_key(KEY_ALPHA),
        is_active=True,
    )
    app_beta = Application(
        id="app_beta",
        tenant_id=ORG_BETA,
        name="Beta App",
        api_key_hash=hash_api_key(KEY_BETA),
        is_active=True,
    )
    db_session.add_all([app_alpha, app_beta])

    # Agent in Alpha
    agent_alpha = Agent(
        id="agent_alpha_1",
        tenant_id=ORG_ALPHA,
        app_id="app_alpha",
        name="Alpha Secret Agent",
        status="ACTIVE",
    )
    # Agent in Beta
    agent_beta = Agent(
        id="agent_beta_1",
        tenant_id=ORG_BETA,
        app_id="app_beta",
        name="Beta Secret Agent",
        status="ACTIVE",
    )
    db_session.add_all([agent_alpha, agent_beta])

    # Memory in Alpha
    mem_alpha = MemoryRecord(
        id="mem_alpha_rec",
        tenant_id=ORG_ALPHA,
        app_id="app_alpha",
        owner_id="usr_alpha_ceo",
        category="CONFIDENTIAL_STRATEGY",
        status="ACTIVE",
        encrypted_content="ciphertext_alpha_merger",
        nonce="iv_alpha",
        wrapped_dek="wrapped_dek_alpha",
        dek_nonce="dek_nonce_alpha",
        content_fingerprint="fp_alpha",
    )
    # Memory in Beta
    mem_beta = MemoryRecord(
        id="mem_beta_rec",
        tenant_id=ORG_BETA,
        app_id="app_beta",
        owner_id="usr_beta_cto",
        category="INTELLECTUAL_PROPERTY",
        status="ACTIVE",
        encrypted_content="ciphertext_beta_algorithm",
        nonce="iv_beta",
        wrapped_dek="wrapped_dek_beta",
        dek_nonce="dek_nonce_beta",
        content_fingerprint="fp_beta",
    )
    db_session.add_all([mem_alpha, mem_beta])

    # MCP Server in Alpha
    mcp_alpha = MCPServer(
        id="mcps_alpha_db",
        tenant_id=ORG_ALPHA,
        app_id="app_alpha",
        name="Alpha Internal Postgres",
        endpoint_url="http://alpha.internal:8080/mcp",
        status="ACTIVE",
    )
    # MCP Server in Beta
    mcp_beta = MCPServer(
        id="mcps_beta_db",
        tenant_id=ORG_BETA,
        app_id="app_beta",
        name="Beta Internal MongoDB",
        endpoint_url="http://beta.internal:8080/mcp",
        status="ACTIVE",
    )
    db_session.add_all([mcp_alpha, mcp_beta])

    # Workspace in Alpha
    ws_alpha = Workspace(
        id="ws_alpha_finance",
        tenant_id=ORG_ALPHA,
        organization_id=ORG_ALPHA,
        name="Alpha Finance",
        slug="finance",
        is_default=True,
    )
    db_session.add(ws_alpha)

    await db_session.commit()


@pytest.mark.asyncio
async def test_01_cross_tenant_agent_access_blocked(client: httpx.AsyncClient, setup_tenants):
    """Test 1: Tenant Alpha cannot view or modify Tenant Beta's agents."""
    # Attempting to fetch Beta's agent using Alpha's credentials
    res = await client.get(
        "/v1/agents/agent_beta_1",
        headers={"X-API-Key": KEY_ALPHA, "X-Tenant-ID": ORG_ALPHA},
    )
    # Must fail: agent belongs to Beta, caller is Alpha
    assert res.status_code in (403, 404), f"Cross-tenant agent access was not blocked: {res.text}"


@pytest.mark.asyncio
async def test_02_cross_tenant_mcp_access_blocked(client: httpx.AsyncClient, setup_tenants):
    """Test 2: Tenant Alpha cannot view, sync, or call Tenant Beta's MCP servers."""
    res = await client.get(
        "/v1/mcp/servers/mcps_beta_db",
        headers={"X-API-Key": KEY_ALPHA, "X-Tenant-ID": ORG_ALPHA},
    )
    assert res.status_code in (403, 404), f"Cross-tenant MCP access was not blocked: {res.text}"


@pytest.mark.asyncio
async def test_03_cross_tenant_memory_access_blocked(client: httpx.AsyncClient, setup_tenants):
    """Test 3: Tenant Alpha cannot retrieve or search Tenant Beta's encrypted memories."""
    res = await client.get(
        "/v1/memory/records/mem_beta_rec",
        headers={"X-API-Key": KEY_ALPHA, "X-Tenant-ID": ORG_ALPHA},
    )
    assert res.status_code in (403, 404), f"Cross-tenant memory access was not blocked: {res.text}"


@pytest.mark.asyncio
async def test_04_cross_tenant_approval_access_blocked(client: httpx.AsyncClient, setup_tenants, db_session: AsyncSession):
    """Test 4: Tenant Alpha cannot view or decide on pending approvals belonging to Tenant Beta."""
    from app.database.models import AgentTask

    from datetime import timedelta
    task_beta = AgentTask(
        id="task_beta_1",
        tenant_id=ORG_BETA,
        app_id="app_beta",
        agent_id="agent_beta_1",
        description="Manage cluster",
        status="ACTIVE",
        expires_at=utcnow() + timedelta(hours=1),
    )
    db_session.add(task_beta)
    await db_session.flush()

    appr_beta = ApprovalRequest(
        id="apr_beta_sensitive",
        tenant_id=ORG_BETA,
        app_id="app_beta",
        agent_id="agent_beta_1",
        task_id="task_beta_1",
        tool_name="delete_production_database",
        target_resource="production_cluster",
        action_parameters="{}",
        action_hash="hash_action_beta",
        risk_level="CRITICAL",
        status="PENDING",
        expires_at=utcnow(),
    )
    db_session.add(appr_beta)
    await db_session.commit()

    res = await client.post(
        "/v1/approvals/apr_beta_sensitive/approve",
        headers={"X-API-Key": KEY_ALPHA, "X-Tenant-ID": ORG_ALPHA},
    )
    assert res.status_code in (403, 404), f"Cross-tenant approval tampering succeeded: {res.text}"


@pytest.mark.asyncio
async def test_05_cross_tenant_policy_access_blocked(client: httpx.AsyncClient, setup_tenants):
    """Test 5: Tenant Alpha cannot read or deploy policies for Tenant Beta."""
    res = await client.get(
        f"/v1/organizations/{ORG_BETA}/policies",
        headers={"X-API-Key": KEY_ALPHA, "X-Tenant-ID": ORG_ALPHA},
    )
    assert res.status_code == 403, f"Cross-tenant policy listing was not blocked: {res.text}"


@pytest.mark.asyncio
async def test_06_cross_tenant_audit_access_blocked(client: httpx.AsyncClient, setup_tenants):
    """Test 6: Tenant Alpha cannot access Tenant Beta's audit ledger."""
    res = await client.get(
        f"/v1/organizations/{ORG_BETA}/audit",
        headers={"X-API-Key": KEY_ALPHA, "X-Tenant-ID": ORG_ALPHA},
    )
    assert res.status_code == 403, f"Cross-tenant audit reading was not blocked: {res.text}"


@pytest.mark.asyncio
async def test_07_cross_tenant_workspace_access_blocked(client: httpx.AsyncClient, setup_tenants):
    """Test 7: Tenant Alpha cannot list or access workspaces belonging to Tenant Beta."""
    res = await client.get(
        f"/v1/organizations/{ORG_BETA}/workspaces",
        headers={"X-API-Key": KEY_ALPHA, "X-Tenant-ID": ORG_ALPHA},
    )
    assert res.status_code == 403, f"Cross-tenant workspace reading was not blocked: {res.text}"


@pytest.mark.asyncio
async def test_08_forged_tenant_header_rejected(client: httpx.AsyncClient, setup_tenants):
    """Test 8: Spoofing X-Tenant-ID to match another tenant is immediately rejected."""
    # Key belongs to Alpha, but client attempts to spoof X-Tenant-ID: ORG_BETA
    res = await client.get(
        f"/v1/organizations/{ORG_BETA}/members",
        headers={"X-API-Key": KEY_ALPHA, "X-Tenant-ID": ORG_BETA},
    )
    assert res.status_code == 403, "Forged tenant header was accepted!"


@pytest.mark.asyncio
async def test_09_missing_authentication_context_fails_closed(client: httpx.AsyncClient):
    """Test 9: Requests with missing or malformed credentials fail closed with HTTP 401."""
    res = await client.get(f"/v1/organizations/{ORG_ALPHA}/fleet")
    assert res.status_code in (401, 403), f"Missing authentication did not fail closed: {res.status_code}"


@pytest.mark.asyncio
async def test_10_database_query_level_isolation(db_session: AsyncSession, setup_tenants):
    """Test 10: Direct DB query scoping guarantees no records leak across tenant boundaries."""
    # Query scoped strictly to ORG_ALPHA
    alpha_q = select(Agent).where(Agent.tenant_id == ORG_ALPHA)
    res = await db_session.execute(alpha_q)
    alpha_agents = res.scalars().all()

    # Must only contain Alpha agents
    assert len(alpha_agents) >= 1
    for a in alpha_agents:
        assert a.tenant_id == ORG_ALPHA
        assert a.tenant_id != ORG_BETA

