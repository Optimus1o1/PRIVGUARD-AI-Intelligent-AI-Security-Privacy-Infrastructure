"""Adversarial security tests for Identity, SSO, SCIM, and RBAC (Tests 11-23)."""

import time
import pytest
import pytest_asyncio
import httpx
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.exceptions import AuthenticationError, AuthorizationError
from app.database.models import Organization, OrganizationMembership, Application, utcnow
from app.enterprise.identity import EnterpriseIdentityManager, SSOConfig
from app.enterprise.scim import SCIMService, SCIMUserPayload, SCIMRole
from app.enterprise.rbac import EnterpriseRole, Permission, RBACAuthorizer, ROLE_PERMISSIONS
from app.core.tenant import TenantContext, set_current_tenant

ORG_TEST = "org_identity_rbac_test"


@pytest_asyncio.fixture
async def setup_rbac_org(db_session: AsyncSession):
    """Sets up an organization with members in different roles."""
    org = Organization(
        id=ORG_TEST,
        slug="identity-rbac-test",
        name="Identity RBAC Test Org",
        domain="acmetest.org",
        domain_verified=True,
        status="ACTIVE",
    )
    db_session.add(org)

    # Owner
    owner = OrganizationMembership(
        id="mem_owner",
        organization_id=ORG_TEST,
        user_id="usr_owner",
        email="owner@acmetest.org",
        role="ORGANIZATION_OWNER",
        status="ACTIVE",
    )
    # Developer
    dev = OrganizationMembership(
        id="mem_dev",
        organization_id=ORG_TEST,
        user_id="usr_dev",
        email="dev@acmetest.org",
        role="DEVELOPER",
        status="ACTIVE",
    )
    # Auditor
    auditor = OrganizationMembership(
        id="mem_auditor",
        organization_id=ORG_TEST,
        user_id="usr_auditor",
        email="auditor@acmetest.org",
        role="AUDITOR",
        status="ACTIVE",
    )
    # Viewer
    viewer = OrganizationMembership(
        id="mem_viewer",
        organization_id=ORG_TEST,
        user_id="usr_viewer",
        email="viewer@acmetest.org",
        role="VIEWER",
        status="ACTIVE",
    )
    # Suspended member
    suspended = OrganizationMembership(
        id="mem_suspended",
        organization_id=ORG_TEST,
        user_id="usr_suspended",
        email="suspended@acmetest.org",
        role="DEVELOPER",
        status="SUSPENDED",
    )
    db_session.add_all([owner, dev, auditor, viewer, suspended])
    await db_session.commit()


def test_14_sso_issuer_mismatch():
    """Test 14: OIDC/SAML token with untrusted issuer is rejected."""
    config = SSOConfig(
        issuer="https://idp.okta.com/acme",
        client_id="privguard-client-123",
        redirect_uri="https://privguard.internal/sso/callback",
    )
    claims = {
        "iss": "https://malicious-idp.evil.com",
        "aud": "privguard-client-123",
        "sub": "user_123",
        "email": "user@acmetest.org",
    }
    with pytest.raises(AuthenticationError, match="Issuer mismatch"):
        EnterpriseIdentityManager.validate_sso_token(claims, config)


def test_15_sso_audience_mismatch():
    """Test 15: OIDC/SAML token targeted at another client is rejected."""
    config = SSOConfig(
        issuer="https://idp.okta.com/acme",
        client_id="privguard-client-123",
        redirect_uri="https://privguard.internal/sso/callback",
    )
    claims = {
        "iss": "https://idp.okta.com/acme",
        "aud": "attacker-client-999",
        "sub": "user_123",
        "email": "user@acmetest.org",
    }
    with pytest.raises(AuthenticationError, match="Audience mismatch"):
        EnterpriseIdentityManager.validate_sso_token(claims, config)


def test_16_sso_token_expired():
    """Test 16: Expired SSO tokens fail closed."""
    config = SSOConfig(
        issuer="https://idp.okta.com/acme",
        client_id="privguard-client-123",
        redirect_uri="https://privguard.internal/sso/callback",
    )
    claims = {
        "iss": "https://idp.okta.com/acme",
        "aud": "privguard-client-123",
        "sub": "user_123",
        "email": "user@acmetest.org",
        "exp": int(time.time()) - 600,  # 10 minutes ago
    }
    with pytest.raises(AuthenticationError, match="Token expired"):
        EnterpriseIdentityManager.validate_sso_token(claims, config)


@pytest.mark.asyncio
async def test_17_scim_deprovisioning_immediate_revocation(db_session: AsyncSession, setup_rbac_org):
    """Test 17: SCIM deprovisioning immediately terminates access and marks member DEPROVISIONED."""
    # Deprovision developer
    await SCIMService.deprovision_user(db_session, ORG_TEST, "usr_dev")

    q = select(OrganizationMembership).where(
        OrganizationMembership.organization_id == ORG_TEST,
        OrganizationMembership.user_id == "usr_dev",
    )
    res = await db_session.execute(q)
    mem = res.scalar_one_or_none()
    assert mem is not None
    assert mem.status == "DEPROVISIONED"


@pytest.mark.asyncio
async def test_18_suspended_member_access_blocked(client: httpx.AsyncClient, setup_rbac_org):
    """Test 18: Suspended member is blocked from calling APIs."""
    res = await client.get(
        f"/v1/organizations/{ORG_TEST}/fleet",
        headers={"X-API-Key": "usr_suspended", "X-Tenant-ID": ORG_TEST},
    )
    assert res.status_code in (401, 403), f"Suspended member accessed API: {res.status_code}"


def test_19_viewer_attempts_administrative_changes():
    """Test 19: Viewer role is denied permission to manage members or deploy policies."""
    ctx = TenantContext(
        tenant_id=ORG_TEST,
        organization_id=ORG_TEST,
        user_id="usr_viewer",
        role="VIEWER",
    )
    with pytest.raises(AuthorizationError):
        RBACAuthorizer.enforce_permission(ctx, Permission.ORG_MEMBERS_MANAGE.value)

    with pytest.raises(AuthorizationError):
        RBACAuthorizer.enforce_permission(ctx, Permission.POLICY_DEPLOY.value)


def test_20_developer_attempts_policy_publication():
    """Test 20: Developer role cannot approve or deploy enterprise security policies."""
    ctx = TenantContext(
        tenant_id=ORG_TEST,
        organization_id=ORG_TEST,
        user_id="usr_dev",
        role="DEVELOPER",
    )
    with pytest.raises(AuthorizationError):
        RBACAuthorizer.enforce_permission(ctx, Permission.POLICY_DEPLOY.value)

    with pytest.raises(AuthorizationError):
        RBACAuthorizer.enforce_permission(ctx, Permission.POLICY_APPROVE.value)


def test_21_auditor_attempts_tool_execution():
    """Test 21: Auditor role has read-only access and cannot execute tools."""
    ctx = TenantContext(
        tenant_id=ORG_TEST,
        organization_id=ORG_TEST,
        user_id="usr_auditor",
        role="AUDITOR",
    )
    with pytest.raises(AuthorizationError):
        RBACAuthorizer.enforce_permission(ctx, Permission.TOOL_EXECUTE.value)

    with pytest.raises(AuthorizationError):
        RBACAuthorizer.enforce_permission(ctx, Permission.AGENT_RUN.value)


def test_22_rbac_matrix_integrity():
    """Test 22: Enforces complete role-to-permission mapping for all 8 defined roles."""
    expected_roles = {
        "ORGANIZATION_OWNER",
        "SECURITY_ADMIN",
        "POLICY_ADMIN",
        "FLEET_ADMIN",
        "DEVELOPER",
        "AGENT_OPERATOR",
        "AUDITOR",
        "VIEWER",
    }
    for r in expected_roles:
        assert r in ROLE_PERMISSIONS, f"Role '{r}' is missing from ROLE_PERMISSIONS"
        perms = ROLE_PERMISSIONS[r]
        assert len(perms) > 0, f"Role '{r}' has empty permissions"


def test_23_separation_of_duties_immutability():
    """Test 23: Security Admin cannot unilaterally manage SSO settings without Organization Owner permission."""
    sec_admin_perms = ROLE_PERMISSIONS[EnterpriseRole.SECURITY_ADMIN.value]
    assert Permission.ORG_SSO_MANAGE.value not in sec_admin_perms

