"""Enterprise Role-Based and Attribute-Based Access Control (RBAC/ABAC)."""

from enum import Enum
from typing import Set, List, Optional
from fastapi import HTTPException, status, Depends

from app.core.exceptions import AuthorizationError
from app.core.tenant import TenantContext, resolve_tenant_context


class EnterpriseRole(str, Enum):
    ORGANIZATION_OWNER = "ORGANIZATION_OWNER"
    SECURITY_ADMIN = "SECURITY_ADMIN"
    POLICY_ADMIN = "POLICY_ADMIN"
    FLEET_ADMIN = "FLEET_ADMIN"
    DEVELOPER = "DEVELOPER"
    AGENT_OPERATOR = "AGENT_OPERATOR"
    AUDITOR = "AUDITOR"
    VIEWER = "VIEWER"


class Permission(str, Enum):
    # Organization Management
    ORG_MANAGE = "org:manage"
    ORG_SSO_MANAGE = "org:sso:manage"
    ORG_MEMBERS_MANAGE = "org:members:manage"
    ORG_READ = "org:read"

    # Workspace Management
    WORKSPACE_MANAGE = "workspace:manage"
    WORKSPACE_READ = "workspace:read"

    # Policy Governance
    POLICY_DRAFT = "policy:draft"
    POLICY_VALIDATE = "policy:validate"
    POLICY_APPROVE = "policy:approve"
    POLICY_DEPLOY = "policy:deploy"
    POLICY_READ = "policy:read"

    # Fleet Management
    FLEET_REGISTER = "fleet:register"
    FLEET_REVOKE = "fleet:revoke"
    FLEET_SYNC = "fleet:sync"
    FLEET_READ = "fleet:read"

    # Agent & Tool Operations
    AGENT_RUN = "agent:run"
    TOOL_EXECUTE = "tool:execute"
    APPROVAL_DECIDE = "approval:decide"

    # Audit & SIEM
    AUDIT_READ = "audit:read"
    AUDIT_EXPORT = "audit:export"

    # Security & Threats
    THREAT_READ = "threat:read"
    THREAT_RESPOND = "threat:respond"


# Authoritative Enterprise Role-to-Permissions Mapping
ROLE_PERMISSIONS: dict[str, Set[str]] = {
    EnterpriseRole.ORGANIZATION_OWNER.value: {
        Permission.ORG_MANAGE.value,
        Permission.ORG_SSO_MANAGE.value,
        Permission.ORG_MEMBERS_MANAGE.value,
        Permission.ORG_READ.value,
        Permission.WORKSPACE_MANAGE.value,
        Permission.WORKSPACE_READ.value,
        Permission.POLICY_DRAFT.value,
        Permission.POLICY_VALIDATE.value,
        Permission.POLICY_APPROVE.value,
        Permission.POLICY_DEPLOY.value,
        Permission.POLICY_READ.value,
        Permission.FLEET_REGISTER.value,
        Permission.FLEET_REVOKE.value,
        Permission.FLEET_SYNC.value,
        Permission.FLEET_READ.value,
        Permission.AGENT_RUN.value,
        Permission.TOOL_EXECUTE.value,
        Permission.APPROVAL_DECIDE.value,
        Permission.AUDIT_READ.value,
        Permission.AUDIT_EXPORT.value,
        Permission.THREAT_READ.value,
        Permission.THREAT_RESPOND.value,
    },
    EnterpriseRole.SECURITY_ADMIN.value: {
        Permission.ORG_READ.value,
        Permission.WORKSPACE_READ.value,
        Permission.POLICY_VALIDATE.value,
        Permission.POLICY_APPROVE.value,
        Permission.POLICY_READ.value,
        Permission.FLEET_REVOKE.value,
        Permission.FLEET_READ.value,
        Permission.APPROVAL_DECIDE.value,
        Permission.AUDIT_READ.value,
        Permission.AUDIT_EXPORT.value,
        Permission.THREAT_READ.value,
        Permission.THREAT_RESPOND.value,
    },
    EnterpriseRole.POLICY_ADMIN.value: {
        Permission.ORG_READ.value,
        Permission.WORKSPACE_READ.value,
        Permission.POLICY_DRAFT.value,
        Permission.POLICY_VALIDATE.value,
        Permission.POLICY_APPROVE.value,
        Permission.POLICY_DEPLOY.value,
        Permission.POLICY_READ.value,
        Permission.FLEET_READ.value,
        Permission.AUDIT_READ.value,
    },
    EnterpriseRole.FLEET_ADMIN.value: {
        Permission.ORG_READ.value,
        Permission.WORKSPACE_MANAGE.value,
        Permission.WORKSPACE_READ.value,
        Permission.FLEET_REGISTER.value,
        Permission.FLEET_REVOKE.value,
        Permission.FLEET_SYNC.value,
        Permission.FLEET_READ.value,
        Permission.AUDIT_READ.value,
    },
    EnterpriseRole.DEVELOPER.value: {
        Permission.ORG_READ.value,
        Permission.WORKSPACE_READ.value,
        Permission.FLEET_READ.value,
        Permission.AGENT_RUN.value,
        Permission.TOOL_EXECUTE.value,
        Permission.POLICY_READ.value,
        Permission.AUDIT_READ.value,
    },
    EnterpriseRole.AGENT_OPERATOR.value: {
        Permission.ORG_READ.value,
        Permission.WORKSPACE_READ.value,
        Permission.FLEET_READ.value,
        Permission.AGENT_RUN.value,
        Permission.APPROVAL_DECIDE.value,
        Permission.AUDIT_READ.value,
    },
    EnterpriseRole.AUDITOR.value: {
        Permission.ORG_READ.value,
        Permission.WORKSPACE_READ.value,
        Permission.POLICY_READ.value,
        Permission.FLEET_READ.value,
        Permission.AUDIT_READ.value,
        Permission.AUDIT_EXPORT.value,
        Permission.THREAT_READ.value,
    },
    EnterpriseRole.VIEWER.value: {
        Permission.ORG_READ.value,
        Permission.WORKSPACE_READ.value,
        Permission.FLEET_READ.value,
        Permission.POLICY_READ.value,
        Permission.AUDIT_READ.value,
    },
}


# Immutable platform guardrails that CANNOT be disabled by any tenant or role
IMMUTABLE_PLATFORM_GUARDRAILS = {
    "SECRET_LEAKAGE_PREVENTION": "Critical system secrets (AWS, OpenAI, Anthropic, private keys) are unconditionally blocked.",
    "SSRF_LOOPBACK_PREVENTION": "Requests to 127.0.0.1, localhost, 169.254.169.254 are unconditionally blocked.",
    "IMMUTABLE_HASH_AUDIT": "Hash-chained audit events cannot be modified or truncated.",
}


class RBACAuthorizer:
    """Enforces role-based and attribute-based permissions across enterprise APIs."""

    @staticmethod
    def has_permission(role: str, permission: str) -> bool:
        """Checks if a given role possesses a specific permission."""
        perms = ROLE_PERMISSIONS.get(role, set())
        return permission in perms

    @staticmethod
    def enforce_permission(context: TenantContext, permission: str) -> None:
        """Raises AuthorizationError if the tenant context lacks the required permission."""
        if "*" in context.permissions:
            return

        if not RBACAuthorizer.has_permission(context.role, permission):
            raise AuthorizationError(
                f"Forbidden: Role '{context.role}' does not possess required permission '{permission}'."
            )

    @staticmethod
    def enforce_platform_immutability(rule_target: str, action: str) -> None:
        """
        Enforces that organizational administrators cannot weaken immutable platform guardrails.
        Core Decision: Enterprise administrators must not have unlimited power.
        """
        target_normalized = rule_target.upper().strip()
        action_normalized = action.upper().strip()

        # If an admin attempts to ALLOW or DISABLE rules protecting system secrets or SSRF
        if target_normalized in ("ALL_SECRETS", "SSRF_LOOPBACK", "SYSTEM_CREDENTIALS", "LOCAL_NETWORK"):
            if action_normalized in ("ALLOW", "DISABLE", "IGNORE", "NONE"):
                raise AuthorizationError(
                    f"Platform Security Violation: Platform guardrail '{target_normalized}' is immutable "
                    f"and cannot be relaxed by organization administrators."
                )


def require_permission(permission: str):
    """FastAPI dependency to require a specific permission."""
    async def _dependency(ctx: TenantContext = Depends(resolve_tenant_context)):
        RBACAuthorizer.enforce_permission(ctx, permission)
        return ctx
    return _dependency

