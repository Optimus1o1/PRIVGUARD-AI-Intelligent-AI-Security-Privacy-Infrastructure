"""Resource namespaces for PRIVGUARD SDK."""

from privguard_sdk.resources.agents import AgentsResource, AsyncAgentsResource
from privguard_sdk.resources.approvals import ApprovalsResource, AsyncApprovalsResource
from privguard_sdk.resources.audit import AsyncAuditResource, AuditResource
from privguard_sdk.resources.capabilities import AsyncCapabilitiesResource, CapabilitiesResource
from privguard_sdk.resources.compliance import AsyncComplianceResource, ComplianceResource
from privguard_sdk.resources.gateway import AsyncGatewayResource, GatewayResource
from privguard_sdk.resources.health import AsyncHealthResource, HealthResource
from privguard_sdk.resources.memory import AsyncMemoryResource, MemoryResource
from privguard_sdk.resources.privacy import AsyncPrivacyResource, PrivacyResource
from privguard_sdk.resources.tasks import AsyncTasksResource, TasksResource
from privguard_sdk.resources.threats import AsyncThreatsResource, ThreatsResource
from privguard_sdk.resources.tools import AsyncToolsResource, ToolsResource

__all__ = [
    "AgentsResource",
    "ApprovalsResource",
    "AsyncAgentsResource",
    "AsyncApprovalsResource",
    "AsyncAuditResource",
    "AsyncCapabilitiesResource",
    "AsyncComplianceResource",
    "AsyncGatewayResource",
    "AsyncHealthResource",
    "AsyncMemoryResource",
    "AsyncPrivacyResource",
    "AsyncTasksResource",
    "AsyncThreatsResource",
    "AsyncToolsResource",
    "AuditResource",
    "CapabilitiesResource",
    "ComplianceResource",
    "GatewayResource",
    "HealthResource",
    "MemoryResource",
    "PrivacyResource",
    "TasksResource",
    "ThreatsResource",
    "ToolsResource",
]
