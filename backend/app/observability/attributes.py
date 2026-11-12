"""PRIVGUARD AI - Safe OpenTelemetry Attribute Definitions & Strict Blocklists.
Enforces explicit allowlists and data minimization across all distributed traces.
"""

from typing import Set

# ==============================================================================
# 1. Standard Safe Semantic Conventions
# ==============================================================================
HTTP_METHOD = "http.method"
HTTP_ROUTE = "http.route"
HTTP_STATUS_CODE = "http.status_code"
HTTP_STATUS_CLASS = "http.status_class"
HTTP_CLIENT_IP_TYPE = "http.client_ip_type"  # e.g., "internal", "loopback", "external"

DB_SYSTEM = "db.system"
DB_OPERATION = "db.operation"
DB_TABLE = "db.table"

RPC_SYSTEM = "rpc.system"
RPC_SERVICE = "rpc.service"
RPC_METHOD = "rpc.method"

# PRIVGUARD Specific Operational Dimensions (Bounded Cardinality)
PRIVGUARD_OPERATION = "privguard.operation"
PRIVGUARD_STATUS = "privguard.status"
PRIVGUARD_DECISION = "privguard.decision"
PRIVGUARD_RISK_LEVEL = "privguard.risk_level"
PRIVGUARD_THREAT_CATEGORY = "privguard.threat_category"
PRIVGUARD_DATA_CATEGORY = "privguard.data_category"
PRIVGUARD_TOOL_NAME = "privguard.tool_name"
PRIVGUARD_MCP_SERVER_TYPE = "privguard.mcp_server_type"
PRIVGUARD_KMS_PROVIDER = "privguard.kms_provider"
PRIVGUARD_KMS_OPERATION = "privguard.kms_operation"
PRIVGUARD_REQUEST_ID = "privguard.request_id"

# ==============================================================================
# 2. Explicit Attribute Allowlist
# ==============================================================================
# Only attributes appearing in this allowlist or prefixed with safe namespace are exported
SAFE_ATTRIBUTE_ALLOWLIST: Set[str] = {
    HTTP_METHOD,
    HTTP_ROUTE,
    HTTP_STATUS_CODE,
    HTTP_STATUS_CLASS,
    HTTP_CLIENT_IP_TYPE,
    DB_SYSTEM,
    DB_OPERATION,
    DB_TABLE,
    RPC_SYSTEM,
    RPC_SERVICE,
    RPC_METHOD,
    PRIVGUARD_OPERATION,
    PRIVGUARD_STATUS,
    PRIVGUARD_DECISION,
    PRIVGUARD_RISK_LEVEL,
    PRIVGUARD_THREAT_CATEGORY,
    PRIVGUARD_DATA_CATEGORY,
    PRIVGUARD_TOOL_NAME,
    PRIVGUARD_MCP_SERVER_TYPE,
    PRIVGUARD_KMS_PROVIDER,
    PRIVGUARD_KMS_OPERATION,
    PRIVGUARD_REQUEST_ID,
    "service.name",
    "service.version",
    "deployment.environment",
}

# ==============================================================================
# 3. Prohibited Attribute Substring & Name Patterns
# ==============================================================================
# Any attribute whose key contains any of these substrings is unconditionally rejected
PROHIBITED_KEY_PATTERNS: Set[str] = {
    "prompt",
    "completion",
    "message",
    "content",
    "memory",
    "payload",
    "secret",
    "password",
    "token",
    "api_key",
    "apikey",
    "key_material",
    "credential",
    "authorization",
    "cookie",
    "email",
    "user_id",
    "agent_id",
    "tenant_id",
    "task_id",
    "sql_statement",
    "query_params",
}


class SemanticAttributes:
    """Namespace grouping safe OpenTelemetry attribute keys."""

    HTTP_METHOD = HTTP_METHOD
    HTTP_ROUTE = HTTP_ROUTE
    HTTP_STATUS_CODE = HTTP_STATUS_CODE
    HTTP_STATUS_CLASS = HTTP_STATUS_CLASS
    HTTP_CLIENT_IP_TYPE = HTTP_CLIENT_IP_TYPE

    DB_SYSTEM = DB_SYSTEM
    DB_OPERATION = DB_OPERATION
    DB_TABLE = DB_TABLE

    RPC_SYSTEM = RPC_SYSTEM
    RPC_SERVICE = RPC_SERVICE
    RPC_METHOD = RPC_METHOD

    PRIVGUARD_OPERATION = PRIVGUARD_OPERATION
    PRIVGUARD_STATUS = PRIVGUARD_STATUS
    PRIVGUARD_DECISION = PRIVGUARD_DECISION
    PRIVGUARD_RISK_LEVEL = PRIVGUARD_RISK_LEVEL
    PRIVGUARD_THREAT_CATEGORY = PRIVGUARD_THREAT_CATEGORY
    PRIVGUARD_DATA_CATEGORY = PRIVGUARD_DATA_CATEGORY
    PRIVGUARD_TOOL_NAME = PRIVGUARD_TOOL_NAME
    PRIVGUARD_MCP_SERVER_TYPE = PRIVGUARD_MCP_SERVER_TYPE
    PRIVGUARD_KMS_PROVIDER = PRIVGUARD_KMS_PROVIDER
    PRIVGUARD_KMS_OPERATION = PRIVGUARD_KMS_OPERATION
    PRIVGUARD_REQUEST_ID = PRIVGUARD_REQUEST_ID
