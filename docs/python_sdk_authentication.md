# PRIVGUARD AI — Python SDK Authentication & Multi-Tenancy

**Organization**: Moon Sanctum Labs  
**Motto**: Decode. Build. Evolve.  
**Package**: `privguard-sdk` (import: `privguard_sdk`)  
**Specification Version**: 1.0.0 (SDK Version: 0.1.0)  

---

## 1. Authentication Architecture

PRIVGUARD AI uses cryptographic API keys for authenticating API requests. The Python SDK transparently manages token injection, multi-tenant context propagation, and secure header construction.

### Header Construction

When an API key is provided, the SDK injects an HTTP `Authorization` header on every outbound request:

```http
Authorization: Bearer <api_key>
```

If tenant, user, or workspace contexts are configured, they are passed as routing headers:

```http
X-Tenant-ID: <tenant_id>
X-User-ID: <user_id>
X-Workspace-ID: <workspace_id>
```

---

## 2. Configuration Precedence

`PrivGuardConfig` evaluates settings in the following strict order of precedence:

1. **Explicit Parameter Value**: Arguments explicitly passed to `PrivGuardConfig(...)` or `PrivGuardClient(...)`.
2. **Environment Variable**: System environment variables if parameters are omitted or `None`.
3. **Internal Default**: Built-in safe fallbacks (e.g., base URL `http://localhost:8000`, 3 retries, SSL verification enabled).

### Supported Environment Variables

| Variable | Description | Default |
| :--- | :--- | :--- |
| `PRIVGUARD_BASE_URL` | Base URL of the PRIVGUARD AI service | `http://localhost:8000` |
| `PRIVGUARD_API_KEY` | Secret API key used for Bearer authentication | `None` |
| `PRIVGUARD_TENANT_ID` | Multi-tenant tenant identifier | `None` |
| `PRIVGUARD_USER_ID` | Originating end-user identifier | `None` |
| `PRIVGUARD_WORKSPACE_ID` | Workspace or department identifier | `None` |

---

## 3. Usage Examples

### Direct Client Initialization

```python
from privguard_sdk import PrivGuardClient

# Direct initialization with explicit parameters
client = PrivGuardClient(
    base_url="https://privguard.internal.company.com",
    api_key="sk-live-9f823a4b...",
    tenant_id="enterprise-org-01",
    user_id="usr_83726",
    workspace_id="ws_finance_prod",
    timeout=15.0,
    max_retries=3,
    verify_ssl=True,
)
```

### Environment Variable Initialization

```python
import os
from privguard_sdk import PrivGuardClient

# Configuration loaded automatically from environment variables
os.environ["PRIVGUARD_BASE_URL"] = "https://privguard.internal.company.com"
os.environ["PRIVGUARD_API_KEY"] = "sk-live-9f823a4b..."
os.environ["PRIVGUARD_TENANT_ID"] = "enterprise-org-01"

client = PrivGuardClient()
```

### Dynamic Multi-Tenant Context Switching

For applications serving multiple organizations through a single process or pool:

```python
from privguard_sdk import PrivGuardClient, PrivGuardConfig

base_config = PrivGuardConfig(
    base_url="https://privguard.internal.company.com",
    api_key=os.environ["SERVICE_ACCOUNT_API_KEY"],
)

# Spawn isolated client instances per tenant request
def get_tenant_client(tenant_id: str, user_id: str) -> PrivGuardClient:
    tenant_config = PrivGuardConfig(
        base_url=base_config.base_url,
        api_key=base_config.api_key,
        tenant_id=tenant_id,
        user_id=user_id,
    )
    return PrivGuardClient(config=tenant_config)
```

---

## 4. Integration with Enterprise Secret Managers

In production deployments, never store API keys in plain text files or source code repositories. Retrieve credentials from enterprise secrets managers at application bootstrap:

### AWS Secrets Manager Example

```python
import json
import boto3
from privguard_sdk import PrivGuardClient

def create_privguard_client_from_aws() -> PrivGuardClient:
    client = boto3.client("secretsmanager", region_name="us-east-1")
    response = client.get_secret_value(SecretId="privguard/production/credentials")
    secret = json.loads(response["SecretString"])
    
    return PrivGuardClient(
        base_url=secret["BASE_URL"],
        api_key=secret["API_KEY"],
        tenant_id=secret.get("TENANT_ID"),
    )
```

### GCP Secret Manager Example

```python
from google.cloud import secretmanager
from privguard_sdk import PrivGuardClient

def create_privguard_client_from_gcp(project_id: str) -> PrivGuardClient:
    client = secretmanager.SecretManagerServiceClient()
    name = f"projects/{project_id}/secrets/privguard-api-key/versions/latest"
    response = client.access_secret_version(request={"name": name})
    api_key = response.payload.data.decode("UTF-8")
    
    return PrivGuardClient(
        base_url="https://privguard.internal.company.com",
        api_key=api_key,
    )
```

### HashiCorp Vault Example

```python
import hvac
from privguard_sdk import PrivGuardClient

def create_privguard_client_from_vault() -> PrivGuardClient:
    client = hvac.Client(url="https://vault.internal.company.com")
    # Authenticate via Kubernetes or AppRole
    read_secret = client.secrets.kv.v2.read_secret_version(path="privguard/prod")
    data = read_secret["data"]["data"]
    
    return PrivGuardClient(
        base_url=data["base_url"],
        api_key=data["api_key"],
        tenant_id=data.get("tenant_id"),
    )
```

---

## 5. Security & Redaction Safeguards

1. **String Representation Masking**:  
   Both `PrivGuardConfig` and `PrivGuardClient` implement a secure `__repr__()` that masks API keys. Keys longer than 8 characters expose only the first 4 and last 4 characters separated by ellipses (e.g. `'sk-t...7890'`). Keys of 8 characters or fewer are completely obscured with asterisks (`'***'`).
2. **Crash & Logging Protection**:  
   Exceptions raised by the transport layer never include raw authorization headers or sensitive bearer tokens in exception tracebacks or string representations.

