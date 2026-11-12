# PRIVGUARD AI — Application Secret Lifecycle Specification
## Metadata Governance, Zero Plaintext Storage & Rotation

**Organization:** Moon Sanctum Labs — *Decode. Build. Evolve.*  
**Author:** Aniket Nandi (Kolkata, IST)  
**Baseline:** Stage 10.5  

---

### 1. Distinction: Encryption Keys vs Application Secrets

A foundational architectural rule established in Stage 10.5:

| Category | Managed Key (`ManagedKey`) | Application Secret (`SecretMetadataRecord`) |
| :--- | :--- | :--- |
| **Purpose** | Protects data confidentiality & integrity (KEK, DEK, Signing) | Authorizes access to external services & platforms |
| **Operations** | Cryptographic primitives (`encrypt`, `decrypt`, `sign`, `verify`) | API authentication, tokens, connection strings |
| **Storage Location** | Provider KMS / Hardware Security Module | External Secret Store (`AWS Secrets Manager`, `Vault`, K8s Secrets, Env) |
| **PRIVGUARD Role** | Cryptographic envelope participant | Metadata & audit tracking engine (Zero plaintext stored) |

---

### 2. Zero Plaintext Invariant

PRIVGUARD AI enforces a strict zero-plaintext architecture for all application secrets (LLM API keys, database passwords, OAuth secrets, MCP credentials):
- `SecretMetadataRecord` stores **only** descriptive metadata: `name`, `secret_type`, `version`, `provider_ref`, `status`, `expires_at`, `last_rotated_at`.
- The database schema has **no column** for plaintext credentials.
- API endpoints (`GET /v1/secrets`, `GET /v1/secrets/{id}`) return only `SecretMetadataResponse` containing zero credential material.
- If an application component requires the actual secret value at runtime, it resolves the secret directly from the runtime environment or external provider (e.g. `/run/secrets/`, AWS Secrets Manager) using the `provider_ref`.

---

### 3. Secret Types & Rotation Lifecycle

```
[ REGISTERED (v1) ] ---> [ ACTIVE ] ---> [ ROTATION_PENDING ] ---> [ ROTATING (v2) ] ---> [ ACTIVE (v2) ]
                                |
                                +---> [ REVOKED ]
```

#### Supported Types:
- `LLM_API_KEY`: OpenAI, Anthropic, Gemini, or local inference endpoint keys.
- `DATABASE_CREDENTIAL`: PostgreSQL / Redis connection credentials.
- `REDIS_CREDENTIAL`: Distributed state Redis password / token.
- `MCP_CREDENTIAL`: Upstream MCP server authorization tokens or basic auth strings.
- `OAUTH_SECRET`: OAuth 2.0 client secrets and integration tokens.
- `SIEM_TOKEN`: Splunk / Datadog / OpenTelemetry authorization headers.

#### Rotation Workflow:
1. Administrator or automation triggers `POST /v1/secrets/{id}/rotate`.
2. `SecretManager` increments the version number, creates a `SecretRotationJob`, updates `last_rotated_at`, and sets status to `ACTIVE`.
3. Upstream orchestrator (e.g. Kubernetes External Secrets Operator or AWS Secrets Manager rotation Lambda) provisions the new secret in the external store.
4. If an external credential is breached, calling `POST /v1/secrets/{id}/revoke` flags the secret as `REVOKED`, instantly blocking all agents from attempting to consume it.
