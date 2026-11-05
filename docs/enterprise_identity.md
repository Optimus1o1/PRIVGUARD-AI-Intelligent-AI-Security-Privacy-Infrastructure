# Enterprise Identity, SSO & SCIM 2.0 Provisioning

> **PRIVGUARD AI** — *Enterprise Authentication & Lifecycle Management*  
> **Target Version**: Stage 9

---

## 1. Single Sign-On (SSO) Architecture

PRIVGUARD implements enterprise SSO using an identity provider abstraction supporting OpenID Connect (OIDC) and SAML 2.0.

### 1.1 Strict Claim Verification
Every token presented during federated enterprise login undergoes the following mandatory verifications:
1. **Issuer Validation (`iss`)**: Must exactly match the configured identity provider issuer URI.
2. **Audience Validation (`aud`)**: Must contain the registered PRIVGUARD client ID.
3. **Expiration Check (`exp`)**: Tokens past their expiration timestamp fail closed.
4. **Nonce Verification (`nonce`)**: Protects against token injection and cross-site replay attacks.
5. **Domain Verification**: Enforces that the user's email domain has been explicitly verified by the organization administrator before granting access.

### 1.2 Domain Verification Workflow
To prevent unauthorized users from claiming memberships based on unverified email domains, organization owners must verify domain ownership via a cryptographically random challenge token:
```
POST /v1/organizations/{id}/domain/verify
{
  "domain": "company.com",
  "verification_token": "a4f8910b2c3d4e5f..."
}
```
Only after verification can SSO route employees into that tenant automatically.

---

## 2. SCIM 2.0 User Provisioning (RFC 7643 / RFC 7644)

PRIVGUARD provides a SCIM 2.0 endpoint for automated enterprise provisioning from identity providers like Okta, Azure Active Directory, and PingFederate.

### 2.1 Supported Endpoints
- `GET /v1/scim/v2/Users`: Lists provisioned users in standard SCIM ListResponse format.
- `POST /v1/scim/v2/Users`: Provisions a new employee into the enterprise organization.
- `GET /v1/scim/v2/Users/{id}`: Retrieves SCIM user record.
- `PATCH /v1/scim/v2/Users/{id}` / `PUT`: Updates employee profile or suspends account.
- `DELETE /v1/scim/v2/Users/{id}`: Deprovisions user.

### 2.2 Immediate Deprovisioning Revocation Guarantee
When a user is deprovisioned via SCIM:
1. `OrganizationMembership.status` is set to `DEPROVISIONED`.
2. All pending human approvals assigned to or requested by that user are expired immediately (`status = "EXPIRED"`).
3. Any active user sessions or API tokens are invalidated immediately, halting further protected actions.
