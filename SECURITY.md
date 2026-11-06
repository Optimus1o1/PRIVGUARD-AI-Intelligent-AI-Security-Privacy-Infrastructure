# PRIVGUARD AI — Security Policy & Coordinated Vulnerability Disclosure

Organization: **Moon Sanctum Labs**  
Slogan: **Decode. Build. Evolve.**  
System: **PRIVGUARD AI — Independent Security & Privacy Enforcement Layer for Agentic AI**  

---

## 1. Security Philosophy & Commitment

PRIVGUARD AI is an independent, zero-trust security perimeter mediating autonomous agent execution, personal AI memory, and upstream language models. We take the security of our codebase, supply chain, and deployment artifacts seriously.

We welcome vulnerability reports from researchers, security engineers, and community contributors who practice responsible disclosure.

---

## 2. Supported Versions

Security updates and patches are actively maintained for the following release lines:

| Version Line | Release Status | Security Support |
| :--- | :--- | :--- |
| `0.1.x` | Active Development (Stage 10.x) | Full Security Support |
| `< 0.1.0` | Legacy Development Previews | Unsupported |

---

## 3. Reporting a Vulnerability

> [!CAUTION]
> **DO NOT file public GitHub issues for security vulnerabilities.**
> Public disclosure before an agreed-upon fix exposes downstream users and deployments to zero-day risk.

### 3.1 Primary Reporting Channel
Please report all security vulnerabilities privately to:
- **Email**: `security@moonsanctum.internal` (or direct to Lead Developer & Designer [ANIKET NANDI])
- **GitHub Private Vulnerability Reporting**: Utilize the "Report a vulnerability" button under the **Security** tab of this repository.

### 3.2 What to Include in Your Report
To accelerate triage and remediation, please provide:
1. **Vulnerability Type**: (e.g. Prompt Injection Bypass, PII De-anonymization, SSRF in MCP Destination Validator, Envelope Encryption Key Derivation Flaw, Privilege Escalation).
2. **Affected Component**: File path, API endpoint, or Docker service.
3. **Step-by-Step Reproduction**: Detailed proof-of-concept (PoC) scripts or curl commands.
4. **Impact Assessment**: Real-world threat scenario and potential blast radius.
5. **Proposed Remediation**: If you have identified a code-level fix.

---

## 4. Response Timeline & SLAs

Moon Sanctum Labs commits to the following coordinated response service levels:
- **Initial Acknowledgment**: Within **24 hours** of receipt.
- **Triage & Severity Confirmation**: Within **72 hours**.
- **Remediation Plan & Private Patch**: Within **14 business days** for Critical/High severity flaws.
- **Public Advisory & Release**: Coordinated with the reporting researcher within **30 days** of triage.

---

## 5. Security Architecture Invariants

Any report demonstrating a violation of these core platform invariants will be assigned immediate `CRITICAL` triage priority:
1. **Zero Raw Secrets in Model Context**: Model ingress allowing raw API keys, bearer tokens, or database connection strings to pass to upstream providers.
2. **Memory Vault Isolation**: Any mechanism permitting User B to decrypt, read, or splice User A's AES-256-GCM envelope-encrypted memories.
3. **MCP SSRF Barrier**: Any bypass allowing agent tool execution to connect to private subnets (RFC 1918) or cloud metadata (`169.254.169.254`).
4. **Approval Action Binding**: Any mechanism permitting an approved tool action to execute with altered parameters.
5. **Zero-Content Telemetry**: Raw prompts, completions, or memory plaintext appearing in Prometheus metrics, OpenTelemetry spans, or structured logs.
