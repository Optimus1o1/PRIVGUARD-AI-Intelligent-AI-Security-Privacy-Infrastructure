# PRIVGUARD AI — Model Context Protocol SSRF Defense
## Destination Validation, RFC 1918 Private Subnet Blocking, and Metadata Shields

*Moon Sanctum Labs — Decode. Build. Evolve.*

---

### 1. SSRF Threats in Tool-Enabled AI Systems

Autonomous AI agents with tool-calling capabilities can be coerced into targeting internal network resources through Server-Side Request Forgery (SSRF):
- Probing internal microservices (`http://10.0.0.1:8080/admin`).
- Extracting cloud provider IAM credentials from instance metadata services (`http://169.254.169.254/latest/meta-data/`).
- Accessing local databases or administrative dashboards on `localhost` / `127.0.0.1`.
- Performing DNS rebinding attacks to resolve a public domain to an internal private IP post-validation.

---

### 2. Destination Validation Engine

PRIVGUARD implements a deterministic multi-stage destination connection validator (`MCPDestinationValidator`):

```
Target URL Input (e.g. "https://api.github.com/mcp")
                       |
                       v
+-------------------------------------------------------+
| 1. Protocol Scheme Verification                       |
|    - Enforces scheme in ('http', 'https')             |
|    - Blocks file://, ftp://, gopher://, ldap://       |
+-------------------------------------------------------+
                       |
                       v
+-------------------------------------------------------+
| 2. Protected Hostname & TLD Matching                  |
|    - Blocks: localhost, metadata.google.internal,     |
|      169.254.169.254, instance-data                   |
|    - Blocks TLD suffixes: .internal, .local,          |
|      .corp, .lan                                      |
+-------------------------------------------------------+
                       |
                       v
+-------------------------------------------------------+
| 3. Pre-Flight DNS Resolution                          |
|    - Resolves hostname to all target IP addresses     |
+-------------------------------------------------------+
                       |
                       v
+-------------------------------------------------------+
| 4. Strict IP Range & CIDR Verification                |
|    - Matches every resolved IP against blocked CIDRs: |
|      * 127.0.0.0/8 (Loopback)                         |
|      * 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16     |
|      * 169.254.0.0/16 (Link-Local & Cloud Metadata)   |
|      * 100.64.0.0/10 (Carrier-Grade NAT)              |
|      * 224.0.0.0/4 (Multicast)                        |
|      * ::1/128, fc00::/7, fe80::/10 (IPv6)            |
+-------------------------------------------------------+
                       |
                       v
           Destination Approved for MCP Connection
```

---

### 3. DNS Rebinding Defense

DNS rebinding occurs when an attacker configures a domain name with a low TTL (e.g. 1 second) that initially resolves to a benign public IP, and then subsequently resolves to `127.0.0.1` or `169.254.169.254` when the application makes its HTTP connection.

PRIVGUARD protects against DNS rebinding by:
1. Resolving the hostname immediately prior to validation.
2. Validating every IP returned in the DNS `getaddrinfo` response set.
3. Rejecting any destination where even one resolved IP belongs to a private, loopback, or metadata subnet.
4. Pinning resolved IPs in production transport configurations to prevent dynamic resolution shifts between check and connection.
