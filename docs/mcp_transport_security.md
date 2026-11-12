# PRIVGUARD AI — Model Context Protocol Transport Security
## Streamable HTTP, Isolated stdio Subprocesses, and Header Routing

*Moon Sanctum Labs — Decode. Build. Evolve.*

---

### 1. Transport Protocols Supported

PRIVGUARD implements transport security according to the official **MCP 2026-07-28 specification**:

#### 1.1 Streamable HTTP (Primary Standard)
- All remote network-accessible MCP servers must communicate over **Streamable HTTP**.
- Transport uses standard HTTP/2 or HTTP/1.1 with TLS 1.3 encryption.
- Direct JSON-RPC 2.0 requests are delivered via `POST` with mandatory protocol headers:
  - `mcp-version: 2026-07-28`
  - `mcp-method: <method_name>`
  - `mcp-name: <tool_or_resource_name>` (when method is `tools/call` or `resources/read`)

#### 1.2 Isolated Local stdio Subprocesses
- For local command-line tools, PRIVGUARD provides a hardened stdio process sandbox.
- **Default State:** Disabled by default (`enabled_by_default=False`).
- **Binary Allowlist:** Only approved executables may be spawned:
  - `node`, `npx`, `python`, `python3`, `uvx`
- **Shell Invocation:** Processes are spawned strictly via `asyncio.create_subprocess_exec` with `shell=False`. Shell interpreters (`bash`, `sh`, `cmd`, `powershell`) are rejected.
- **Metacharacter Defense:** Argument strings containing chaining characters (`;`, `|`, `&`, `$`, `` ` ``, `<`, `>`, `\n`) are immediately rejected.
- **Environment Sanitization:** Subprocesses run in a stripped environment retaining only essential runtime variables (`PATH`, `SYSTEMROOT`, `WINDIR`, `TEMP`, `HOME`). Master encryption keys (`PRIVGUARD_MASTER_KEY`), database credentials, and authentication tokens are never inherited.

---

### 2. Header Routing & Method Mismatch Defense

Streamable HTTP uses headers to enable efficient edge routing and pre-execution filtering. PRIVGUARD enforces complete synchronization between protocol headers and JSON-RPC bodies:

| Scenario | Request State | Gateway Action | Response |
|---|---|---|---|
| Valid Request | `mcp-method: tools/list`, body method `tools/list` | Dispatched to handler | JSON-RPC 2.0 Result |
| Version Mismatch | Missing or unsupported `mcp-version` | Immediate rejection | `-32600 Invalid Request` |
| Method Mismatch | Header says `tools/list`, body says `tools/call` | Immediate rejection | `-32600 Invalid Request` |
| Tool Name Mismatch | Header says `tool_a`, body params say `tool_b` | Immediate rejection | `-32600 Invalid Request` |
| Unknown Method | Method not implemented by PRIVGUARD facade | Method not found | `-32601 Method not found` |
