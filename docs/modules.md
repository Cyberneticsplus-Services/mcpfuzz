# Module Reference

MCPFuzz ships 12 security modules. Each module targets a specific vulnerability class and runs independently — you can run all of them or pick specific ones with `--modules`.

```bash
# List all modules
mcpfuzz list-modules

# Run specific modules
mcpfuzz scan --server "..." --modules path_traversal,ssrf,command_injection
```

---

## Module summary

| ID | Name | CWE | Transport |
|----|------|-----|-----------|
| `path_traversal` | Path Traversal | CWE-22 | All |
| `command_injection` | Command Injection | CWE-78 | All |
| `sql_injection` | SQL Injection | CWE-89 | All |
| `ssrf` | SSRF | CWE-918 | All |
| `auth_bypass` | Auth Bypass | CWE-287 / CWE-862 | All |
| `hardcoded_secrets` | Hardcoded Secrets | CWE-798 | All |
| `dns_rebinding` | DNS Rebinding | CWE-346 | SSE / HTTP only |
| `tool_poisoning` | Tool Poisoning | CWE-74 | All |
| `rug_pull` | Rug Pull Detection | CWE-494 | All |
| `idor_bola` | IDOR / BOLA | CWE-639 | All |
| `protocol_fuzzing` | Protocol Fuzzing | CWE-20 | All |
| `cve_checks` | CVE Checks | Various | All |

---

## `path_traversal`

**CWE-22 — Improper Limitation of a Pathname to a Restricted Directory**

Tests MCP tools that accept file path arguments. Sends `../../../../etc/passwd` style payloads and checks if the server returns content from outside its allowed directory.

**Triggers on:** Tools with parameter names like `path`, `file`, `filename`, `filepath`, `directory`, `dir`, `resource`, `uri`. Also checks tool names containing `read`, `file`, `get`, `load`, `fetch`, `list`.

**Confirmed when:** The server response contains content that only exists outside the base directory — e.g. `/etc/passwd` contents, `/proc/self/environ`, `C:\Windows\System32\drivers\etc\hosts`.

**Typical CVSS:** 7.5–8.5 HIGH (stdio), 8.5 HIGH (network-exposed)

**Example payload:** `../../../../etc/passwd`

**Remediation:** Resolve all paths with `os.path.realpath()` then verify the result still starts with the allowed base directory before opening.

---

## `command_injection`

**CWE-78 — OS Command Injection**

Tests MCP tools that execute shell commands or accept shell-like parameters. Injects OS command separators (`; id`, `| id`, `$(id)`, `` `id` ``) and checks if command output appears in the response.

**Triggers on:** Tools with parameter names `command`, `cmd`, `exec`, `run`, `shell`, `args`, `expression`, `code`, `script`. Also tools named `execute`, `run`, `shell`, `bash`, `terminal`, `eval`.

**Confirmed when:** The response contains output of the injected command — e.g. `uid=0(root)`, `uid=1000(user)`.

**Also uses OOB detection:** Sends payloads that trigger DNS/HTTP callbacks to the built-in OOB server for blind injection scenarios.

**Typical CVSS:** 9.8 CRITICAL

**Example payload:** `hello; id`

**Remediation:** Never pass user-controlled input to shell commands. Use `subprocess.run()` with a list of arguments (not `shell=True`). Validate and whitelist all inputs.

---

## `sql_injection`

**CWE-89 — SQL Injection**

Three-phase detection:

1. **Error-based:** Injects `'`, `"`, `;`, `--` and checks for database error strings (MySQL, PostgreSQL, SQLite, MSSQL, Oracle)
2. **Boolean-blind:** Compares response to `OR 1=1` (always-true) vs `OR 1=2` (always-false) — significant difference indicates unsanitised SQL execution
3. **Time-based blind:** Injects `SLEEP(5)`, `pg_sleep(5)`, `WAITFOR DELAY '0:0:5'` and measures latency delta

Auto-detects database dialect from tool names and descriptions (Postgres, MySQL, MSSQL, SQLite, Oracle) and sends dialect-appropriate payloads.

**Triggers on:** Tools with `query`, `sql`, `statement`, `filter`, `search`, `condition`, `where` parameters, or tool names containing `query`, `search`, `execute`, `find`, `filter`.

**Confirmed when:** DB error strings in response, or measurable timing difference (≥4.5s on time-based injection).

**Typical CVSS:** 8.8–9.8 CRITICAL (unauthenticated), 7.2–8.8 HIGH (authenticated required)

**Example payload:** `' OR '1'='1`

**Remediation:** Use parameterised queries / prepared statements. Never concatenate user input into SQL strings.

---

## `ssrf`

**CWE-918 — Server-Side Request Forgery**

Tests MCP tools that accept URLs or make HTTP requests. Sends:
- Cloud metadata URLs (`http://169.254.169.254/latest/meta-data/`)
- Internal network targets (`http://localhost:6379/`, `http://10.0.0.1/`)
- OOB callback URL to the built-in local HTTP listener

**OOB detection:** MCPFuzz starts a local HTTP server before the scan. When an OOB payload is sent and the MCP server makes an outbound request, the callback server records the hit — proving blind SSRF even when the response contains no evidence.

**Transport-aware severity:**
- `stdio` transport (local process, not network-exposed): **HIGH / CVSS 7.5**
- `sse` / `http` / `streamable-http` (network-exposed): **CRITICAL / CVSS 9.1**

**Framework / by-design exclusions:** Tools from `fastmcp`, `mcp`, `@modelcontextprotocol/sdk` are excluded (SSRF is a design feature of the framework, not a bug). Browser automation tools (`playwright`, `puppeteer`), curl tools, and fetch tools are downgraded to POTENTIAL since URL-fetching is their advertised purpose.

**Triggers on:** Parameters named `url`, `uri`, `endpoint`, `link`, `href`, `src`, `source`, `address`.

**Confirmed when:** Response contains cloud metadata, internal service response, or OOB callback hit.

**Remediation:** Validate URL scheme (allow only `https`), block private IP ranges (RFC1918 + link-local), use an allowlist of permitted domains, or proxy all outbound requests through a hardened egress layer.

---

## `auth_bypass`

**CWE-287 / CWE-862 — Improper Authentication / Missing Authorization**

Dynamic, schema-aware testing in three steps:

1. **Checks whether the server uses MCP-level auth at all** — looks for auth-related parameters (`token`, `api_key`, `password`, `secret`, `credential`, `authorization`)
2. **Baseline test:** Sends a random UUID as the auth value to establish what a rejected request looks like
3. **Bypass test:** Sends known bypass payloads (`admin`, `true`, `null`, `*`, `undefined`, `bypass`, empty string) — if these succeed where the baseline failed, it's a confirmed auth bypass
4. **Missing auth detection:** For sensitive tools (admin, delete, drop, deploy) with no auth parameters on a server that uses auth elsewhere, flags as Missing Authorization (CWE-862)

**Confirmed when:** Bypass payload succeeds and baseline UUID fails. Or: sensitive tool is accessible with no auth check.

**Typical CVSS:** 8.1–9.8 depending on what the tool does

**Remediation:** Implement authentication at the server level, not per-tool. Use the MCP spec's OAuth/token mechanisms. Never rely on client-side access control.

---

## `hardcoded_secrets`

**CWE-798 — Use of Hard-coded Credentials**

Two-pass scanning:

1. **Schema scan:** Checks all tool names, descriptions, and parameter definitions for embedded credentials
2. **Response scan:** Calls info/config/status tools and scans their responses

Uses confidence-scored patterns:
- **High confidence** (fire immediately): vendor-prefixed tokens like `AKIA...` (AWS), `ghp_...` (GitHub), `sk-ant-...` (Anthropic), `xoxb-...` (Slack), PEM private key headers, JWT tokens, connection strings
- **Low confidence** (require corroborating context): generic base64, generic hex strings — only flagged when combined with a key-like parameter name or connection string context

**Confirmed when:** A high-confidence pattern matches in schema or response.

**Typical CVSS:** 7.5–9.0 depending on the secret type and what it grants access to

**Remediation:** Never embed credentials in tool definitions or server responses. Use environment variables. Rotate any detected secrets immediately.

---

## `dns_rebinding`

**CWE-346 — Origin Validation Error**

> **Only runs against HTTP/SSE servers** (`--transport sse`, `http`, or `streamable-http`). Skipped automatically for stdio.

Per the MCP specification, HTTP MCP servers **must** validate the `Origin` header and reject connections from untrusted origins. Failure to do so enables DNS rebinding attacks — a malicious website can make the victim's browser connect to the MCP server as a trusted local client.

Sends requests with spoofed origins: `http://evil.com`, `null`, `http://localhost.evil.com`, `http://169.254.169.254`, and empty string.

**Confirmed when:** Server responds with `200 OK` or a valid JSON-RPC response to any invalid origin.

**Typical CVSS:** 7.5 HIGH

**Remediation:** Validate the `Origin` header. Accept only `http://localhost`, `http://127.0.0.1`, and explicitly configured trusted origins. Return `403 Forbidden` for all others.

---

## `tool_poisoning`

**CWE-74 / OWASP LLM07 — Tool Poisoning / Prompt Injection via MCP**

Two-pass detection:

**Pass 1 — Regex/heuristics (always runs, no API key needed):**
- Prompt injection patterns: `ignore previous instructions`, `disregard`, `you are now`, `system prompt override`, `<SYSTEM>`, etc.
- Data exfiltration patterns: instructions to send data to external URLs hidden in tool descriptions
- Unicode tricks: homoglyph characters, invisible zero-width characters, right-to-left override
- Shadow tools: tools claiming to be a different, more trusted tool
- Persona override: instructions telling the AI agent to change its identity or ignore safety rules

**Pass 2 — LLM-judge (optional, requires `--llm-key`):**
Sends each tool definition to Claude Haiku (or Ollama/OpenAI) for adversarial intent analysis. Catches obfuscated attacks, multi-step manipulation split across fields, and synonym-based attacks that defeat regex patterns.

**Confirmed when:** Regex matches a known-malicious pattern (Pass 1), or LLM-judge returns `is_malicious: true` with `confidence: high` (Pass 2).

**Typical CVSS:** 8.0–9.0 HIGH depending on what the injection attempts to do

**Remediation:** MCP clients should display tool definitions to users before connecting. Registry operators should scan tool definitions before listing servers. Treat tool descriptions as untrusted user input.

---

## `rug_pull`

**CWE-494 — Download of Code Without Integrity Check**

Detects runtime tool definition changes between scan sessions. On first scan, MCPFuzz hashes all tool definitions (name, description, inputSchema) and stores them in `~/.mcpfuzz/baseline.db`. On subsequent scans of the same server, it compares current definitions against the stored baseline.

Any change in a tool's description or schema after the baseline is flagged — this is the pattern of a rug pull attack: a server that presents benign tools during initial trust evaluation but modifies them later.

**Confirmed when:** A tool's definition hash differs from its stored baseline.

**Note:** First scan always sets the baseline — no findings are reported on first scan. Findings appear from the second scan onwards.

**Typical CVSS:** 8.0–9.0 HIGH

**Remediation:** Pin tool definitions in your MCP client config. Use signed tool registries. Monitor tool definitions for changes in production.

---

## `idor_bola`

**CWE-639 — Authorization Bypass Through User-Controlled Key (IDOR / BOLA)**

Tests whether resource IDs can be manipulated to access objects belonging to other users. Sends predictable/sequential ID values (`1`, `0`, `-1`, `2`, `admin`, null UUID, zero UUID) in parameters named `id`, `user_id`, `account_id`, `document_id`, `resource_id`, etc.

**Confirmed when:** Server returns a valid resource (non-error response with data) for an ID that was not provided during tool setup — indicating the server is not enforcing object-level authorization.

**Typical CVSS:** 6.5–8.5 depending on the sensitivity of the exposed resource

**Remediation:** Always verify that the requesting client has permission to access the specific object — not just that the client is authenticated. Never rely solely on ID obscurity.

---

## `protocol_fuzzing`

**CWE-20 / CWE-703 — Improper Input Validation**

Sends malformed JSON-RPC messages and checks for crashes, stack traces, and information disclosure:

- Missing required fields (`method`, `jsonrpc`, `id`)
- Wrong types (integer where string expected, array where object expected)
- Oversized payloads (64KB strings, 10,000-element arrays)
- Deeply nested objects (500 levels deep)
- Boundary values (`null`, `0`, `-1`, `2^31-1`, `2^63-1`, `Infinity`, `NaN`)
- Unicode edge cases (`\x00`, `\uFFFD`, RTL override characters)

**Confirmed when:** Response contains a stack trace, internal file path, or the server crashes (connection refused on subsequent request).

**Typical CVSS:** 5.0–7.5 MEDIUM-HIGH (depends on what's disclosed)

**Remediation:** Validate all inputs at the JSON-RPC layer. Return generic error messages — never expose stack traces or internal paths. Use a framework that handles malformed input gracefully.

---

## `cve_checks`

**Various CVEs — Checks for known published MCP vulnerabilities**

Sends reproduction payloads for 13 specific CVEs affecting MCP servers and SDKs:

| CVE / Advisory | Description | Affected |
|----------------|-------------|---------|
| GHSA-hc55-p739-j48w | Path prefix collision bypass | Filesystem MCP servers |
| CVE-2026-0621 | ReDoS via URI template exploded variables | TypeScript MCP SDK |
| CVE-2025-53366 | FastMCP unhandled exception DoS | Python FastMCP |
| CVE-2026-25536 | Cross-client response data leak (stateless HTTP) | TypeScript MCP SDK |
| CVE-2025-43859 | SSE endpoint URL injection (`mcp` Python ≤1.6.0) | Python MCP SDK |
| CVE-2025-47279 | Missing JSON-RPC parameter validation | Python MCP SDK |
| CVE-2025-49596 | Tool name confusion / shadowing | All MCP servers |
| CVE-2026-18423 | Prompt injection via tool description reflection | All MCP servers |
| CVE-2025-46728 | Prototype pollution via `__proto__` in tool args | Node.js MCP servers |
| GHSA-7q7c-xpqm-3v7j | Unbounded resource allocation / response bomb | All MCP servers |
| CVE-2025-53521 | SSTI via Jinja2 templates | Python MCP servers |
| CVE-2026-33023 | Path traversal via null-byte injection | Filesystem tools |
| GHSA-mcp-9q8g-2j7f | Unicode normalization path bypass | Filesystem tools |

Framework guards prevent false positives: TypeScript CVEs only fire on JS/TS servers, Python CVEs only fire on Python servers.

**Confirmed when:** The server's response matches the known vulnerable behaviour for that specific CVE.

**Typical CVSS:** Varies — 5.0–9.8 depending on the CVE

**Remediation:** Update to the patched version listed in the CVE advisory.
