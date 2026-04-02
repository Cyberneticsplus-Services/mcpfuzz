# Quickstart — Scan Your First MCP Server

This guide walks you through your first scan in under 5 minutes.

---

## 1. Pick a target

MCPFuzz scans any MCP server. You can use a server you're building, one from npm/PyPI, or the official reference server.

For this walkthrough we'll use `@modelcontextprotocol/server-filesystem` — the most widely used MCP server (requires `npx`):

```bash
# Make sure npx is available
npx --version
```

---

## 2. Run your first scan

```bash
mcpfuzz scan \
  --server "npx -y @modelcontextprotocol/server-filesystem /tmp" \
  --transport stdio
```

`--transport stdio` is the default — you can omit it for stdio servers.

What happens:
- MCPFuzz launches the server as a subprocess
- Connects over stdio (standard MCP protocol)
- Calls `tools/list` to discover all available tools
- Runs all 12 security modules against each tool
- Prints results to the terminal

---

## 3. Reading the output

A typical scan looks like this:

```
╭─────────────────────────────────────────────────────╮
│ MCPFuzz — Dynamic MCP Security Scanner               │
│ By Cyberneticsplus Services Private Limited          │
│                                                      │
│ Target: npx -y @modelcontextprotocol/server-fil...  │
│ Transport: stdio                                     │
│ Modules: all (12)                                    │
╰─────────────────────────────────────────────────────╯

  [path_traversal] testing read_file ...
  [path_traversal] testing list_directory ...
  [ssrf] testing read_file ...
  [command_injection] no applicable tools found
  ...

╭──────────────────── Scan abc12345 ────────────────────╮
│ ✗ VULNERABLE                                          │
│                                                       │
│ Tools discovered: 5                                   │
│ Confirmed findings: 2                                 │
│ Potential findings: 1                                 │
│                                                       │
│ 🔴 CRITICAL: 0                                       │
│ 🟠 HIGH: 2                                           │
│ 🟡 MEDIUM: 0                                         │
│ 🔵 LOW: 0                                            │
│ ⚪ INFO: 1                                           │
╰───────────────────────────────────────────────────────╯

┌──────────────────────────────────────────────────────────────────────┐
│ Findings                                                             │
├──────────────┬───────────┬────────────────┬───────────┬─────────────┤
│ Severity     │ Status    │ Module         │ Tool      │ Title       │
├──────────────┼───────────┼────────────────┼───────────┼─────────────┤
│ 🟠 HIGH     │ confirmed │ path_traversal │ read_file │ Path Trav…  │
│ 🟠 HIGH     │ confirmed │ path_traversal │ list_dir  │ Path Trav…  │
│ 🟡 MEDIUM   │ potential │ ssrf           │ read_file │ SSRF via…   │
│ ⚪ INFO     │ confirmed │ hardcoded_…    │ -         │ No secrets… │
└──────────────┴───────────┴────────────────┴───────────┴─────────────┘

Finding Details:

╭──────────── 1. Path Traversal in 'read_file' ───────────────────────╮
│ CVSS: 7.5  |  CWE: CWE-22                                          │
│                                                                      │
│ Description:                                                         │
│ The read_file tool returned content from outside the allowed         │
│ directory when given a traversal payload in the 'path' parameter.   │
│                                                                      │
│ Payload: ../../../../etc/passwd                                      │
│                                                                      │
│ Evidence:                                                            │
│ root:x:0:0:root:/root:/bin/bash                                     │
│ daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin                     │
│                                                                      │
│ Remediation:                                                         │
│ Resolve all paths with os.path.realpath() before use. Check that    │
│ the resolved path still starts with the allowed base directory.      │
╰──────────────────────────────────────────────────────────────────────╯
```

---

## 4. Run specific modules only

If you only want to test for a specific vulnerability class:

```bash
# Path traversal and command injection only
mcpfuzz scan \
  --server "npx -y @modelcontextprotocol/server-filesystem /tmp" \
  --modules path_traversal,command_injection

# Just check for hardcoded secrets
mcpfuzz scan --server "python3 my_server.py" --modules hardcoded_secrets

# See all module IDs
mcpfuzz list-modules
```

---

## 5. Scan an HTTP/SSE server

```bash
# SSE transport (most common for remote servers)
mcpfuzz scan \
  --server http://localhost:8080 \
  --transport sse

# With auth token
mcpfuzz scan \
  --server https://api.example.com/mcp \
  --transport sse \
  --token "Bearer sk-your-token"

# Streamable HTTP (newer MCP spec)
mcpfuzz scan \
  --server http://localhost:3000/mcp \
  --transport streamable-http
```

---

## 6. Save results to a file

```bash
# JSON output — machine-readable, for CI/CD or further analysis
mcpfuzz scan \
  --server "npx -y @modelcontextprotocol/server-filesystem /tmp" \
  --output json \
  --out results.json

# Filter confirmed findings with jq
cat results.json | jq '.findings[] | select(.status == "confirmed")'
```

---

## 7. Auto-generate POC scripts

For every confirmed finding, MCPFuzz can generate a standalone Python script that reproduces the vulnerability:

```bash
mcpfuzz scan \
  --server "npx -y @modelcontextprotocol/server-filesystem /tmp" \
  --poc-dir ./poc/
```

This creates `poc/<finding-id>.py` — a self-contained script you can run to reproduce and verify the finding. If Pillow is installed, it also saves a terminal screenshot as `poc/<finding-id>.png` for bug reports.

---

## 8. Use with environment variables (stdio only)

Some servers need credentials or config passed as environment variables:

```bash
mcpfuzz scan \
  --server "npx -y @modelcontextprotocol/server-postgres" \
  --env DATABASE_URL=postgresql://localhost/testdb \
  --env DEBUG=1
```

---

## 9. Enable LLM-judge for tool poisoning

The `tool_poisoning` module has two detection layers:

- **Pass 1 (always-on):** Regex + heuristics — detects known patterns fast, no API key needed
- **Pass 2 (optional):** LLM-judge — sends each tool definition to Claude Haiku for adversarial intent analysis — catches obfuscated attacks that defeat regex

```bash
# Anthropic Claude Haiku (requires API key)
mcpfuzz scan \
  --server "npx my-mcp-server" \
  --llm-key sk-ant-... \
  --llm-provider anthropic

# Ollama cloud (get key from ollama.com/settings/keys)
mcpfuzz scan \
  --server "npx my-mcp-server" \
  --llm-key ollama-... \
  --llm-provider ollama

# Local Ollama (no key needed — defaults to llama3.2)
mcpfuzz scan \
  --server "npx my-mcp-server" \
  --llm-provider ollama
```

---

## 10. CI/CD integration

MCPFuzz exits with code `1` if findings at or above the `--fail-on` severity are found:

```yaml
# GitHub Actions example
- name: MCP Security Scan
  run: |
    pip install mcpfuzz
    mcpfuzz scan \
      --server "python3 src/my_mcp_server.py" \
      --output json \
      --out mcp-scan-results.json \
      --fail-on high \
      --quiet

- name: Upload scan results
  uses: actions/upload-artifact@v3
  with:
    name: mcp-scan-results
    path: mcp-scan-results.json
```

Exit codes:
- `0` — No findings above `--fail-on` threshold (default: high)
- `1` — Findings at or above threshold found
- `2` — Scan failed (server unreachable, crash, etc.)

---

## Common options reference

| Option | Default | Description |
|--------|---------|-------------|
| `--server`, `-s` | required | Server command (stdio) or URL (sse/http) |
| `--transport`, `-t` | `stdio` | `stdio`, `sse`, `http`, `streamable-http` |
| `--modules`, `-m` | all | Comma-separated module IDs |
| `--output`, `-o` | `console` | `console` or `json` |
| `--out` | stdout | File path for JSON output |
| `--timeout` | `30` | Seconds per tool call |
| `--fail-on` | `high` | Minimum severity to exit 1 |
| `--token` | — | Auth token for SSE/HTTP |
| `--env`, `-e` | — | `KEY=VALUE` env vars (stdio only, repeatable) |
| `--poc-dir` | — | Directory for generated POC scripts |
| `--llm-key` | — | API key for LLM-judge |
| `--llm-provider` | `anthropic` | `anthropic`, `ollama`, `openai` |
| `--quiet`, `-q` | off | Print results only, suppress progress |
