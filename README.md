# MCPFuzz ⚡

**The first dynamic security scanner for MCP (Model Context Protocol) servers.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![PyPI version](https://badge.fury.io/py/mcpfuzz.svg)](https://badge.fury.io/py/mcpfuzz)

---

## Why MCPFuzz?

Every other MCP security tool reads tool descriptions and pattern-matches text. **MCPFuzz actually connects to your MCP server and sends real exploit payloads** — then checks if they worked.

| Tool | Approach | Path Traversal | SSRF | Command Injection | Auth Bypass | POC Output |
|------|----------|:--------------:|:----:|:-----------------:|:-----------:|:----------:|
| mcp-scan (Snyk) | Static analysis | ❌ | ❌ | ❌ | ❌ | ❌ |
| Cisco MCP Scanner | Static + YARA | ❌ | ❌ | ❌ | ❌ | ❌ |
| mcp-shield | Static analysis | ❌ | ❌ | ❌ | ❌ | ❌ |
| **MCPFuzz** | **Active exploit testing** | ✅ | ✅ | ✅ | ✅ | ✅ |

If a vulnerability exists, MCPFuzz proves it with evidence — not a warning about suspicious text. It also generates a ready-to-submit POC script and terminal screenshot for every confirmed finding.

---

## What MCPFuzz Found

MCPFuzz is used by [Cyberneticsplus Services Private Limited](https://cyberneticsplus.com) as part of an ongoing CVE research programme targeting AI/MCP infrastructure. Findings are responsibly disclosed to maintainers under a 90-day embargo — they appear in this table only after the fix is shipped.

| Server | Severity | Type | Fixed In | Report |
|--------|----------|------|----------|--------|
| `lighthouse-mcp` | HIGH | SSRF OOB via `run_audit` + `get_performance_score` (CWE-918) | v0.1.13 | [#23](https://github.com/priyankark/lighthouse-mcp/issues/23) |
| `html-to-markdown-mcp` | CRITICAL | SSRF OOB via `html_to_markdown` (CWE-918) | PR #3 (2026-03-29) | [#2](https://github.com/levz0r/html-to-markdown-mcp/issues/2) |

Additional findings are currently under responsible disclosure. This table will grow as fixes are released by maintainers.

---

## Documentation

| | |
|--|--|
| [Installation](docs/installation.md) | pip, from source, uvx, troubleshooting |
| [Quickstart](docs/quickstart.md) | Scan your first MCP server in 5 minutes |
| [Module Reference](docs/modules.md) | All 12 modules — triggers, payloads, CVSS, remediation |
| [Understanding Output](docs/understanding-output.md) | Statuses, CVSS scoring, JSON format, POC scripts |

---

## Installation

```bash
pip install mcpfuzz

# Optional: install Pillow to enable POC terminal screenshot generation
pip install mcpfuzz Pillow
```

Requires Python 3.11+

---

## Quick Start

```bash
# Scan a local MCP server (stdio transport)
mcpfuzz scan --server "npx @modelcontextprotocol/server-filesystem /tmp" --transport stdio

# Scan a remote MCP server (SSE transport)
mcpfuzz scan --server http://localhost:8080 --transport sse

# Run specific modules only
mcpfuzz scan --server "npx @modelcontextprotocol/server-filesystem /tmp" \
  --modules path_traversal,ssrf,command_injection

# JSON output for CI/CD pipelines
mcpfuzz scan --server "python3 my_server.py" --output json --out report.json

# Exit code 1 if HIGH or CRITICAL findings found (default) — use in CI/CD
mcpfuzz scan --server "python3 my_server.py" --fail-on high

# Auto-generate POC scripts + screenshots for every confirmed finding
mcpfuzz scan --server "npx my-mcp-server" --poc-dir ./poc/

# List all available modules
mcpfuzz list-modules
```

---

## Example Output

```
╭──────────────────────────────────────────────────────────╮
│  MCPFuzz — Dynamic MCP Security Scanner                  │
│  Target: npx @modelcontextprotocol/server-filesystem /tmp│
│  Transport: stdio  │  Modules: all (12)                  │
╰──────────────────────────────────────────────────────────╯

  Connected via stdio
  Discovered 3 tools: ['read_file', 'write_file', 'list_directory']
  [Path Traversal] 1 confirmed finding(s)
  [Command Injection] clean
  [Hardcoded Secrets] clean
  ...

╭─────────────────────────╮
│  ✗ VULNERABLE           │
│  Tools discovered: 3    │
│  Confirmed findings: 1  │
│    🟠 HIGH: 1           │
╰─────────────────────────╯

╭──────────────────────────────────────────────────────────────────────╮
│  🟠 1. Path Traversal in 'read_file' via 'path' parameter            │
│  CVSS: 7.5  |  CWE: CWE-22                                           │
│                                                                       │
│  Description:                                                         │
│  The MCP tool 'read_file' does not properly validate the 'path'      │
│  parameter. An attacker can read arbitrary files on the server by    │
│  supplying a path traversal sequence such as '../../etc/passwd'.     │
│                                                                       │
│  Payload: ../../../../etc/passwd                                       │
│                                                                       │
│  Evidence:                                                            │
│  Server returned file content: root:*:0:0:System Administrator:...   │
│                                                                       │
│  Remediation:                                                         │
│  Resolve path to absolute using os.path.realpath(), verify it starts │
│  with the configured base directory before opening.                   │
╰──────────────────────────────────────────────────────────────────────╯

POC files generated:
  poc-a1b2c3d4-path_traversal.py  + poc-a1b2c3d4-path_traversal.png
```

---

## POC Auto-Generation

When MCPFuzz confirms a vulnerability, it automatically generates a **standalone POC script** and a **terminal screenshot** for every confirmed non-INFO finding.

```
poc/
├── poc-a1b2c3d4-path_traversal.py    # Standalone Python script, no MCPFuzz dependency
├── poc-a1b2c3d4-path_traversal.png   # Dark terminal screenshot of expected output
├── poc-b2c3d4e5-ssrf.py
└── poc-b2c3d4e5-ssrf.png
```

The POC script:
- Has **zero MCPFuzz dependency** — uses only the `mcp` SDK
- Automatically sets up the correct transport (stdio or SSE)
- Calls the exact vulnerable tool with the confirmed payload
- Prints color-coded output showing the exploit result
- Includes finding metadata (CWE, CVSS, severity, remediation) in the docstring
- Is ready to run with `python3 poc-<id>-<module>.py`

The terminal PNG shows the expected script output on a dark background — suitable for attaching directly to bug reports.

```bash
# POCs go to ./poc/ by default
mcpfuzz scan --transport stdio --server "npx @wonderwhy-er/desktop-commander"

# Specify a custom output directory
mcpfuzz scan --transport stdio --server "npx ..." --poc-dir ./reports/pocs/
```

Requires `Pillow` for PNG generation (`pip install Pillow`). The script is always generated regardless.

---

## Modules

MCPFuzz ships with 12 active security modules. Each one connects to the live server and tests real behavior.

| Module ID | Name | What It Tests | CWE |
|-----------|------|---------------|-----|
| `path_traversal` | Path Traversal | Filesystem tools — sends `../../../../etc/passwd` payloads, confirms file content in response | CWE-22 |
| `command_injection` | Command Injection | Shell-executing tools — injects `; id`, `$(whoami)`, checks for `uid=` in response | CWE-78 |
| `sql_injection` | SQL Injection | Query tools — error-based, boolean-blind, and time-based detection; auto-detects DB dialect | CWE-89 |
| `ssrf` | SSRF | URL-accepting tools — OOB callback listener confirms server fetched attacker-controlled URL; also probes cloud metadata (`169.254.169.254`) | CWE-918 |
| `auth_bypass` | Auth Bypass | Sensitive tools — calls with empty/null/malformed tokens, checks if access granted | CWE-287/862 |
| `hardcoded_secrets` | Hardcoded Secrets | Tool definitions and config tool responses — AWS keys, GitHub tokens, JWTs, passwords | CWE-798 |
| `dns_rebinding` | DNS Rebinding | HTTP servers — tests Origin header validation per MCP specification requirement (SSE/HTTP only) | CWE-346 |
| `tool_poisoning` | Tool Poisoning | Tool definitions — prompt injection patterns, zero-width Unicode, homoglyph characters, shadow tool attempts | CWE-74 |
| `rug_pull` | Rug Pull Detection | All tools — hashes definitions on first scan, alerts on changes in subsequent scans. Fingerprints servers by tool set for accurate cross-scan comparison | CWE-494 |
| `idor_bola` | IDOR / BOLA | ID-parameter tools — probes with sequential/boundary IDs for broken object authorization | CWE-639 |
| `protocol_fuzzing` | Protocol Fuzzing | All tools — 100KB strings, null bytes, deep nesting, wrong types — detects stack traces | CWE-20 |
| `cve_checks` | CVE Checks | Sends reproduction payloads for 13 known CVEs targeting MCP servers and SDKs | Various |

---

## Supported Transports

| Transport | Flag | Use Case |
|-----------|------|----------|
| stdio | `--transport stdio` | Local MCP servers launched as a subprocess |
| SSE | `--transport sse` | Remote MCP servers via HTTP + Server-Sent Events |
| Streamable HTTP | `--transport streamable-http` | Remote MCP servers via Streamable HTTP (2025-03 spec) |
| HTTP | `--transport http` | Remote MCP servers via plain HTTP |

---

## All CLI Options

```
mcpfuzz scan [OPTIONS]

Options:
  -s, --server TEXT          Server to scan. For stdio: the command to launch
                             it (e.g. 'npx @modelcontextprotocol/server-filesystem /tmp').
                             For sse/http: the server URL.  [required]
  -t, --transport [stdio|sse|http|streamable-http]
                             Transport protocol (default: stdio)
  -m, --modules TEXT         Comma-separated list of module IDs to run.
                             Default: all modules.
                             Example: path_traversal,ssrf,command_injection
  -o, --output [console|json]
                             Output format (default: console)
      --out TEXT             Write output to file (use with --output json)
      --timeout INTEGER      Timeout in seconds per tool call  [default: 30]
      --fail-on [critical|high|medium|low]
                             Exit with code 1 if findings at this severity or
                             above are found  [default: high]
      --token TEXT           Auth token for SSE/HTTP transports (sent as
                             Authorization header)
  -e, --env TEXT             KEY=VALUE environment variable for the server
                             process (stdio only, repeatable)
      --poc-dir TEXT         Auto-generate standalone POC scripts + terminal
                             screenshots into this directory for every confirmed
                             finding
      --llm-key TEXT         API key for LLM-judge (tool_poisoning Pass 2)
      --llm-provider TEXT    LLM provider for judge: anthropic, ollama, openai
                             [default: anthropic]
  -q, --quiet                Suppress progress output, print results only
      --version              Show the version and exit.
      --help                 Show this message and exit.
```

---

## CI/CD Integration

MCPFuzz exits with code `1` if confirmed findings at or above the `--fail-on` threshold are found. Drop it into any pipeline.

```yaml
# .github/workflows/mcp-security.yml
name: MCP Security Scan
on: [push, pull_request]

jobs:
  mcpfuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install mcpfuzz Pillow
      - run: |
          python3 my_mcp_server.py &
          sleep 2
          mcpfuzz scan \
            --server http://localhost:8080 \
            --transport sse \
            --fail-on high \
            --output json \
            --out security-report.json \
            --poc-dir poc/
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: mcpfuzz-report
          path: |
            security-report.json
            poc/
```

---

## Advanced Usage

```bash
# Authenticate with a bearer token (SSE/HTTP transports)
mcpfuzz scan \
  --server http://api.example.com/mcp \
  --transport sse \
  --token "Bearer sk-..."

# Quiet mode — suppress progress, print only results
mcpfuzz scan --server "python3 server.py" --quiet

# Pipe JSON output into jq to filter confirmed findings only
mcpfuzz scan --server "npx my-mcp-server" --output json \
  | jq '.findings[] | select(.status == "confirmed")'

# Only fail the build on CRITICAL findings
mcpfuzz scan --server "npx my-mcp-server" --fail-on critical

# Timeout — allow 60s per tool call (for slow servers)
mcpfuzz scan --server "npx my-mcp-server" --timeout 60

# POC scripts only (no PNG screenshots) — omit Pillow
mcpfuzz scan --server "npx my-mcp-server" --poc-dir ./poc/
```

---

## The MCP Security Problem

MCP (Model Context Protocol) is the standard for connecting AI agents to external tools and data. The attack surface is new, growing fast, and largely unaudited:

- **30+ CVEs in 60 days** targeting MCP implementations (Jan–Feb 2026)
- **82% of MCP servers** vulnerable to path traversal in independent research
- **CVSS 9.6 RCE** confirmed in `mcp-remote` — 437,000+ downloads affected (CVE-2025-6514)
- Official Anthropic MCP servers had chained RCE via path validation bypass (CVE-2025-68143/68144/68145)

Every AI product shipping an MCP integration is shipping an unaudited attack surface. MCPFuzz is built to change that.

---

## Writing a Custom Module

Any module implementing `ScanModule` is automatically discovered via the plugin system.

```python
# my_custom_module.py
from mcpfuzz.modules.base import ScanModule
from mcpfuzz.models import Finding, FindingStatus, Severity
from mcp import ClientSession


class SQLInjectionModule(ScanModule):
    module_id = "sql_injection"
    name = "SQL Injection"
    description = "Tests MCP tools for SQL injection via string parameters"

    async def run(self, session: ClientSession, tools: list[dict]) -> list[Finding]:
        findings = []
        payloads = ["' OR '1'='1", "'; DROP TABLE users;--", "1 UNION SELECT null,null,null--"]

        for tool in tools:
            for param in tool.get("inputSchema", {}).get("properties", {}).keys():
                for payload in payloads:
                    try:
                        result = await session.call_tool(
                            tool["name"],
                            arguments={param: payload}
                        )
                        response_text = " ".join(
                            item.text for item in result.content if hasattr(item, "text")
                        )
                        if any(err in response_text.lower() for err in
                               ["sql syntax", "mysql_fetch", "ora-", "sqlite"]):
                            findings.append(Finding(
                                module_id=self.module_id,
                                title=f"SQL Injection in '{tool['name']}'",
                                severity=Severity.CRITICAL,
                                status=FindingStatus.CONFIRMED,
                                cvss_score=9.8,
                                description="SQL error in response confirms injection point.",
                                tool_name=tool["name"],
                                payload_used=payload,
                                payload_args={param: payload},  # enables POC auto-generation
                                evidence=response_text[:200],
                                remediation="Use parameterised queries. Never concatenate user input into SQL.",
                                cwe_id="CWE-89",
                            ))
                    except Exception:
                        pass
        return findings
```

Register it:
```toml
[project.entry-points."mcpfuzz.modules"]
sql_injection = "my_package.my_custom_module:SQLInjectionModule"
```

Set `payload_args` on your `Finding` to enable automatic POC script generation for your custom module.

---

## False Positive Tuning

MCPFuzz has been tested against 20+ real-world MCP servers and has gone through several rounds of FP elimination. The following patterns were removed:

| FP | Root Cause | Fix |
|----|-----------|-----|
| Auth Bypass — keyboard keys flagged as auth params | `browser_press_key.key` matched `AUTH_PARAM_NAMES` | Added `NON_AUTH_PARAM_DESCRIPTIONS` exclusion filter |
| Auth Bypass — connectivity errors treated as success | "Session not found" / "Executable doesn't exist" had no match in error patterns | Added 10+ error patterns: `failed`, `not found`, `invalid url`, `doesn't exist`, MCP JSON-RPC errors (`-32xxx`), `unavailable` |
| Tool Poisoning — legitimate AI guidance flagged | "Always use the latest snapshot." matched `(always\|never) (respond\|say\|tell\|use)` | Removed `use` from the alternation |
| Tool Poisoning — HTTP client tools flagged for exfil | `playwright_post` URL parameter matched hidden instruction pattern | Tools ending in `_post/_get/_put/_patch/_delete` skip exfil check |
| Tool Poisoning — CJK characters flagged as homoglyphs | Chinese/Arabic/Devanagari characters incorrectly detected as Unicode lookalikes | Non-Latin script ranges excluded from homoglyph detection |
| Rug Pull — cross-server baseline collision | `server_id` always resolved to `"unknown"` for stdio transport | Server fingerprinted by sorted set of tool names when transport attributes unavailable |

---

## Responsible Disclosure

MCPFuzz is intended for:
- Testing MCP servers **you own or have explicit written permission to test**
- Security research with responsible disclosure
- CI/CD integration in your own development pipeline

All CVEs found using MCPFuzz by Cyberneticsplus are disclosed responsibly following a 90-day vendor notification process before public disclosure.

**Do not use this tool against servers you do not own or have permission to test.**

---

## Contributing

Contributions welcome — especially new test modules for emerging MCP attack patterns.

1. Fork the repo
2. Implement your module in `src/mcpfuzz/modules/your_module.py` following the `ScanModule` interface
3. Register it in `src/mcpfuzz/modules/__init__.py`
4. Set `payload_args` on confirmed `Finding` objects to enable POC auto-generation
5. Submit a PR with a description of what the module tests and example output

---

## About

Built and maintained by **[Cyberneticsplus Services Private Limited](https://cyberneticsplus.com)** — AI security research and penetration testing.

CVE research contact: info@cyberneticsplus.com

---

## Other Tools from Cyberneticsplus

| Tool | Description |
|------|-------------|
| [SecurityStatus.io](https://securitystatus.io) | Automated domain security scanner — checks DNS, SSL, email authentication, HTTP headers, and vulnerability exposure in one report |
| [AIWorkview](https://aiworkview.com) | AI-agent-native project management — task tracking and coordination built for AI teams and autonomous agent workflows |

---

## License

MIT — free to use, modify, and distribute. See [LICENSE](LICENSE).
