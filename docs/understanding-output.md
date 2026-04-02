# Understanding Output & CVSS Scores

---

## Finding statuses

Every finding MCPFuzz reports has one of three statuses:

| Status | Meaning |
|--------|---------|
| `confirmed` | MCPFuzz sent a payload and received evidence that the vulnerability is exploitable — e.g. `/etc/passwd` contents in a path traversal, or a database error string in a SQL injection response |
| `potential` | The tool looks like it could be vulnerable (matching parameter names, suspicious behaviour) but MCPFuzz couldn't get conclusive evidence — manual verification recommended |
| `info` | Informational finding — no vulnerability, but something worth knowing. Example: a tool with no auth parameters on an otherwise-authenticated server, or a finding that was excluded as by-design |

In JSON output, `status` is one of `"confirmed"`, `"potential"`, or `"info"`.

---

## Severity levels

| Severity | CVSS Range | Colour |
|----------|-----------|--------|
| CRITICAL | 9.0–10.0 | Red |
| HIGH | 7.0–8.9 | Orange |
| MEDIUM | 4.0–6.9 | Yellow |
| LOW | 1.0–3.9 | Blue |
| INFO | 0.0 | Grey |

---

## How CVSS scores are assigned

MCPFuzz assigns CVSS v3.1 base scores per finding, not per module. The score depends on the **vulnerability class** and the **transport** the server uses.

### Transport-aware scoring

The transport matters because it determines whether an attacker needs local access or can exploit the server remotely over a network.

| Transport | Exposure | Effect on score |
|-----------|----------|-----------------|
| `stdio` | Local process only — attacker needs code execution on the same machine | Scores are lower (HIGH rather than CRITICAL for most classes) |
| `sse` / `http` / `streamable-http` | Network-exposed — attacker can reach the server from the internet or LAN | Scores are higher (CRITICAL for SSRF and command injection) |

**Example — SSRF:**
- stdio server: **HIGH / CVSS 7.5** — exploiting SSRF requires local access first
- SSE/HTTP server: **CRITICAL / CVSS 9.1** — SSRF is remotely exploitable, no prior access needed

### Score reference by module

| Module | stdio | SSE / HTTP |
|--------|-------|------------|
| `path_traversal` | 7.5–8.5 HIGH | 8.5 HIGH |
| `command_injection` | 9.8 CRITICAL | 9.8 CRITICAL |
| `sql_injection` | 7.2–9.8 HIGH–CRITICAL | 8.8–9.8 CRITICAL |
| `ssrf` | 7.5 HIGH | 9.1 CRITICAL |
| `auth_bypass` | 8.1–9.8 HIGH–CRITICAL | 8.1–9.8 CRITICAL |
| `hardcoded_secrets` | 7.5–9.0 HIGH | 7.5–9.0 HIGH |
| `dns_rebinding` | N/A (skipped) | 7.5 HIGH |
| `tool_poisoning` | 8.0–9.0 HIGH | 8.0–9.0 HIGH |
| `rug_pull` | 8.0–9.0 HIGH | 8.0–9.0 HIGH |
| `idor_bola` | 6.5–8.5 MEDIUM–HIGH | 6.5–8.5 MEDIUM–HIGH |
| `protocol_fuzzing` | 5.0–7.5 MEDIUM–HIGH | 5.0–7.5 MEDIUM–HIGH |
| `cve_checks` | Varies (5.0–9.8) | Varies (5.0–9.8) |

---

## Console output

### Summary box

```
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
```

The header line is either `✗ VULNERABLE`, `✓ CLEAN`, or `⚠ POTENTIAL` depending on whether any confirmed, no findings, or only potential findings exist.

### Findings table

```
┌──────────────────────────────────────────────────────────────────────┐
│ Findings                                                             │
├──────────────┬───────────┬────────────────┬───────────┬─────────────┤
│ Severity     │ Status    │ Module         │ Tool      │ Title       │
├──────────────┼───────────┼────────────────┼───────────┼─────────────┤
│ 🟠 HIGH     │ confirmed │ path_traversal │ read_file │ Path Trav…  │
│ 🟠 HIGH     │ confirmed │ path_traversal │ list_dir  │ Path Trav…  │
│ 🟡 MEDIUM   │ potential │ ssrf           │ read_file │ SSRF via…   │
└──────────────┴───────────┴────────────────┴───────────┴─────────────┘
```

### Finding detail block

```
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

Each detail block includes:
- **CVSS score and CWE** — the numeric score and the CWE ID
- **Description** — what was found and in which tool/parameter
- **Payload** — the exact input MCPFuzz sent that triggered the finding
- **Evidence** — the fragment of the server's response that confirms the vulnerability
- **Remediation** — a concrete fix specific to the vulnerability class

---

## JSON output

Use `--output json --out results.json` to get machine-readable output. This is the recommended format for CI/CD pipelines.

### Top-level structure

```json
{
  "scan_id": "abc12345",
  "target": "npx -y @modelcontextprotocol/server-filesystem /tmp",
  "transport": "stdio",
  "modules": ["path_traversal", "ssrf", "..."],
  "started_at": "2026-04-02T10:00:00Z",
  "completed_at": "2026-04-02T10:00:45Z",
  "tools_discovered": 5,
  "summary": {
    "status": "vulnerable",
    "confirmed": 2,
    "potential": 1,
    "info": 1,
    "critical": 0,
    "high": 2,
    "medium": 0,
    "low": 0
  },
  "findings": [ ... ]
}
```

### Finding object

```json
{
  "id": "abc12345-001",
  "title": "Path Traversal in 'read_file'",
  "status": "confirmed",
  "severity": "high",
  "cvss": 7.5,
  "cwe": "CWE-22",
  "module": "path_traversal",
  "tool": "read_file",
  "parameter": "path",
  "payload": "../../../../etc/passwd",
  "evidence": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
  "description": "The read_file tool returned content from outside the allowed directory when given a traversal payload in the 'path' parameter.",
  "remediation": "Resolve all paths with os.path.realpath() before use. Check that the resolved path still starts with the allowed base directory."
}
```

### Filtering with jq

```bash
# Confirmed findings only
cat results.json | jq '.findings[] | select(.status == "confirmed")'

# CRITICAL and HIGH findings
cat results.json | jq '.findings[] | select(.severity == "critical" or .severity == "high")'

# Just the payloads and tool names
cat results.json | jq '.findings[] | {tool, payload, severity}'

# Exit non-zero if any confirmed HIGH/CRITICAL finding exists
cat results.json | jq -e '.findings[] | select(.status == "confirmed" and (.severity == "high" or .severity == "critical"))' > /dev/null
```

---

## POC scripts

When you pass `--poc-dir ./poc/`, MCPFuzz writes a self-contained Python script for each confirmed finding:

```
poc/
├── abc12345-001.py     ← reproduces path traversal in read_file
├── abc12345-001.png    ← terminal screenshot (requires Pillow)
└── abc12345-002.py     ← reproduces path traversal in list_directory
```

Each script:
- Has zero external dependencies beyond the `mcp` SDK
- Connects to the server using the same transport you scanned with
- Sends the exact payload that triggered the finding
- Prints the server response and a pass/fail verdict

```bash
# Run a POC to verify the finding is reproducible
python3 poc/abc12345-001.py
```

POC scripts are useful for:
- Reproducing a finding before reporting it to the developer
- Verifying a fix actually closes the vulnerability
- Including in bug reports as self-contained reproducers

---

## What to do with findings

### Confirmed findings

These are real vulnerabilities with evidence. Prioritise them by CVSS score:

1. **CRITICAL (9.0+):** Fix immediately. Command injection and unauthenticated SSRF on network-exposed servers fall here. These are remotely exploitable without any prior access.
2. **HIGH (7.0–8.9):** Fix before your next release. Path traversal, SQL injection, and auth bypass findings land here.
3. **MEDIUM (4.0–6.9):** Plan a fix in the current sprint. IDOR/BOLA and most protocol fuzzing findings.
4. **LOW (1.0–3.9):** Schedule for the next maintenance window.

### Potential findings

Review manually. MCPFuzz found a pattern that *looks* like a vulnerability but couldn't prove exploitability. Common reasons a finding is `potential` rather than `confirmed`:

- The tool accepts URLs but only fetches from an allowlisted set (SSRF)
- Path traversal payloads were sent but the server returned an error, not file content
- An auth parameter exists but the bypass attempt returned the same result as the baseline (ambiguous)

Use the `--poc-dir` output to dig deeper, or test the payload manually against your server.

### Info findings

No action required unless you want to investigate further. Example: `hardcoded_secrets` reports `info` when the schema scan finds no secrets — this confirms the check ran and found nothing.

---

## Suppressing false positives

If a finding is a known false positive (e.g. a browser automation tool correctly flagging as SSRF because fetching URLs is its purpose), you can:

- Use `--modules` to skip that module for that server
- For CI/CD, use `--fail-on critical` instead of `--fail-on high` to let HIGH findings through while still blocking CRITICAL ones

```bash
# Only fail the build on CRITICAL findings
mcpfuzz scan --server "..." --fail-on critical

# Skip SSRF checks on a server that intentionally fetches URLs
mcpfuzz scan --server "..." --modules path_traversal,command_injection,sql_injection
```
