# MCPFuzz Plugin Development Guide

Writing a custom scan module for MCPFuzz.

---

## The ScanModule Interface

Every module must extend `ScanModule` and implement `run()`.

```python
from abc import ABC, abstractmethod
from mcp import ClientSession
from mcpfuzz.models import Finding

class ScanModule(ABC):
    module_id: str        # Unique snake_case ID, e.g. "sql_injection"
    name: str             # Human-readable name, e.g. "SQL Injection"
    description: str      # One-line description shown in mcpfuzz list-modules

    async def run(self, session: ClientSession, tools: list[dict]) -> list[Finding]:
        ...
```

Rules:
- `run()` must never raise exceptions — catch internally and return `Finding(status=ERROR)` if needed
- `run()` returns an empty list if nothing is found — never `None`
- Each `Finding` must have `status=CONFIRMED` (evidence in server response) or `status=POTENTIAL` (heuristic match)

---

## The Finding Model

```python
from mcpfuzz.models import Finding, FindingStatus, Severity

Finding(
    module_id="my_module",           # Your module's module_id
    title="Descriptive title",       # Short, specific — includes tool name
    severity=Severity.HIGH,          # CRITICAL / HIGH / MEDIUM / LOW / INFO
    status=FindingStatus.CONFIRMED,  # CONFIRMED / POTENTIAL / NOT_VULN / ERROR
    cvss_score=7.5,                  # CVSS 3.1 base score
    description="Full description",  # What the vulnerability is and its impact
    tool_name="read_file",           # The MCP tool that was called
    payload_used="../../etc/passwd", # Exact payload sent
    evidence="root:x:0:0:...",       # What in the response proves exploitation
    remediation="How to fix it",     # Specific, actionable remediation
    cwe_id="CWE-22",                 # Optional CWE reference
)
```

---

## Calling MCP Tools

The `session` parameter is a live `mcp.ClientSession`. Call any tool like this:

```python
result = await session.call_tool(
    tool_name,
    arguments={"param_name": "your_payload"}
)

# Extract text from the result
response_text = "\n".join(
    item.text for item in result.content if hasattr(item, "text")
)
```

---

## Discovering Tool Parameters

The `tools` list contains dicts serialized from the MCP `tools/list` response:

```python
{
    "name": "read_file",
    "description": "Read the contents of a file",
    "inputSchema": {
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "Path to the file"
            }
        },
        "required": ["path"]
    }
}
```

Helper from the base class:
```python
# Returns parameter names that accept string values
string_params = self._get_string_params(tool)
```

---

## CVSS Scoring Reference

| Vulnerability Type | Typical CVSS | Vector |
|-------------------|-------------|--------|
| Unauthenticated RCE | 9.8 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| SSRF to cloud metadata | 9.1 | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N |
| Path traversal (read-only) | 7.5 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N |
| Auth bypass | 8.1 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N |
| Info disclosure (stack trace) | 5.3 | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N |

---

## Full Example Module

```python
"""
XML Injection Module — tests MCP tools for XXE vulnerabilities.
"""
import re
from mcp import ClientSession
from mcpfuzz.modules.base import ScanModule
from mcpfuzz.models import Finding, FindingStatus, Severity

XXE_PAYLOAD = """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>"""

PASSWD_PATTERN = re.compile(r"root:.*:/bin/(bash|sh)", re.IGNORECASE)


class XXEModule(ScanModule):
    module_id = "xxe"
    name = "XML External Entity (XXE)"
    description = "Tests XML-accepting MCP tools for XXE injection (CWE-611)"

    async def run(self, session: ClientSession, tools: list[dict]) -> list[Finding]:
        findings = []
        for tool in tools:
            # Only target tools that likely process XML
            if not any(kw in tool.get("description", "").lower()
                       for kw in ["xml", "parse", "document", "svg", "html"]):
                continue

            for param in self._get_string_params(tool):
                try:
                    result = await session.call_tool(
                        tool["name"],
                        arguments={param: XXE_PAYLOAD}
                    )
                    response_text = "\n".join(
                        item.text for item in result.content if hasattr(item, "text")
                    )
                    if PASSWD_PATTERN.search(response_text):
                        findings.append(Finding(
                            module_id=self.module_id,
                            title=f"XXE Injection in '{tool['name']}' via '{param}'",
                            severity=Severity.HIGH,
                            status=FindingStatus.CONFIRMED,
                            cvss_score=7.5,
                            description=(
                                f"The tool '{tool['name']}' processes XML with external entities "
                                f"enabled, allowing file read via XXE injection."
                            ),
                            tool_name=tool["name"],
                            payload_used=XXE_PAYLOAD[:80] + "...",
                            evidence=f"Server returned /etc/passwd content: {response_text[:200]}",
                            remediation=(
                                "Disable external entity processing. In Python's lxml: "
                                "use `resolve_entities=False`. In Java: "
                                "`factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)`"
                            ),
                            cwe_id="CWE-611",
                        ))
                        break
                except Exception:
                    pass
        return findings
```

---

## Registering Your Module (Package Distribution)

If distributing as a package, register via `pyproject.toml`:

```toml
[project.entry-points."mcpfuzz.modules"]
xxe = "my_package.xxe_module:XXEModule"
```

After `pip install my_package`, MCPFuzz will discover your module automatically.

---

## Testing Your Module

```python
# tests/test_xxe_module.py
import pytest
import anyio
from unittest.mock import AsyncMock, MagicMock
from my_package.xxe_module import XXEModule
from mcpfuzz.models import FindingStatus

@pytest.mark.anyio
async def test_detects_xxe():
    module = XXEModule()

    mock_result = MagicMock()
    mock_result.content = [MagicMock(text="root:x:0:0:root:/root:/bin/bash")]

    mock_session = AsyncMock()
    mock_session.call_tool.return_value = mock_result

    tools = [{
        "name": "parse_xml",
        "description": "Parse an XML document",
        "inputSchema": {
            "type": "object",
            "properties": {"content": {"type": "string"}},
            "required": ["content"]
        }
    }]

    findings = await module.run(mock_session, tools)
    assert len(findings) == 1
    assert findings[0].status == FindingStatus.CONFIRMED
```
