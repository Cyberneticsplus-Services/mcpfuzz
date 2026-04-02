"""
Protocol Fuzzing Module
Targets: All MCP servers.
Method: Sends malformed JSON-RPC messages — missing fields, wrong types,
        oversized payloads, recursive nesting, boundary values.
        Detects crashes, stack traces, and unexpected information disclosure.
CWE-20: Improper Input Validation / CWE-703: Failure to Handle Exceptional Conditions
"""

import re
import anyio
from mcp import ClientSession

from .base import ScanModule
from ..models import Finding, FindingStatus, Severity


# Evidence of implementation details leaking in error messages
STACK_TRACE_PATTERNS = [
    re.compile(r"Traceback \(most recent call last\)"),  # Python
    re.compile(r"at \w+\.\w+\(<\w+>:\d+:\d+\)"),         # Node.js
    re.compile(r"Exception in thread"),                    # Java
    re.compile(r"System\.NullReferenceException"),         # .NET
    re.compile(r"panic: "),                                # Go
    re.compile(r"thread '.*' panicked at"),                # Rust
    re.compile(r"SIGSEGV|Segmentation fault"),             # Native crash
]

INTERNAL_PATH_PATTERNS = [
    # Require a deeper path component to avoid matching shebangs (#!/usr/bin/env) and short refs
    re.compile(r"/home/\w+/"),
    re.compile(r"/root/\w"),
    re.compile(r"/var/(log|lib|run|www|data)/"),
    re.compile(r"/usr/(local|share|lib)/"),
    re.compile(r"C:\\Users\\\w"),
    re.compile(r"C:\\Program Files"),
    re.compile(r"\.(py|js|ts|go|rb|java):\d+"),           # Source file with line number (traceback)
    re.compile(r"File \"[^\"]+\", line \d+"),              # Python traceback
]

# Server info that genuinely indicates internal details leaking in error responses.
# Patterns here must NOT match normal tool output. Rules:
#   - "version X.Y" appears in thousands of legitimate API responses and help text
#     → only flag when it looks like an HTTP Server header in the response body
#   - "running on X" is used in documentation and log summaries
#     → only flag when followed by a network address (IP:port or hostname:port)
#   - database connection strings with credentials ARE a leak wherever they appear
INFO_LEAK_PATTERNS = [
    # HTTP Server header appearing in response body (not a header, but body text)
    # e.g. "Server: gunicorn/21.2.0" or "X-Powered-By: Express/4.18"
    re.compile(r"(?:Server|X-Powered-By|X-Framework):\s*\S+/[\d.]+", re.IGNORECASE),
    # Bind/listen address with an actual port number — not a description sentence
    re.compile(
        r"(?:running on|listening on|bound to)\s+"
        r"(?:0\.0\.0\.0|\d{1,3}(?:\.\d{1,3}){3}|localhost|127\.0\.0\.1|[\w.-]+):\d{2,5}",
        re.IGNORECASE,
    ),
    # Database connection details with credentials
    re.compile(r"database\s+(?:connection|host|name)\s*[:=]\s*\S+", re.IGNORECASE),
    # Explicit DB DSN/URI leaking credentials
    re.compile(r"(?:postgres|mysql|mongodb|redis|sqlite)://[^@\s]+@[^/\s]+", re.IGNORECASE),
]


def _extract_error_text(exc: Exception) -> str:
    return str(exc)


def _extract_text(result) -> str:
    parts = []
    for item in result.content:
        if hasattr(item, "text"):
            parts.append(item.text)
        elif isinstance(item, dict) and "text" in item:
            parts.append(item["text"])
    return "\n".join(parts)


def _check_for_leaks(text: str) -> tuple[str, str] | None:
    """Returns (leak_type, evidence) if sensitive info found, else None."""
    for pattern in STACK_TRACE_PATTERNS:
        m = pattern.search(text)
        if m:
            return ("Stack Trace", text[max(0, m.start()-20):m.start()+300].strip())
    for pattern in INTERNAL_PATH_PATTERNS:
        m = pattern.search(text)
        if m:
            return ("Internal Path Disclosure", text[max(0, m.start()-20):m.start()+150].strip())
    for pattern in INFO_LEAK_PATTERNS:
        m = pattern.search(text)
        if m:
            return ("Server Info Leak", text[max(0, m.start()-10):m.start()+100].strip())
    return None


class ProtocolFuzzingModule(ScanModule):
    module_id = "protocol_fuzzing"
    name = "Protocol Fuzzing"
    description = "Sends malformed JSON-RPC inputs to all tools looking for crashes, stack traces, and information disclosure (CWE-20)"

    async def run(self, session: ClientSession, tools: list[dict]) -> list[Finding]:
        findings: list[Finding] = []

        for tool in tools:
            tool_name = tool["name"]
            schema = tool.get("inputSchema", {})
            properties = schema.get("properties", {})

            if not properties:
                # No parameters — tool ignores all args and returns its normal response.
                # Get a baseline first; only flag leaks that appear in the fuzz response
                # but NOT in the baseline, to prevent flagging normal tool output as
                # info disclosure (FIND-018 class false positive).
                baseline_text = await self._get_baseline_text(session, tool)
                fuzz_cases = [
                    ("Unexpected extra args", {"__fuzz__": "A" * 10000, "__inject__": "<script>"}),
                    ("Null value args", {"__null__": None}),
                ]
            else:
                param_names = list(properties.keys())
                first_param = param_names[0]
                fuzz_cases = [
                    # Oversized input — 10KB is enough to trigger issues without crashing transport
                    ("Oversized string (10KB)", {first_param: "A" * 10_000}),
                    # Null/None
                    ("Null value", {first_param: None}),
                    # Wrong type — number where string expected
                    ("Integer instead of string", {first_param: 2**63}),
                    # Empty object
                    ("Empty object", {first_param: {}}),
                    # Array input
                    ("Array instead of string", {first_param: ["a", "b", "c"]}),
                    # Deeply nested object
                    ("Deeply nested object (50 levels)", {first_param: self._deep_nest(50)}),
                    # Null bytes
                    ("Null bytes", {first_param: "test\x00injection\x00"}),
                    # Unicode edge case (use replacement chars, not real surrogates — surrogates break JSON)
                    ("Unicode edge chars", {first_param: "\ufffd\ufffe\uffff"}),
                    # Format string attempt
                    ("Format string patterns", {first_param: "%s%s%s%s%n%d"}),
                    # XML/template injection probes
                    ("Template injection", {first_param: "{{7*7}}${7*7}<%=7*7%>"}),
                    # All params set to null
                    ("All params null", {p: None for p in param_names}),
                ]

            for fuzz_name, fuzz_args in fuzz_cases:
                try:
                    result = await session.call_tool(tool_name, arguments=fuzz_args)
                    response_text = _extract_text(result)
                    leak = _check_for_leaks(response_text)
                    # For no-arg tools: skip if the same leak appears in the baseline response.
                    # The tool always returns this content regardless of input — it's not a
                    # vulnerability reaction, just normal output (prevents FIND-018 class FPs).
                    if leak and not properties and baseline_text:
                        _, evidence_candidate = leak
                        if evidence_candidate[:80] in baseline_text:
                            continue
                    if leak:
                        leak_type, evidence = leak
                        findings.append(Finding(
                            module_id=self.module_id,
                            title=f"{leak_type} in '{tool_name}' Error Response",
                            severity=Severity.MEDIUM,
                            status=FindingStatus.CONFIRMED,
                            cvss_score=5.3,
                            description=(
                                f"The tool '{tool_name}' leaks {leak_type.lower()} when called "
                                f"with malformed input ({fuzz_name}). This information helps "
                                f"attackers understand the server's internals and craft targeted exploits."
                            ),
                            tool_name=tool_name,
                            payload_used=fuzz_name,
                            evidence=evidence,
                            remediation=(
                                "Implement generic error responses for unexpected inputs. "
                                "Never include stack traces, file paths, or internal details in "
                                "production error messages. Log details server-side only."
                            ),
                            cwe_id="CWE-209",
                        ))

                except Exception as exc:
                    error_text = _extract_error_text(exc)
                    leak = _check_for_leaks(error_text)
                    if leak:
                        leak_type, evidence = leak
                        findings.append(Finding(
                            module_id=self.module_id,
                            title=f"{leak_type} in '{tool_name}' Exception",
                            severity=Severity.MEDIUM,
                            status=FindingStatus.CONFIRMED,
                            cvss_score=5.3,
                            description=(
                                f"Exception from '{tool_name}' with malformed input ({fuzz_name}) "
                                f"contains {leak_type.lower()}."
                            ),
                            tool_name=tool_name,
                            payload_used=fuzz_name,
                            evidence=evidence,
                            remediation="Return generic error messages to clients. Log detailed errors server-side only.",
                            cwe_id="CWE-209",
                        ))

        return findings

    def _deep_nest(self, depth: int) -> dict:
        obj: dict = {"leaf": "value"}
        for _ in range(depth):
            obj = {"nested": obj}
        return obj
