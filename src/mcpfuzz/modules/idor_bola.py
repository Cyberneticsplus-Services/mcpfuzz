"""
IDOR / BOLA (Broken Object Level Authorization) Module
Targets: MCP tools with ID, user, or resource parameters.
Method: Tests whether resource identifiers can be manipulated to access
        objects belonging to other users or outside the caller's scope.
CWE-639: Authorization Bypass Through User-Controlled Key
"""

import re
from mcp import ClientSession

from .base import ScanModule
from ..models import Finding, FindingStatus, Severity


# Parameter names that suggest resource identifiers
ID_PARAM_NAMES = [
    "id", "user_id", "userid", "account_id", "resource_id",
    "document_id", "file_id", "object_id", "record_id",
    "project_id", "org_id", "tenant_id", "customer_id",
    "message_id", "thread_id", "channel_id", "workspace_id",
    "item_id", "entity_id", "owner", "owner_id",
]

# IDOR test values — sequential/predictable IDs + boundary values
IDOR_PAYLOADS = [
    "1",
    "0",
    "-1",
    "2",
    "100",
    "1000",
    "99999",
    "admin",
    "root",
    "0000000000000000000000000000000",  # Zero UUID-like
    "00000000-0000-0000-0000-000000000000",  # Null UUID
    "../other_user",
    "*",
    "null",
]

# Patterns that suggest we've accessed another user's data
CROSS_USER_PATTERNS = [
    re.compile(r'"(user|owner|email|username)":\s*"[^"]{3,}"'),
    re.compile(r'"(account|profile|settings)"\s*:\s*\{'),
    re.compile(r"@[a-zA-Z0-9._%+-]+\.[a-zA-Z]{2,}"),  # email in response
    re.compile(r'"(balance|credit|payment|invoice)"\s*:\s*[\d.]+'),  # financial data
    re.compile(r'"(secret|private|confidential|internal)"\s*:\s*"'),
]


def _extract_text(result) -> str:
    parts = []
    for item in result.content:
        if hasattr(item, "text"):
            parts.append(item.text)
        elif isinstance(item, dict) and "text" in item:
            parts.append(item["text"])
    return "\n".join(parts)


def _looks_like_data(text: str) -> str | None:
    """
    Returns evidence if the response contains recognisable user-data indicators.

    Requires a CROSS_USER_PATTERN match — a specific field name (user, email,
    balance, secret, etc.) that makes the response look like it contains another
    user's record. The previous fallback "any JSON > 50 chars" is intentionally
    removed: virtually every database/storage MCP tool returns substantial JSON
    for a valid ID, so that heuristic flagged all of them as IDOR regardless of
    whether the data was sensitive or access-controlled.
    """
    if len(text) < 10:
        return None
    # Hard stop on clear error responses — no point checking further
    error_keywords = ["not found", "no such", "does not exist", "invalid id",
                      "forbidden", "unauthorized", "access denied", "error"]
    if any(kw in text.lower() for kw in error_keywords):
        return None
    # Only flag when a specific sensitive-data pattern is present in the response
    for pattern in CROSS_USER_PATTERNS:
        m = pattern.search(text)
        if m:
            return text[max(0, m.start()-20):m.start()+100].strip()
    return None


def _has_id_param(tool: dict) -> list[str]:
    """
    Return parameter names that represent access-controlled resource identifiers.

    Only matches the curated ID_PARAM_NAMES list — NOT the generic endswith("_id")
    pattern. The generic suffix catch included params like trace_id, request_id,
    revision_id, log_id, event_id, version_id — none of which are access-control
    boundaries. Including them caused every observability/versioning/logging tool
    to be tested for IDOR, generating high false-positive rates globally.

    If a tool has a genuinely security-relevant ID param that's not in this list,
    add it to ID_PARAM_NAMES explicitly so the decision is documented.
    """
    schema = tool.get("inputSchema", {})
    props = schema.get("properties", {})
    return [name for name in props if name.lower() in ID_PARAM_NAMES]


class IDORBOLAModule(ScanModule):
    module_id = "idor_bola"
    name = "IDOR / BOLA"
    description = "Tests MCP tools with resource ID parameters for Broken Object Level Authorization (CWE-639) by probing with predictable and boundary IDs"

    async def run(self, session: ClientSession, tools: list[dict]) -> list[Finding]:
        findings: list[Finding] = []

        for tool in tools:
            tool_name = tool["name"]
            id_params = _has_id_param(tool)
            if not id_params:
                continue

            schema = tool.get("inputSchema", {})
            all_params = list(schema.get("properties", {}).keys())

            for id_param in id_params:
                confirmed = False
                for payload in IDOR_PAYLOADS:
                    if confirmed:
                        break
                    try:
                        # Build args: fill non-ID params with dummy values
                        args = {p: "test" for p in all_params}
                        args[id_param] = payload

                        result = await session.call_tool(tool_name, arguments=args)
                        response_text = _extract_text(result)
                        evidence = _looks_like_data(response_text)

                        if evidence:
                            findings.append(Finding(
                                module_id=self.module_id,
                                title=f"Potential IDOR in '{tool_name}' via '{id_param}' Parameter",
                                severity=Severity.HIGH,
                                status=FindingStatus.POTENTIAL,
                                cvss_score=7.5,
                                description=(
                                    f"The MCP tool '{tool_name}' returned data when called with "
                                    f"'{id_param}={payload}' — a predictable/test ID value. "
                                    f"This may indicate that object-level authorization is not enforced, "
                                    f"allowing any caller to access any resource by guessing its ID."
                                ),
                                tool_name=tool_name,
                                payload_used=f"{id_param}={payload}",
                                evidence=f"Tool returned data for test ID: {evidence}",
                                remediation=(
                                    "Implement object-level authorization: verify that the calling user "
                                    "owns or has permission to access the requested resource. "
                                    "Do not rely solely on obscure/unguessable IDs for access control. "
                                    "Use UUIDs + authorization checks, not sequential integers."
                                ),
                                cwe_id="CWE-639",
                            ))
                            confirmed = True
                    except Exception:
                        pass

        return findings
