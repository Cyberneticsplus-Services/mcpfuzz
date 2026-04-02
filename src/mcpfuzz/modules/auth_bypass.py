"""
Authentication Bypass Module
Targets: MCP tools that enforce authentication/authorization.
Method: Dynamic, schema-aware testing:
        1. Detects whether the server uses MCP-level auth at all (has any auth params)
        2. For auth params: establishes a baseline (random UUID) — if baseline fails but
           bypass payload succeeds, it's a true auth bypass.
           If baseline also succeeds, it's Missing Auth (CWE-862) not a bypass.
        3. For sensitive tools with no required params: only tests when the server
           demonstrably uses MCP-level auth on other tools.
CWE-287: Improper Authentication / CWE-862: Missing Authorization
"""

import re
import uuid
from mcp import ClientSession

from .base import ScanModule
from ..models import Finding, FindingStatus, Severity


# Tool names that suggest sensitive / auth-protected operations
SENSITIVE_TOOL_KEYWORDS = [
    "admin", "delete", "remove", "update", "create", "write",
    "user", "account", "password", "secret", "private", "internal",
    "manage", "config", "settings", "grant", "revoke", "token",
    "auth", "login", "register", "reset", "drop", "purge", "truncate",
    "execute", "run", "deploy", "publish",
]

# Strong auth indicators — parameter name alone is enough evidence
STRONG_AUTH_PARAMS = {
    "token", "auth", "authorization", "api_key", "apikey",
    "access_token", "bearer", "jwt", "session", "session_id",
    "credential", "credentials", "password", "passwd", "passphrase",
    "auth_token", "x-api-key", "x_api_key",
}

# Weak auth indicators — only treat as auth param if description confirms it
WEAK_AUTH_PARAMS = {"key", "secret"}

# Description terms that confirm a "weak" param is actually an auth token
AUTH_CONFIRMING_TERMS = [
    "authentication", "api key", "access", "token", "authorization",
    "auth", "credential", "bearer", "secret key", "api-key", "apikey",
]

# Description terms that confirm a "key" param is NOT an auth token
NON_AUTH_PARAM_DESCRIPTIONS = [
    "keyboard", "press", "keystroke", "hotkey", "shortcut",
    "key to press", "character to", "name of the key", "key name",
    "button", "keybinding",
    # Database / storage key names
    "redis key", "cache key", "database key", "record key",
    "the key to", "key in", "key for the", "key of the",
    "sort key", "partition key", "primary key", "foreign key",
    "encryption key", "object key", "map key", "dict key",
]

# Bypass payloads — ordered from most dangerous to least
AUTH_BYPASS_PAYLOADS = [
    ("Empty string",       ""),
    ("Null string",        "null"),
    ("None string",        "None"),
    ("Whitespace",         "   "),
    ("Zero",               "0"),
    ("Malformed JWT",      "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9."),
    ("Algorithm none JWT", "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwicm9sZSI6ImFkbWluIn0."),
    ("Expired JWT",        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE1MTYyMzkwMjJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"),
    ("SQL injection",      "' OR '1'='1"),
    ("Admin literal",      "admin"),
    ("True string",        "true"),
]

# Patterns that indicate a real auth rejection — response is NOT a success
AUTH_ERROR_PATTERNS = [
    # Standard HTTP / API auth errors
    re.compile(r"unauthorized", re.IGNORECASE),
    re.compile(r"forbidden", re.IGNORECASE),
    re.compile(r"authentication (required|failed|error)", re.IGNORECASE),
    re.compile(r"access denied", re.IGNORECASE),
    re.compile(r"permission denied", re.IGNORECASE),
    re.compile(r'"error"', re.IGNORECASE),
    re.compile(r"\b401\b|\b403\b"),
    # Token/credential specific rejections — match with words between
    re.compile(r"(invalid|expired|revoked|bad|malformed).{0,30}(token|key|credential|session|jwt)", re.IGNORECASE),
    re.compile(r"(token|key|credential|session|jwt).{0,30}(invalid|expired|revoked|bad|malformed)", re.IGNORECASE),
    re.compile(r"\bexpired\b", re.IGNORECASE),
    re.compile(r"confirmation.{0,20}token", re.IGNORECASE),
    re.compile(r"please.*again", re.IGNORECASE),
    re.compile(r"(wrong|incorrect).{0,20}(token|key|password|credential)", re.IGNORECASE),
    # Application / connectivity errors — tool failed, not auth success
    re.compile(r"^Error:", re.IGNORECASE | re.MULTILINE),
    re.compile(r"no connection", re.IGNORECASE),
    re.compile(r"not connected", re.IGNORECASE),
    re.compile(r"not (running|available|initialized|ready)", re.IGNORECASE),
    re.compile(r"connection (refused|closed|failed|lost)", re.IGNORECASE),
    re.compile(r"(failed|unable) to connect", re.IGNORECASE),
    re.compile(r"(server|service|extension|browser|plugin) (not|isn't) (running|available|connected|found)", re.IGNORECASE),
    re.compile(r"please (connect|start|launch|open|enable)", re.IGNORECASE),
    re.compile(r"must (first|be) (connect|start|launch|enable)", re.IGNORECASE),
    # Generic failure / not-found — not auth success
    re.compile(r"\bfailed\b", re.IGNORECASE),
    re.compile(r"not found", re.IGNORECASE),
    re.compile(r"invalid (url|uri)", re.IGNORECASE),
    re.compile(r"doesn't exist|does not exist", re.IGNORECASE),
    # MCP protocol / schema errors
    re.compile(r"MCP error", re.IGNORECASE),
    re.compile(r"-32\d{3}"),
    re.compile(r"Input (validation|should be|is not)", re.IGNORECASE),
    re.compile(r"invalid_type|invalid_enum_value", re.IGNORECASE),
    re.compile(r"is not valid (json|JSON)", re.IGNORECASE),
    re.compile(r"unexpected token", re.IGNORECASE),
    re.compile(r"validation error", re.IGNORECASE),
    # Confirmation-flow prompts — tool is asking for a code, not confirming auth bypass
    re.compile(r"type the \d+-digit", re.IGNORECASE),
    re.compile(r"enter.*confirmation.*code|type.*confirmation", re.IGNORECASE),
    re.compile(r"security operation warning", re.IGNORECASE),
    re.compile(r"this operation.{0,60}irreversible", re.IGNORECASE),
    # Resource / context unavailable
    re.compile(r"\bunavailable\b", re.IGNORECASE),
    re.compile(r"context is (unavailable|missing|not set)", re.IGNORECASE),
    re.compile(r"(session|working.?dir|workspace|repo|path).{0,20}(unavailable|not set|missing|required)", re.IGNORECASE),
    # EVM / blockchain config errors
    re.compile(r"unsupported network", re.IGNORECASE),
    re.compile(r"error fetching", re.IGNORECASE),
    re.compile(r"(EVM_PRIVATE_KEY|EVM_MNEMONIC|PRIVATE_KEY|MNEMONIC)\b", re.IGNORECASE),
    re.compile(r"neither .{0,40} nor .{0,40} (is set|found|provided)", re.IGNORECASE),
    re.compile(r"(rpc|provider|endpoint|network).{0,30}(not set|missing|required|invalid|error)", re.IGNORECASE),
    re.compile(r"transaction.{0,30}(failed|error|reverted)", re.IGNORECASE),
    # Missing / incomplete configuration — tool is unconfigured, not auth-bypassed
    re.compile(r"not configured", re.IGNORECASE),
    re.compile(r"configuration options.{0,60}(missing|invalid)", re.IGNORECASE),
    re.compile(r"(missing|invalid).{0,60}configuration", re.IGNORECASE),
    re.compile(r"requires?.{0,20}(api.?key|token|credential|configuration)", re.IGNORECASE),
    re.compile(r"(api.?key|token|credential).{0,30}(not set|not provided|not found|required)", re.IGNORECASE),
]


def _extract_text(result) -> str:
    parts = []
    for item in result.content:
        if hasattr(item, "text"):
            parts.append(item.text)
        elif isinstance(item, dict) and "text" in item:
            parts.append(item["text"])
    return "\n".join(parts)


def _looks_like_auth_error(text: str) -> bool:
    return any(p.search(text) for p in AUTH_ERROR_PATTERNS)


def _is_sensitive_tool(tool: dict) -> bool:
    name = tool.get("name", "").lower()
    desc = tool.get("description", "").lower()
    combined = name + " " + desc
    return any(
        re.search(r"\b" + re.escape(kw) + r"\b", combined)
        for kw in SENSITIVE_TOOL_KEYWORDS
    )


def _get_auth_params(tool: dict) -> list[str]:
    """
    Return parameter names that are likely authentication tokens/credentials.
    Strong param names (token, api_key, jwt, etc.) are always included.
    Weak names (key, secret) are only included if the description confirms
    they are auth-related — prevents Redis key-name params from being treated
    as auth tokens.
    """
    schema = tool.get("inputSchema", {})
    properties = schema.get("properties", {})
    result = []

    for name, spec in properties.items():
        name_lower = name.lower()
        param_desc = spec.get("description", "").lower()

        if name_lower in STRONG_AUTH_PARAMS:
            # Strong auth param — include unless description rules it out
            if any(kw in param_desc for kw in NON_AUTH_PARAM_DESCRIPTIONS):
                continue
            result.append(name)

        elif name_lower in WEAK_AUTH_PARAMS:
            # Weak param — only include if description positively confirms auth use
            if any(kw in param_desc for kw in NON_AUTH_PARAM_DESCRIPTIONS):
                continue
            if any(term in param_desc for term in AUTH_CONFIRMING_TERMS):
                result.append(name)
            # If description gives no signal either way for "key", skip it —
            # ambiguous "key" params (like Redis key names) should not be tested
            # as auth tokens without explicit confirmation in the description.

    return result


def _server_uses_mcp_auth(tools: list[dict]) -> bool:
    """
    Returns True if at least one tool in this server has an explicit auth parameter.
    Used to decide whether Phase 1 (no-auth call on sensitive tools) is meaningful:
    if no tool in the server uses MCP-level auth, testing for its absence is a
    false positive — the server uses a different auth layer (e.g. Redis protocol auth).
    """
    return any(bool(_get_auth_params(tool)) for tool in tools)


class AuthBypassModule(ScanModule):
    module_id = "auth_bypass"
    name = "Authentication Bypass"
    description = (
        "Tests MCP tools for authentication bypass (CWE-287/CWE-862) using a "
        "baseline-first approach: establishes whether a parameter is auth-gated, "
        "then tests bypass payloads only when auth is actually enforced."
    )

    async def run(self, session: ClientSession, tools: list[dict]) -> list[Finding]:
        findings: list[Finding] = []
        server_has_mcp_auth = _server_uses_mcp_auth(tools)

        # ── Phase 1: Sensitive tools with no required params ────────────────────
        # Only meaningful when the server demonstrably uses MCP-level auth on
        # other tools. Skipping when the server has no auth layer prevents false
        # positives on servers like Redis MCP that delegate auth to the backend.
        if server_has_mcp_auth:
            for tool in tools:
                if not _is_sensitive_tool(tool):
                    continue

                tool_name = tool["name"]
                schema = tool.get("inputSchema", {})
                required_params = schema.get("required", [])

                if required_params:
                    continue  # Has required params — we can't call it blind

                try:
                    result = await session.call_tool(tool_name, arguments={})
                    response_text = _extract_text(result)

                    if not _looks_like_auth_error(response_text) and len(response_text) > 10:
                        findings.append(Finding(
                            module_id=self.module_id,
                            title=f"Sensitive Tool '{tool_name}' Accessible Without Authentication",
                            severity=Severity.HIGH,
                            status=FindingStatus.CONFIRMED,
                            cvss_score=8.1,
                            description=(
                                f"The sensitive MCP tool '{tool_name}' returned a non-error response "
                                f"when called with no arguments on a server that enforces MCP-level "
                                f"authentication on other tools. This suggests inconsistent access control."
                            ),
                            tool_name=tool_name,
                            payload_used="{} (no arguments)",
                            payload_args={},
                            evidence=f"Tool responded successfully without auth: {response_text[:200]}",
                            remediation=(
                                "Implement consistent authentication checks at the tool handler level. "
                                "All sensitive tools should require a valid session token or API key. "
                                "Do not rely solely on transport-level auth."
                            ),
                            cwe_id="CWE-862",
                        ))
                except Exception:
                    pass

        # ── Phase 2: Auth parameter bypass — baseline-first ────────────────────
        # For each tool with an auth param:
        #   Step A — baseline: call with a random UUID token.
        #     - If baseline SUCCEEDS → param is not enforced → Missing Auth (CWE-862)
        #     - If baseline FAILS with auth error → auth IS enforced → proceed to bypass
        #   Step B — bypass payloads: try known bypass values.
        #     - If any payload succeeds where baseline failed → True Auth Bypass (CWE-287)
        for tool in tools:
            tool_name = tool["name"]
            auth_params = _get_auth_params(tool)
            if not auth_params:
                continue

            schema = tool.get("inputSchema", {})
            all_params = list(schema.get("properties", {}).keys())

            for auth_param in auth_params:
                # Build a generic args dict with "test" for all non-auth params
                base_args = {p: "test" for p in all_params}

                # Step A — baseline with random UUID (should fail if auth is enforced)
                random_token = str(uuid.uuid4())
                baseline_args = {**base_args, auth_param: random_token}
                baseline_text = ""
                baseline_auth_enforced = False

                try:
                    baseline_result = await session.call_tool(tool_name, arguments=baseline_args)
                    baseline_text = _extract_text(baseline_result)

                    if _looks_like_auth_error(baseline_text):
                        # Auth IS enforced — random token was rejected correctly
                        baseline_auth_enforced = True
                    else:
                        # Auth is NOT enforced — random token was accepted → Missing Auth
                        if len(baseline_text) > 10:
                            findings.append(Finding(
                                module_id=self.module_id,
                                title=f"Missing Authentication on '{tool_name}' ('{auth_param}' not validated)",
                                severity=Severity.HIGH,
                                status=FindingStatus.CONFIRMED,
                                cvss_score=8.1,
                                description=(
                                    f"The tool '{tool_name}' has an auth parameter '{auth_param}' "
                                    f"but accepts any value for it — a random UUID token was accepted "
                                    f"without rejection. The auth parameter is not validated server-side."
                                ),
                                tool_name=tool_name,
                                payload_used=f"{auth_param}={repr(random_token)} (random UUID — should be rejected)",
                                payload_args=baseline_args,
                                evidence=f"Random token accepted: {baseline_text[:200]}",
                                remediation=(
                                    "Validate the auth parameter server-side on every call. "
                                    "Reject tokens that are not signed, not in the allowed set, "
                                    "or do not match an active session."
                                ),
                                cwe_id="CWE-862",
                            ))
                        # No point testing bypass payloads if auth isn't enforced
                        continue

                except Exception:
                    # Tool threw an exception on the baseline call — auth may be enforced
                    # or the tool has other issues. Skip bypass testing for this param.
                    continue

                if not baseline_auth_enforced:
                    continue

                # Step B — bypass payloads (only reached when baseline was rejected)
                for payload_name, payload_value in AUTH_BYPASS_PAYLOADS:
                    bypass_args = {**base_args, auth_param: payload_value}
                    try:
                        result = await session.call_tool(tool_name, arguments=bypass_args)
                        response_text = _extract_text(result)

                        if not _looks_like_auth_error(response_text) and len(response_text) > 10:
                            findings.append(Finding(
                                module_id=self.module_id,
                                title=f"Auth Bypass in '{tool_name}' — {payload_name} Accepted as Token",
                                severity=Severity.CRITICAL,
                                status=FindingStatus.CONFIRMED,
                                cvss_score=9.1,
                                description=(
                                    f"The tool '{tool_name}' rejected a random UUID token (auth is enforced) "
                                    f"but accepted '{payload_value}' as a valid '{auth_param}' — "
                                    f"confirming broken authentication logic."
                                ),
                                tool_name=tool_name,
                                payload_used=f"{auth_param}={repr(payload_value)} ({payload_name})",
                                payload_args=bypass_args,
                                evidence=f"Bypass succeeded (baseline UUID was rejected): {response_text[:200]}",
                                remediation=(
                                    "Validate tokens server-side on every request. "
                                    "Reject empty, null, or structurally invalid tokens immediately. "
                                    "Use a battle-tested auth library — do not implement token validation manually."
                                ),
                                cwe_id="CWE-287",
                            ))
                            break  # One confirmed bypass per auth param is enough
                    except Exception:
                        pass

        return findings
