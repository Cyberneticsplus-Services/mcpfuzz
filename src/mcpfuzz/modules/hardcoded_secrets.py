"""
Hardcoded Secrets Module
Targets: Any MCP server.
Method: Scans tool names, descriptions, and parameter schemas for embedded
        credentials, API keys, tokens, and connection strings.
        Also calls info/config/status tools and scans their responses.
        Uses a confidence-scored detection approach — high-specificity patterns
        (vendor-prefixed keys, PEM headers, structured tokens) fire immediately;
        low-specificity patterns (generic base64) require corroborating context
        to avoid false positives on Redis INFO output, SHA hashes, etc.
CWE-798: Use of Hard-coded Credentials
"""

import re
from mcp import ClientSession

from .base import ScanModule
from ..models import Finding, FindingStatus, Severity


# ── High-specificity patterns ────────────────────────────────────────────────
# These have vendor-specific prefixes or well-known formats — very low FP rate.
# Match alone is sufficient to raise a finding.
HIGH_CONFIDENCE_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("AWS Access Key ID",
     re.compile(r"AKIA[0-9A-Z]{16}"),
     "Rotate immediately via AWS IAM"),

    ("GitHub Token (Classic)",
     re.compile(r"ghp_[A-Za-z0-9]{36}"),
     "Revoke at github.com/settings/tokens"),

    ("GitHub Token (Fine-grained)",
     re.compile(r"github_pat_[A-Za-z0-9_]{82}"),
     "Revoke at github.com/settings/tokens"),

    ("GitHub OAuth Token",
     re.compile(r"gho_[A-Za-z0-9]{36}"),
     "Revoke at github.com/settings/tokens"),

    ("OpenAI API Key",
     re.compile(r"sk-[A-Za-z0-9]{48}"),
     "Revoke at platform.openai.com/api-keys"),

    ("Anthropic API Key",
     re.compile(r"sk-ant-[A-Za-z0-9\-_]{95}"),
     "Revoke at console.anthropic.com"),

    ("Stripe Secret Key (Live)",
     re.compile(r"sk_live_[A-Za-z0-9]{24,}"),
     "Revoke at dashboard.stripe.com/apikeys"),

    ("Stripe Secret Key (Test)",
     re.compile(r"sk_test_[A-Za-z0-9]{24,}"),
     "Revoke at dashboard.stripe.com/apikeys"),

    ("Slack Bot Token",
     re.compile(r"xoxb-[0-9]{11}-[0-9]{11}-[A-Za-z0-9]{24}"),
     "Revoke at api.slack.com/apps"),

    ("Slack App Token",
     re.compile(r"xapp-[0-9]-[A-Z0-9]{11}-[0-9]{13}-[a-f0-9]{64}"),
     "Revoke at api.slack.com/apps"),

    ("Slack Webhook",
     re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{44}"),
     "Revoke in Slack app settings"),

    ("HuggingFace Token",
     re.compile(r"hf_[A-Za-z0-9]{37}"),
     "Revoke at huggingface.co/settings/tokens"),

    ("Private Key (PEM)",
     re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
     "Rotate the private key immediately"),

    ("Database Connection String with Credentials",
     re.compile(r"(postgresql|mysql|mongodb|redis)://[^@\s:]+:[^@\s]{3,}@"),
     "Rotate database credentials and remove from connection strings"),

    ("Generic Password in URL",
     re.compile(r"://[A-Za-z0-9_\-\.]+:[A-Za-z0-9_\-\.!@#$%^&*()]{6,}@"),
     "Remove credentials from URLs — use environment variables"),
]

# ── Context-dependent patterns ───────────────────────────────────────────────
# These patterns are broad and prone to false positives on their own (e.g.
# Redis run_id, SHA256 hashes, base64 data). They only fire when a corroborating
# context keyword appears nearby in the same line or within 120 chars.
CONTEXT_DEPENDENT_PATTERNS: list[tuple[str, re.Pattern, list[str], str]] = [
    (
        "AWS Secret Access Key",
        re.compile(r"[A-Za-z0-9/+=]{40}"),
        # Context: must appear near an AWS Access Key or labelled as a secret key
        ["AKIA", "aws_secret", "SecretAccessKey", "secret_access_key",
         "AWS_SECRET", "aws secret", "Secret Access Key"],
        "Rotate immediately via AWS IAM",
    ),
    (
        "Generic JWT",
        re.compile(r"eyJ[A-Za-z0-9\-_=]{10,}\.[A-Za-z0-9\-_=]{10,}\.?[A-Za-z0-9\-_.+/=]*"),
        # Context: must appear in a field that looks like a token/credential
        ["token", "jwt", "bearer", "auth", "authorization", "credential",
         "session", "access_token", "id_token", "refresh_token"],
        "Rotate the signing secret and invalidate existing tokens",
    ),
    (
        "Generic API Key (long hex)",
        re.compile(r"\b[a-f0-9]{32,64}\b"),
        # Context: must be labelled as an api_key, secret, or token
        ["api_key", "api-key", "apikey", "secret", "token", "password",
         "credential", "private_key", "access_key"],
        "Rotate the API key or secret via the issuing service",
    ),
]

# Tool names that might expose config/secrets when called
INFO_TOOL_KEYWORDS = [
    "info", "config", "status", "version", "health", "env",
    "settings", "debug", "whoami", "about", "diagnostics",
]

# Redis INFO output signatures — if any of these appear, apply stricter filtering
REDIS_INFO_SIGNATURES = [
    "redis_version:", "uptime_in_seconds:", "used_memory:", "connected_clients:",
    "rdb_changes_since_last_save:", "aof_enabled:", "keyspace_hits:",
    "tcp_port:", "os:Linux", "os:Darwin",
]


def _is_redis_info_response(text: str) -> bool:
    """Returns True if the text looks like Redis INFO command output."""
    matches = sum(1 for sig in REDIS_INFO_SIGNATURES if sig in text)
    return matches >= 3


def _scan_text_for_secrets(text: str, strict: bool = False) -> list[tuple[str, str, str]]:
    """
    Return list of (secret_type, redacted_value, remediation) for secrets found.

    strict=True applies additional filtering for responses that are likely to
    contain long opaque strings by design (Redis INFO, diagnostic output, etc.).
    In strict mode, only high-confidence vendor-prefixed patterns are reported.
    """
    found = []
    seen_values: set[str] = set()

    # High-confidence patterns — always check
    for secret_type, pattern, remediation in HIGH_CONFIDENCE_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(0)
            if len(value) < 8:
                continue
            key = value[:8]
            if key in seen_values:
                continue
            seen_values.add(key)
            found.append((secret_type, value[:6] + "***" + value[-4:], remediation))

    if strict:
        # In strict mode, skip context-dependent patterns entirely —
        # too many false positives in structured diagnostic output
        return found

    # Context-dependent patterns — only fire when corroborating context is present
    for secret_type, pattern, context_keywords, remediation in CONTEXT_DEPENDENT_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(0)
            if len(value) < 8:
                continue

            # Check 120-char window around the match for context keywords
            start = max(0, match.start() - 120)
            end = min(len(text), match.end() + 120)
            window = text[start:end].lower()

            if not any(kw.lower() in window for kw in context_keywords):
                continue

            key = value[:8]
            if key in seen_values:
                continue
            seen_values.add(key)
            found.append((secret_type, value[:6] + "***" + value[-4:], remediation))

    return found


def _serialize_tool(tool: dict) -> str:
    """Flatten a tool definition to text for secret scanning."""
    parts = [
        tool.get("name", ""),
        tool.get("description", ""),
    ]
    schema = tool.get("inputSchema", {})
    for name, spec in schema.get("properties", {}).items():
        parts.append(name)
        parts.append(spec.get("description", ""))
        if "default" in spec:
            parts.append(str(spec["default"]))
    return " ".join(parts)


def _extract_text(result) -> str:
    parts = []
    for item in result.content:
        if hasattr(item, "text"):
            parts.append(item.text)
        elif isinstance(item, dict) and "text" in item:
            parts.append(item["text"])
    return "\n".join(parts)


class HardcodedSecretsModule(ScanModule):
    module_id = "hardcoded_secrets"
    name = "Hardcoded Secrets"
    description = (
        "Scans tool definitions and info/config tool responses for embedded API keys, "
        "tokens, and credentials (CWE-798). Uses confidence-scored detection to avoid "
        "false positives on Redis INFO output, SHA hashes, and other opaque data."
    )

    async def run(self, session: ClientSession, tools: list[dict]) -> list[Finding]:
        findings: list[Finding] = []

        # Phase 1: Scan static tool definitions (names, descriptions, schemas)
        # Tool definitions rarely contain operational data so use normal scanning
        for tool in tools:
            tool_text = _serialize_tool(tool)
            secrets = _scan_text_for_secrets(tool_text, strict=False)
            for secret_type, redacted_value, remediation in secrets:
                findings.append(Finding(
                    module_id=self.module_id,
                    title=f"Hardcoded {secret_type} in Tool Definition of '{tool['name']}'",
                    severity=Severity.HIGH,
                    status=FindingStatus.CONFIRMED,
                    cvss_score=7.5,
                    description=(
                        f"The tool definition for '{tool['name']}' contains a hardcoded {secret_type}. "
                        f"Any client connecting to this MCP server can read this credential via "
                        f"the tools/list endpoint — no authentication required."
                    ),
                    tool_name=tool["name"],
                    payload_used="tools/list (passive scan)",
                    evidence=f"Found {secret_type}: {redacted_value}",
                    remediation=(
                        f"Remove the hardcoded credential. {remediation}. "
                        f"Load secrets from environment variables at runtime instead."
                    ),
                    cwe_id="CWE-798",
                ))

        # Phase 2: Call info/config/status tools and scan their responses
        for tool in tools:
            tool_name = tool.get("name", "").lower()
            if not any(kw in tool_name for kw in INFO_TOOL_KEYWORDS):
                continue

            schema = tool.get("inputSchema", {})
            required = schema.get("required", [])
            if required:
                continue  # Skip tools requiring mandatory params

            try:
                result = await session.call_tool(tool["name"], arguments={})
                response_text = _extract_text(result)

                # Detect if this is Redis INFO-style output or other high-noise
                # diagnostic output — use strict mode to avoid false positives
                is_noisy = _is_redis_info_response(response_text)
                secrets = _scan_text_for_secrets(response_text, strict=is_noisy)

                for secret_type, redacted_value, remediation in secrets:
                    findings.append(Finding(
                        module_id=self.module_id,
                        title=f"Secret Exposed in Response of '{tool['name']}' Tool",
                        severity=Severity.CRITICAL,
                        status=FindingStatus.CONFIRMED,
                        cvss_score=9.1,
                        description=(
                            f"Calling the '{tool['name']}' tool returns a {secret_type} in its response. "
                            f"Any connected AI client or user can extract this credential by calling this tool."
                        ),
                        tool_name=tool["name"],
                        payload_used="{}  (no arguments — tool called as-is)",
                        evidence=f"Tool response contains {secret_type}: {redacted_value}",
                        remediation=(
                            f"Remove secrets from tool responses. {remediation}. "
                            f"Audit all info/config/status tools for information disclosure."
                        ),
                        raw_response=response_text[:500],
                        cwe_id="CWE-798",
                    ))
            except Exception:
                pass

        return findings
