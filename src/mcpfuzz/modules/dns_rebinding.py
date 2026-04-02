"""
DNS Rebinding Protection Module
Targets: MCP servers running as HTTP services (SSE/HTTP transport).
Method: Sends requests with spoofed/invalid Origin headers and checks if the
        server accepts them — per MCP spec, servers MUST validate Origin header.
CWE-346: Origin Validation Error
"""

import re
from mcp import ClientSession
from mcp.client.sse import sse_client
import httpx

from .base import ScanModule
from ..models import Finding, FindingStatus, Severity


MALICIOUS_ORIGINS = [
    "http://evil.com",
    "http://attacker.local",
    "null",
    "http://localhost.evil.com",
    "http://169.254.169.254",
    "http://127.0.0.1.evil.com",
    "",
    "file://",
    "http://0.0.0.0",
]

# Expected: server returns 400/403 or closes connection for invalid origins
# Vulnerable: server returns 200 or valid JSON-RPC response


class DNSRebindingModule(ScanModule):
    module_id = "dns_rebinding"
    name = "DNS Rebinding Protection"
    description = "Tests HTTP MCP servers for missing Origin header validation (CWE-346) — per MCP spec servers MUST reject connections with invalid Origin headers"

    async def run(self, session: ClientSession, tools: list[dict]) -> list[Finding]:
        findings: list[Finding] = []

        # Get the server URL from session if available
        # This module is most relevant for SSE/HTTP transports
        # For stdio transport, DNS rebinding is not applicable — skip gracefully
        server_url = getattr(session, "_server_url", None) or getattr(session, "server_url", None)

        if not server_url:
            # Try to get it from the transport context stored on session
            for attr in ["_read_stream", "_write_stream", "_transport"]:
                transport = getattr(session, attr, None)
                if transport and hasattr(transport, "url"):
                    server_url = transport.url
                    break

        if not server_url:
            # stdio transport — DNS rebinding not applicable
            return []

        base_url = server_url.rstrip("/sse").rstrip("/")

        async with httpx.AsyncClient(timeout=10.0) as client:
            # First: check if server accepts a connection at all with correct Origin
            try:
                normal_resp = await client.get(
                    f"{base_url}/sse",
                    headers={"Origin": base_url}
                )
                if normal_resp.status_code not in (200, 204, 405):
                    # Server not responding normally — skip
                    return []
            except Exception:
                return []

            # Now test with malicious origins
            for origin in MALICIOUS_ORIGINS:
                try:
                    headers = {"Origin": origin} if origin else {}
                    resp = await client.get(
                        f"{base_url}/sse",
                        headers=headers,
                        timeout=5.0
                    )

                    if resp.status_code in (200, 204):
                        findings.append(Finding(
                            module_id=self.module_id,
                            title=f"Missing Origin Validation — Server Accepts Requests from '{origin or '(no origin)'}' ",
                            severity=Severity.HIGH,
                            status=FindingStatus.CONFIRMED,
                            cvss_score=8.1,
                            description=(
                                f"The MCP server accepted a connection with Origin: '{origin}' "
                                f"(HTTP {resp.status_code}). Per the MCP specification, servers "
                                f"MUST validate the Origin header and reject connections from "
                                f"untrusted origins to prevent DNS rebinding attacks. "
                                f"An attacker hosting a malicious webpage can make the victim's "
                                f"browser connect to the local MCP server and execute tool calls."
                            ),
                            tool_name="(HTTP transport)",
                            payload_used=f"Origin: {origin or '(omitted)'}",
                            evidence=f"Server returned HTTP {resp.status_code} for malicious origin '{origin}'",
                            remediation=(
                                "Implement Origin header validation: maintain an allowlist of trusted "
                                "origins and reject all others with HTTP 403. "
                                "Bind the server to 127.0.0.1 only (not 0.0.0.0). "
                                "Add a session token requirement per the MCP security specification."
                            ),
                            cwe_id="CWE-346",
                        ))
                        # One confirmation is enough — break after first confirmed finding
                        break

                except Exception:
                    pass

        return findings
