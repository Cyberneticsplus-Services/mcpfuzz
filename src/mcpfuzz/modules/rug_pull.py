"""
Rug Pull / Tool Definition Drift Detection Module
Targets: All MCP servers.
Method: Hashes tool definitions on first scan (baseline). On subsequent scans,
        compares current definitions against baseline and alerts on any changes.
        Unexpected tool definition changes = potential rug pull attack.
CWE-494: Download of Code Without Integrity Check
"""

import hashlib
import json
import sqlite3
import os
from datetime import datetime, timezone
from mcp import ClientSession

from .base import ScanModule
from ..models import Finding, FindingStatus, Severity


STATE_DB_PATH = os.path.expanduser("~/.mcpfuzz/baseline.db")


def _ensure_db() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(STATE_DB_PATH), exist_ok=True)
    conn = sqlite3.connect(STATE_DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS tool_baselines (
            server_id TEXT NOT NULL,
            tool_name TEXT NOT NULL,
            definition_hash TEXT NOT NULL,
            definition_json TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            PRIMARY KEY (server_id, tool_name)
        )
    """)
    conn.commit()
    return conn


def _hash_tool(tool: dict) -> str:
    """Stable hash of a tool definition — ignores ordering."""
    canonical = json.dumps(tool, sort_keys=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _server_id(session: ClientSession, tools: list[dict] | None = None,
               server_command: str = "") -> str:
    """Generate a stable ID for the server being scanned.

    Priority:
    1. Explicit server_command (most reliable — set by scanner.py for all transports)
    2. Session URL / command attributes (SSE/HTTP transports)
    3. Sorted set of tool names (last resort — ambiguous when multiple servers
       expose identically-named tools, e.g. connect_database / execute_query)
    """
    if server_command:
        return hashlib.sha256(server_command.encode()).hexdigest()[:16]
    for attr in ["_server_url", "server_url", "_command"]:
        val = getattr(session, attr, None)
        if val:
            return hashlib.sha256(str(val).encode()).hexdigest()[:16]
    # Last resort: tool-name fingerprint. Prone to cross-server collisions
    # when different packages expose tools with identical names.
    if tools:
        names = sorted(t.get("name", "") for t in tools)
        return hashlib.sha256(json.dumps(names).encode()).hexdigest()[:16]
    return "unknown"


class RugPullModule(ScanModule):
    module_id = "rug_pull"
    name = "Rug Pull Detection"
    description = "Detects unexpected tool definition changes between scans (CWE-494) — establishes a baseline on first scan and alerts on any drift"

    async def run(self, session: ClientSession, tools: list[dict]) -> list[Finding]:
        findings: list[Finding] = []
        now = datetime.now(timezone.utc).isoformat()
        server_id = _server_id(session, tools, server_command=self.server_command)

        conn = _ensure_db()
        try:
            for tool in tools:
                tool_name = tool.get("name", "unknown")
                current_hash = _hash_tool(tool)
                current_json = json.dumps(tool, sort_keys=True)

                row = conn.execute(
                    "SELECT definition_hash, definition_json, first_seen FROM tool_baselines "
                    "WHERE server_id = ? AND tool_name = ?",
                    (server_id, tool_name)
                ).fetchone()

                if row is None:
                    # First time seeing this tool — save as baseline
                    conn.execute(
                        "INSERT INTO tool_baselines VALUES (?, ?, ?, ?, ?, ?)",
                        (server_id, tool_name, current_hash, current_json, now, now)
                    )
                    # INFO finding to document the baseline — POTENTIAL not CONFIRMED (not a vulnerability)
                    findings.append(Finding(
                        module_id=self.module_id,
                        title=f"Baseline Recorded for Tool '{tool_name}'",
                        severity=Severity.INFO,
                        status=FindingStatus.POTENTIAL,
                        cvss_score=0.0,
                        description=f"First scan of '{tool_name}' — definition saved as baseline for future drift detection.",
                        tool_name=tool_name,
                        payload_used="tools/list (baseline recording)",
                        evidence=f"Hash: {current_hash[:16]}...",
                        remediation="No action required. Run MCPFuzz again to detect any changes.",
                    ))
                else:
                    baseline_hash, baseline_json, first_seen = row

                    # Update last_seen
                    conn.execute(
                        "UPDATE tool_baselines SET last_seen = ? WHERE server_id = ? AND tool_name = ?",
                        (now, server_id, tool_name)
                    )

                    if current_hash != baseline_hash:
                        # Tool definition changed — compute diff summary
                        old_tool = json.loads(baseline_json)
                        diff_summary = _summarise_diff(old_tool, tool)

                        findings.append(Finding(
                            module_id=self.module_id,
                            title=f"Tool Definition Changed Since Baseline — '{tool_name}' (Rug Pull Risk)",
                            severity=Severity.HIGH,
                            status=FindingStatus.CONFIRMED,
                            cvss_score=7.5,
                            description=(
                                f"The definition of MCP tool '{tool_name}' has changed since the baseline "
                                f"was recorded on {first_seen[:10]}. Unexpected changes to tool definitions "
                                f"are a rug pull attack vector — a compromised or malicious server can "
                                f"silently alter what tools do after initial trust is established."
                            ),
                            tool_name=tool_name,
                            payload_used="tools/list (drift detection)",
                            evidence=diff_summary,
                            remediation=(
                                "Investigate the tool definition change. If the change is legitimate "
                                "(e.g. a version update), re-run MCPFuzz with --reset-baseline to "
                                "record the new baseline. If unexpected, treat the server as compromised."
                            ),
                            cwe_id="CWE-494",
                        ))

            conn.commit()
        finally:
            conn.close()

        return findings


def _summarise_diff(old: dict, new: dict) -> str:
    """Produce a human-readable summary of what changed between tool definitions."""
    changes = []

    old_desc = old.get("description", "")
    new_desc = new.get("description", "")
    if old_desc != new_desc:
        changes.append(f"Description changed:\n  WAS: {old_desc[:100]}\n  NOW: {new_desc[:100]}")

    old_schema = old.get("inputSchema", {})
    new_schema = new.get("inputSchema", {})
    old_props = set(old_schema.get("properties", {}).keys())
    new_props = set(new_schema.get("properties", {}).keys())

    added = new_props - old_props
    removed = old_props - new_props
    if added:
        changes.append(f"Parameters added: {', '.join(added)}")
    if removed:
        changes.append(f"Parameters removed: {', '.join(removed)}")

    if not changes:
        changes.append("Tool structure changed (see full diff)")

    return "\n".join(changes)
