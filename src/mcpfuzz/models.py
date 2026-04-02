"""Core data models for MCPFuzz."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional
import datetime
import uuid


class Severity(str, Enum):
    CRITICAL = "critical"  # CVSS >= 9.0
    HIGH = "high"          # CVSS >= 7.0
    MEDIUM = "medium"      # CVSS >= 4.0
    LOW = "low"            # CVSS >= 0.1
    INFO = "info"


class FindingStatus(str, Enum):
    CONFIRMED = "confirmed"  # Server responded in exploitable way — evidence in output
    POTENTIAL = "potential"  # Heuristic match, needs manual review
    NOT_VULN = "not_vuln"
    ERROR = "error"          # Module failed to run


@dataclass
class Finding:
    module_id: str
    title: str
    severity: Severity
    status: FindingStatus
    cvss_score: float
    description: str
    tool_name: str       # MCP tool that was called
    payload_used: str    # Exact payload sent as argument
    evidence: str        # Why this is a finding — what was in the response
    remediation: str
    payload_args: Optional[dict] = None  # Actual arguments dict sent to the tool (for POC generation)
    raw_request: dict = field(default_factory=dict)
    raw_response: Any = None
    cwe_id: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.datetime.utcnow().isoformat() + "Z")
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "module_id": self.module_id,
            "title": self.title,
            "severity": self.severity.value,
            "status": self.status.value,
            "cvss_score": self.cvss_score,
            "description": self.description,
            "tool_name": self.tool_name,
            "payload_used": self.payload_used,
            "evidence": self.evidence[:500] if self.evidence else "",
            "remediation": self.remediation,
            "cwe_id": self.cwe_id,
            "timestamp": self.timestamp,
        }


@dataclass
class ScanTarget:
    server: str            # Command string (stdio) or URL (sse/http)
    transport: str         # "stdio" | "sse" | "http" | "streamable-http"
    timeout: int = 30
    auth_token: Optional[str] = None
    modules: Optional[list[str]] = None  # None = run all modules
    fail_on: str = "high"  # Severity threshold for non-zero exit code
    env: Optional[dict[str, str]] = None  # Extra env vars for stdio subprocess
    llm_key: Optional[str] = None         # API key for LLM-judge (Anthropic or OpenAI; Ollama doesn't need one)
    llm_provider: str = "anthropic"       # "anthropic" | "ollama" | "openai"
    llm_model: Optional[str] = None       # Model override (defaults per provider in LLMJudgeClient)
    llm_url: Optional[str] = None         # Custom base URL for ollama/openai (e.g. http://localhost:11434/v1)


@dataclass
class ScanResult:
    target: ScanTarget
    scan_id: str
    started_at: str
    completed_at: Optional[str]
    findings: list[Finding]
    tools_discovered: list[dict]
    error: Optional[str] = None

    @property
    def exit_code(self) -> int:
        threshold_map = {
            "critical": {Severity.CRITICAL},
            "high": {Severity.CRITICAL, Severity.HIGH},
            "medium": {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM},
            "low": {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW},
        }
        thresholds = threshold_map.get(self.target.fail_on, {Severity.CRITICAL, Severity.HIGH})
        for f in self.findings:
            if f.status == FindingStatus.CONFIRMED and f.severity in thresholds:
                return 1
        return 0

    def summary(self) -> dict:
        confirmed = [f for f in self.findings if f.status == FindingStatus.CONFIRMED]
        by_severity: dict[str, int] = {}
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            count = sum(1 for f in confirmed if f.severity == sev)
            if count:
                by_severity[sev.value] = count
        return {
            "scan_id": self.scan_id,
            "target": self.target.server,
            "transport": self.target.transport,
            "tools_discovered": len(self.tools_discovered),
            "findings_total": len(self.findings),
            "findings_confirmed": len(confirmed),
            "by_severity": by_severity,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }
