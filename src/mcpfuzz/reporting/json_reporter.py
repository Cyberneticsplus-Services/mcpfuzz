"""JSON report output."""

import json
from ..models import ScanResult


def write_json_report(result: ScanResult, output_path: str | None = None) -> str:
    report = {
        "mcpfuzz_version": "0.1.0",
        "scanner": "MCPFuzz — Dynamic MCP Security Scanner",
        "author": "Cyberneticsplus Services Private Limited",
        "summary": result.summary(),
        "tools_discovered": result.tools_discovered,
        "findings": [f.to_dict() for f in result.findings],
    }
    json_str = json.dumps(report, indent=2, ensure_ascii=True, default=str)
    if output_path:
        with open(output_path, "w") as fh:
            fh.write(json_str)
    return json_str
