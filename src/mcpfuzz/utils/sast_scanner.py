"""
SAST Post-Install Scanner — lightweight source code analysis for MCP server packages.

Downloads the npm/PyPI package tarball from the registry, extracts it to a temp
directory, scans all JS/TS/Python source files for dangerous code patterns, and
returns POTENTIAL findings before the MCP connection is even established.

This runs as a pre-scan phase in scanner.py when the server command is:
  - `npx [-y] PACKAGE [args]`
  - `uvx PACKAGE [args]`

It does NOT run for local paths, GitHub URLs, or commands that aren't registry packages.
"""

import asyncio
import gzip
import io
import os
import re
import shlex
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import httpx

from ..models import Finding, FindingStatus, Severity


# ---------------------------------------------------------------------------
# Dangerous pattern definitions
# Each entry: (regex, description, cwe, severity, applies_to_extensions)
# applies_to_extensions: set of file extensions this pattern targets, or None = all
# ---------------------------------------------------------------------------

_JS_EXT = {".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx"}
_PY_EXT = {".py"}
_ALL_EXT = _JS_EXT | _PY_EXT

DANGEROUS_PATTERNS: list[tuple[re.Pattern, str, str, Severity, Optional[set]]] = [
    # ── JavaScript / TypeScript ──────────────────────────────────────────────
    (
        re.compile(r'\bchild_process\b.{0,60}\b(exec|execSync|execFile|execFileSync)\s*\(', re.DOTALL),
        "OS command execution via child_process.exec",
        "CWE-78", Severity.HIGH, _JS_EXT,
    ),
    (
        re.compile(r'\b(spawn|spawnSync)\s*\([^)]*,\s*\{[^}]*shell\s*:\s*true', re.DOTALL),
        "Shell-enabled spawn() — user input may reach shell",
        "CWE-78", Severity.HIGH, _JS_EXT,
    ),
    (
        re.compile(r'\beval\s*\('),
        "Dynamic eval() — arbitrary code execution",
        "CWE-94", Severity.HIGH, _JS_EXT,
    ),
    (
        re.compile(r'\bnew\s+Function\s*\('),
        "new Function() constructor — dynamic code execution",
        "CWE-94", Severity.HIGH, _JS_EXT,
    ),
    (
        re.compile(r'\brequire\s*\(\s*[^"\'`\)]+\)'),
        "Dynamic require() with variable argument — potential code injection",
        "CWE-94", Severity.MEDIUM, _JS_EXT,
    ),
    (
        re.compile(r'\bfs\s*\.\s*(readFile|writeFile|appendFile|readFileSync|writeFileSync|unlink|rmdir|rm)\s*\(\s*(?![\s"\'`])'),
        "Unvalidated file path passed to fs operation",
        "CWE-22", Severity.MEDIUM, _JS_EXT,
    ),
    (
        re.compile(r'\bpath\s*\.\s*join\s*\([^)]*(?:req\.|params\.|query\.|body\.|args\.)'),
        "path.join() with HTTP request data — potential path traversal",
        "CWE-22", Severity.HIGH, _JS_EXT,
    ),
    (
        re.compile(r'\bserialize\s*\(|\.deserialize\s*\(|JSON\.parse\s*\([^)]*eval'),
        "Unsafe deserialization pattern",
        "CWE-502", Severity.MEDIUM, _JS_EXT,
    ),
    # ── Python ───────────────────────────────────────────────────────────────
    (
        re.compile(r'\bos\.system\s*\('),
        "os.system() — direct shell command execution",
        "CWE-78", Severity.HIGH, _PY_EXT,
    ),
    (
        re.compile(r'\bsubprocess\s*\.\s*(call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True'),
        "subprocess with shell=True — command injection risk",
        "CWE-78", Severity.HIGH, _PY_EXT,
    ),
    (
        re.compile(r'\beval\s*\('),
        "Python eval() — arbitrary code execution",
        "CWE-94", Severity.HIGH, _PY_EXT,
    ),
    (
        re.compile(r'\bexec\s*\('),
        "Python exec() — arbitrary code execution",
        "CWE-94", Severity.HIGH, _PY_EXT,
    ),
    (
        re.compile(r'\bpickle\s*\.\s*(loads?|load)\s*\('),
        "pickle.loads() — unsafe deserialization, RCE if input is attacker-controlled",
        "CWE-502", Severity.HIGH, _PY_EXT,
    ),
    (
        re.compile(r'\byaml\s*\.\s*load\s*\([^,)]+\)(?!\s*,\s*Loader)'),
        "yaml.load() without Loader= — unsafe YAML deserialization",
        "CWE-502", Severity.MEDIUM, _PY_EXT,
    ),
    (
        re.compile(r'\bopen\s*\(\s*(?![\s"\'`])(?!os\.path)'),
        "open() with dynamic path argument — potential path traversal",
        "CWE-22", Severity.MEDIUM, _PY_EXT,
    ),
    # ── Both ─────────────────────────────────────────────────────────────────
    (
        re.compile(r'-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+|DSA\s+)?PRIVATE\s+KEY-----'),
        "Hardcoded private key in source code",
        "CWE-798", Severity.CRITICAL, None,
    ),
    (
        re.compile(r'(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*[=:]\s*["\'][A-Za-z0-9_\-]{20,}["\']', re.IGNORECASE),
        "Potential hardcoded API key or secret",
        "CWE-798", Severity.HIGH, None,
    ),
    (
        re.compile(r'(?:password|passwd|pwd)\s*[=:]\s*["\'][^"\']{6,}["\']', re.IGNORECASE),
        "Hardcoded password string",
        "CWE-798", Severity.HIGH, None,
    ),
]


@dataclass
class SASTFinding:
    file_path: str
    line_number: int
    pattern_desc: str
    cwe: str
    severity: Severity
    snippet: str


def _extract_package_name(command: str) -> Optional[str]:
    """Extract npm package name from an npx/uvx command string."""
    parts = shlex.split(command)
    if not parts:
        return None

    exe = os.path.basename(parts[0]).lower()

    if exe == "npx":
        args = parts[1:]
        # Skip flags like -y, --yes, --no-install, -p, --package
        i = 0
        while i < len(args):
            arg = args[i]
            if arg in ("-y", "--yes", "--no-install", "--prefer-offline"):
                i += 1
                continue
            if arg in ("-p", "--package"):
                i += 2
                continue
            if arg.startswith("-"):
                i += 1
                continue
            # Handle scoped packages: @scope/name or @scope/name@version
            if arg.startswith("@"):
                # @scope/name@version → @scope/name
                parts_at = arg.split("@")
                # parts_at[0] = '', parts_at[1] = 'scope/name', parts_at[2] = 'version' (optional)
                return "@" + parts_at[1] if len(parts_at) >= 2 else arg
            # Unscoped package: name@version → name
            return arg.split("@")[0]
        return None

    if exe in ("uvx", "pipx"):
        args = parts[1:]
        for arg in args:
            if not arg.startswith("-"):
                return arg
        return None

    return None


async def _fetch_npm_tarball(package: str) -> Optional[bytes]:
    """Fetch the latest tarball for an npm package from the registry."""
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            meta = await client.get(f"https://registry.npmjs.org/{package}/latest")
            if meta.status_code != 200:
                return None
            dist = meta.json().get("dist", {})
            tarball_url = dist.get("tarball")
            if not tarball_url:
                return None
            resp = await client.get(tarball_url)
            if resp.status_code != 200:
                return None
            return resp.content
    except Exception:
        return None


def _scan_source_tree(root: Path) -> list[SASTFinding]:
    """Walk a directory tree and scan all source files for dangerous patterns."""
    results: list[SASTFinding] = []

    # Skip test/example/vendor directories
    SKIP_DIRS = {"node_modules", ".git", "test", "tests", "__tests__", "spec",
                 "examples", "example", "dist", "build", ".cache", "coverage"}

    for fpath in root.rglob("*"):
        if not fpath.is_file():
            continue
        if any(part in SKIP_DIRS for part in fpath.parts):
            continue
        ext = fpath.suffix.lower()
        if ext not in _ALL_EXT:
            continue

        try:
            source = fpath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        lines = source.splitlines()
        for pattern, desc, cwe, severity, applies_to in DANGEROUS_PATTERNS:
            if applies_to and ext not in applies_to:
                continue
            for m in pattern.finditer(source):
                # Find line number
                line_no = source[:m.start()].count("\n") + 1
                snippet = lines[line_no - 1].strip()[:120] if line_no <= len(lines) else ""
                # Skip commented lines
                stripped = snippet.lstrip()
                if stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("*"):
                    continue
                results.append(SASTFinding(
                    file_path=str(fpath.relative_to(root)),
                    line_number=line_no,
                    pattern_desc=desc,
                    cwe=cwe,
                    severity=severity,
                    snippet=snippet,
                ))
                # One finding per pattern per file to avoid noise
                break

    return results


def _sast_findings_to_model(package: str, sast_results: list[SASTFinding]) -> list[Finding]:
    findings = []
    for r in sast_results:
        findings.append(Finding(
            module_id="sast_scan",
            title=f"[SAST] {r.pattern_desc} in {package}:{r.file_path}",
            severity=r.severity,
            status=FindingStatus.POTENTIAL,  # SAST = code evidence, not runtime confirmed
            cvss_score=_severity_to_cvss(r.severity),
            description=(
                f"Static analysis of the '{package}' package source detected a potentially "
                f"dangerous code pattern: {r.pattern_desc}. "
                f"Found in {r.file_path}:{r.line_number}. "
                f"This is a POTENTIAL finding — manual review required to confirm exploitability."
            ),
            tool_name="(pre-scan SAST)",
            payload_used=f"(source scan: {r.file_path}:{r.line_number})",
            evidence=f"File: {r.file_path} line {r.line_number}\nCode: {r.snippet}",
            remediation=_cwe_remediation(r.cwe),
            cwe_id=r.cwe,
        ))
    return findings


def _severity_to_cvss(sev: Severity) -> float:
    return {Severity.CRITICAL: 9.0, Severity.HIGH: 7.5, Severity.MEDIUM: 5.0, Severity.LOW: 3.0}.get(sev, 5.0)


def _cwe_remediation(cwe: str) -> str:
    return {
        "CWE-78": "Never pass user-controlled input to shell commands. Use subprocess with shell=False and a list of arguments.",
        "CWE-94": "Avoid eval/exec/new Function with dynamic input. Use safe alternatives.",
        "CWE-22": "Validate file paths — resolve to absolute path and verify containment within allowed base directory.",
        "CWE-502": "Never deserialize untrusted data with pickle/yaml.load. Use safe alternatives (json, yaml.safe_load).",
        "CWE-798": "Remove hardcoded credentials from source code. Use environment variables or a secrets manager.",
    }.get(cwe, "Review and remediate the identified dangerous code pattern.")


async def run_sast_prescan(command: str) -> list[Finding]:
    """
    Entry point called from scanner.py before the MCP connection.
    Returns a (possibly empty) list of POTENTIAL findings from source analysis.

    Only runs for npx/uvx commands — skips local paths, URLs, and unknown formats.
    """
    package = _extract_package_name(command)
    if not package:
        return []

    exe = os.path.basename(shlex.split(command)[0]).lower()
    if exe not in ("npx", "uvx", "pipx"):
        return []

    # Fetch tarball from npm registry (uvx/pipx = PyPI — npm-only for now)
    if exe != "npx":
        return []  # PyPI SAST: future work

    tarball_bytes = await _fetch_npm_tarball(package)
    if not tarball_bytes:
        return []

    with tempfile.TemporaryDirectory(prefix="mcpfuzz_sast_") as tmpdir:
        try:
            # npm tarballs are .tgz (gzip-compressed tar)
            with tarfile.open(fileobj=io.BytesIO(tarball_bytes), mode="r:gz") as tf:
                # Safety: only extract regular files, no absolute paths, no symlinks outside
                safe_members = []
                for member in tf.getmembers():
                    if not member.isreg():
                        continue
                    member.name = re.sub(r"^[/\\]+|\.\.\/", "", member.name)
                    if member.name:
                        safe_members.append(member)
                tf.extractall(tmpdir, members=safe_members)
        except Exception:
            return []

        sast_results = _scan_source_tree(Path(tmpdir))

    return _sast_findings_to_model(package, sast_results)
