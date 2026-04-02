"""Main scanner orchestrator — connects to server, runs all modules, returns ScanResult."""

import uuid
import datetime
import anyio
from mcp import ClientSession

from ..models import ScanTarget, ScanResult, Finding, FindingStatus, Severity
from ..transport import StdioTransport, SSETransport, StreamableHTTPTransport
from ..modules import ALL_MODULES, MODULE_MAP
from ..utils.callback_server import CallbackServer
from ..utils.sast_scanner import run_sast_prescan


def _build_transport(target: ScanTarget):
    if target.transport == "stdio":
        return StdioTransport(target.server, timeout=target.timeout, env=target.env)
    elif target.transport in ("sse", "http"):
        return SSETransport(target.server, auth_token=target.auth_token, timeout=target.timeout)
    elif target.transport == "streamable-http":
        return StreamableHTTPTransport(target.server, auth_token=target.auth_token, timeout=target.timeout)
    else:
        raise ValueError(f"Unknown transport: {target.transport}. Use stdio, sse, http, or streamable-http.")


def _select_modules(target: ScanTarget):
    if not target.modules:
        return ALL_MODULES
    selected = []
    for mod_id in target.modules:
        if mod_id not in MODULE_MAP:
            raise ValueError(f"Unknown module: '{mod_id}'. Run 'mcpfuzz list-modules' for available modules.")
        selected.append(MODULE_MAP[mod_id])
    return selected


async def run_scan(target: ScanTarget, progress_cb=None) -> ScanResult:
    """
    Run a full security scan against an MCP server.
    progress_cb(message: str) is called at each step if provided.
    """
    scan_id = str(uuid.uuid4())[:8]
    started_at = datetime.datetime.utcnow().isoformat() + "Z"
    all_findings: list[Finding] = []
    tools_discovered: list[dict] = []

    def log(msg: str):
        if progress_cb:
            progress_cb(msg)

    transport = _build_transport(target)
    modules = _select_modules(target)

    # Build optional LLM client for LLM-judge tool poisoning analysis.
    # Ollama: always try — cloud models (minimax-m2.5:cloud etc.) run via local daemon,
    #         no API key needed (auth via `ollama signin`).
    # Anthropic / OpenAI: require api_key.
    llm_client = None
    llm_judge_requested = bool(target.llm_key) or target.llm_provider == "ollama"
    if llm_judge_requested:
        try:
            from ..utils.llm_client import LLMJudgeClient
            llm_client = LLMJudgeClient(
                provider=target.llm_provider,
                api_key=target.llm_key,
                model=target.llm_model,
                base_url=target.llm_url,
            )
            if target.llm_provider == "ollama":
                dest = "ollama.com" if target.llm_key else "localhost:11434"
                log(f"LLM-judge enabled (Ollama/{llm_client.model} via {dest}) — tool poisoning analysis enhanced")
            else:
                log(f"LLM-judge enabled ({target.llm_provider}/{llm_client.model}) — tool poisoning analysis enhanced")
        except ImportError as e:
            log(f"WARNING: {e}  (LLM-judge disabled for this scan)")
        except ValueError as e:
            log(f"WARNING: LLM provider error — {e}  (LLM-judge disabled)")

    # SAST pre-scan: download and scan source code before connecting
    if target.transport == "stdio":
        log("Running SAST pre-scan (source code analysis)...")
        try:
            sast_findings = await run_sast_prescan(target.server)
            if sast_findings:
                all_findings.extend(sast_findings)
                log(f"  [SAST] {len(sast_findings)} potential finding(s) from source analysis")
            else:
                log("  [SAST] clean (no dangerous patterns found in source)")
        except Exception as e:
            log(f"  [SAST] skipped ({e})")

    # Tracks whether all modules completed before any exception was raised.
    # If True and an exception fires during context-manager cleanup (e.g. the
    # server subprocess exits after the scan), we treat it as a normal teardown
    # rather than a scan failure.
    scan_completed = False

    try:
        async with CallbackServer() as cb:
            async with transport.connect() as session:
                log(f"Connected via {target.transport}")

                # Discover tools — retry once with a short delay if the first
                # call returns empty (some servers need a moment after initialize)
                tools_response = await session.list_tools()
                if not tools_response.tools:
                    await anyio.sleep(2)
                    tools_response = await session.list_tools()
                tools_discovered = [
                    {
                        "name": t.name,
                        "description": t.description or "",
                        "inputSchema": t.inputSchema.model_dump() if hasattr(t.inputSchema, "model_dump") else (t.inputSchema or {}),
                    }
                    for t in tools_response.tools
                ]
                if tools_discovered:
                    log(f"Discovered {len(tools_discovered)} tools: {[t['name'] for t in tools_discovered]}")
                else:
                    log("WARNING: Server connected but returned 0 tools — server may have crashed after initialize, require additional config, or expose no tools")

                # Run each module
                for module in modules:
                    # Inject callback server for OOB detection (SSRF, blind command injection)
                    module.callback_server = cb
                    # Inject LLM client for enhanced tool poisoning analysis (optional)
                    module.llm_client = llm_client
                    # Inject server command for framework detection / context-aware severity
                    module.server_command = target.server
                    module.transport = target.transport
                    log(f"Running module: {module.name}")
                    try:
                        findings = []
                        with anyio.move_on_after(60) as cancel_scope:
                            findings = await module.run(session, tools_discovered)
                        if cancel_scope.cancelled_caught:
                            log(f"  [{module.name}] TIMEOUT — module exceeded 60s, partial results may be missing")
                        all_findings.extend(findings)
                        confirmed = [f for f in findings if f.status == FindingStatus.CONFIRMED
                                     and f.severity != Severity.INFO]
                        if confirmed:
                            log(f"  [{module.name}] {len(confirmed)} confirmed finding(s)")
                        else:
                            log(f"  [{module.name}] clean")
                    except BaseException as exc:
                        # Catches both regular exceptions and ExceptionGroup from anyio TaskGroup
                        if isinstance(exc, BaseExceptionGroup):
                            msg = "; ".join(str(e) for e in exc.exceptions)
                        else:
                            msg = str(exc)
                        # Detect sampling errors that slipped through the stub
                        if "sampling not supported" in msg.lower() or "sampling" in msg.lower():
                            log(f"  [{module.name}] UNTESTED — server requires MCP Sampling (auto-approve stub active but may need re-scan)")
                            status = FindingStatus.POTENTIAL
                            title = f"Module '{module.name}' blocked by MCP Sampling requirement"
                            remediation = "Scanner sampling stub is active. Re-run scan — if this persists, the server may require a specific model response format."
                        else:
                            log(f"  [{module.name}] ERROR: {msg}")
                            status = FindingStatus.ERROR
                            title = f"Module '{module.name}' failed to run"
                            remediation = "Check scanner logs for details."
                        all_findings.append(Finding(
                            module_id=module.module_id,
                            title=title,
                            severity=Severity.INFO,
                            status=status,
                            cvss_score=0.0,
                            description=msg,
                            tool_name="(scanner)",
                            payload_used="(n/a)",
                            evidence="",
                            remediation=remediation,
                        ))

                # All modules finished — mark scan as complete before context managers unwind.
                # Any exception raised during teardown (e.g. server subprocess exits and
                # anyio TaskGroup detects a broken pipe) is normal and should not be
                # reported as a scan failure.
                scan_completed = True

    except BaseException as exc:
        # If the scan itself finished and the exception came from cleanup (subprocess
        # exit detected by anyio's TaskGroup), discard it — the result is valid.
        if scan_completed:
            pass
        else:
            if isinstance(exc, BaseExceptionGroup):
                err_msg = "; ".join(str(e) for e in exc.exceptions if str(e).strip())
            else:
                err_msg = str(exc).strip()
            if not err_msg:
                err_msg = type(exc).__name__
            # Return partial findings if we collected any before the crash
            return ScanResult(
                target=target,
                scan_id=scan_id,
                started_at=started_at,
                completed_at=datetime.datetime.utcnow().isoformat() + "Z",
                findings=all_findings,
                tools_discovered=tools_discovered,
                error=f"[partial — transport died mid-scan] {err_msg}" if all_findings else err_msg,
            )

    return ScanResult(
        target=target,
        scan_id=scan_id,
        started_at=started_at,
        completed_at=datetime.datetime.utcnow().isoformat() + "Z",
        findings=all_findings,
        tools_discovered=tools_discovered,
    )
