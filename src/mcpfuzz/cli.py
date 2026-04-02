"""MCPFuzz CLI — entry point."""

import sys
import json
import anyio
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.text import Text

from .models import ScanTarget, FindingStatus, Severity
from .engine import run_scan
from .reporting import write_json_report
from .modules import ALL_MODULES
from .poc_generator import generate_all_pocs, print_poc_summary

console = Console()

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}

SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}


@click.group()
@click.version_option("0.1.0", prog_name="mcpfuzz")
def main():
    """
    MCPFuzz — Dynamic MCP Security Scanner

    Actively connects to MCP servers and probes them with exploit payloads.
    Unlike static analysis tools, MCPFuzz tests real server behavior.

    By Cyberneticsplus Services Private Limited
    """
    pass


@main.command()
@click.option("--server", "-s", required=True,
              help="Server to scan. For stdio: the command to launch it (e.g. 'npx @modelcontextprotocol/server-filesystem /tmp'). For sse/http: the server URL.")
@click.option("--transport", "-t", default="stdio",
              type=click.Choice(["stdio", "sse", "http", "streamable-http"]),
              help="Transport protocol (default: stdio)")
@click.option("--modules", "-m", default=None,
              help="Comma-separated list of module IDs to run. Default: all modules. Example: path_traversal,ssrf,command_injection")
@click.option("--output", "-o", default="console",
              type=click.Choice(["console", "json"]),
              help="Output format (default: console)")
@click.option("--out", default=None,
              help="Write output to file (use with --output json)")
@click.option("--timeout", default=30, show_default=True,
              help="Timeout in seconds per tool call")
@click.option("--fail-on", default="high",
              type=click.Choice(["critical", "high", "medium", "low"]),
              help="Exit with code 1 if findings at this severity or above are found (default: high)")
@click.option("--token", default=None,
              help="Auth token for SSE/HTTP transports (sent as Authorization header)")
@click.option("--quiet", "-q", is_flag=True, help="Suppress progress output, print results only")
@click.option("--poc-dir", default=None,
              help="Auto-generate standalone POC scripts + terminal screenshots into this directory for every confirmed finding (default: ./poc/)")
@click.option("--env", "-e", multiple=True,
              help="Extra environment variables for the server subprocess (stdio only). Format: KEY=VALUE. Can be repeated.")
@click.option("--llm-key", default=None, envvar="ANTHROPIC_API_KEY",
              help="API key for LLM-judge. "
                   "anthropic: Anthropic key (or ANTHROPIC_API_KEY env var). "
                   "ollama cloud: OLLAMA_API_KEY from ollama.com/settings/keys. "
                   "ollama local: not needed. "
                   "openai: OpenAI key.")
@click.option("--llm-provider", default="anthropic",
              type=click.Choice(["anthropic", "ollama", "openai"]),
              show_default=True,
              help="LLM provider for tool poisoning judge. "
                   "'ollama' + key → Ollama Cloud (ollama.com), default model qwen3.5:cloud. "
                   "'ollama' no key → local Ollama at localhost:11434, default model llama3.2. "
                   "'anthropic' → Claude Haiku (requires --llm-key). "
                   "'openai' → OpenAI API (requires --llm-key).")
@click.option("--llm-model", default=None,
              help="Model name override. "
                   "Ollama cloud default: qwen3.5:cloud  "
                   "Ollama local default: llama3.2  "
                   "Anthropic default: claude-haiku-4-5-20251001  "
                   "OpenAI default: gpt-4o-mini")
@click.option("--llm-url", default=None,
              help="Override the LLM provider host/base URL "
                   "(e.g. point ollama at a self-hosted cloud GPU instead of ollama.com).")
def scan(server, transport, modules, output, out, timeout, fail_on, token, quiet, poc_dir, env,
         llm_key, llm_provider, llm_model, llm_url):
    """Scan an MCP server for security vulnerabilities."""

    module_list = [m.strip() for m in modules.split(",")] if modules else None

    env_vars: dict[str, str] = {}
    for item in env:
        if "=" not in item:
            raise click.BadParameter(f"--env value must be KEY=VALUE, got: {item!r}", param_hint="--env")
        k, _, v = item.partition("=")
        env_vars[k] = v

    target = ScanTarget(
        server=server,
        transport=transport,
        timeout=timeout,
        auth_token=token,
        modules=module_list,
        fail_on=fail_on,
        env=env_vars if env_vars else None,
        llm_key=llm_key or None,
        llm_provider=llm_provider,
        llm_model=llm_model or None,
        llm_url=llm_url or None,
    )

    if not quiet:
        console.print(Panel(
            f"[bold]MCPFuzz[/bold] — Dynamic MCP Security Scanner\n"
            f"[dim]By Cyberneticsplus Services Private Limited[/dim]\n\n"
            f"Target: [cyan]{server}[/cyan]\n"
            f"Transport: [cyan]{transport}[/cyan]\n"
            f"Modules: [cyan]{modules or 'all (' + str(len(ALL_MODULES)) + ')'}[/cyan]",
            box=box.ROUNDED,
            style="bold blue",
        ))

    def progress(msg: str):
        if not quiet:
            console.print(f"[dim]  {msg}[/dim]")

    result = anyio.run(run_scan, target, progress)

    # Always write output and generate POCs — even on partial/error results
    if output == "json":
        json_out = write_json_report(result, output_path=out)
        if not out:
            print(json_out)
    else:
        _print_console_report(result, quiet)

    poc_output_dir = poc_dir or "poc"
    confirmed_non_info = [
        f for f in result.findings
        if f.status == FindingStatus.CONFIRMED and f.severity.value != "info"
    ]
    if confirmed_non_info:
        generated = generate_all_pocs(result, poc_output_dir)
        if not quiet:
            print_poc_summary(generated, console)

    # Report error after output is written so partial findings are never lost
    if result.error and result.error.strip():
        console.print(f"[bold red]✗ Scan failed:[/bold red] {result.error}")
        sys.exit(2)

    sys.exit(result.exit_code)


def _print_console_report(result, quiet: bool):
    summary = result.summary()
    confirmed = [f for f in result.findings if f.status == FindingStatus.CONFIRMED and f.severity != Severity.INFO]
    potential = [f for f in result.findings if f.status == FindingStatus.POTENTIAL]

    # Summary panel
    status_color = "bold red" if confirmed else "bold green"
    status_icon = "✗ VULNERABLE" if confirmed else "✓ CLEAN"
    console.print()
    console.print(Panel(
        f"[{status_color}]{status_icon}[/{status_color}]\n\n"
        f"Tools discovered: {summary['tools_discovered']}\n"
        f"Confirmed findings: [bold]{summary['findings_confirmed']}[/bold]\n"
        + (f"Potential findings: {len(potential)}\n" if potential else "")
        + "\n".join(
            f"  {SEVERITY_EMOJI.get(Severity(sev), '')} {sev.upper()}: {count}"
            for sev, count in summary.get("by_severity", {}).items()
        ),
        title=f"Scan {summary['scan_id']} — {summary['target']}",
        box=box.ROUNDED,
    ))

    if not confirmed and not potential:
        console.print("[bold green]No vulnerabilities found.[/bold green]")
        return

    # Findings table
    table = Table(
        title="Findings",
        box=box.ROUNDED,
        show_lines=True,
        expand=True,
    )
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Status", width=10)
    table.add_column("Module", width=18)
    table.add_column("Tool", width=20)
    table.add_column("Title")

    for finding in sorted(
        result.findings,
        key=lambda f: ["critical", "high", "medium", "low", "info"].index(f.severity.value)
    ):
        if finding.status == FindingStatus.ERROR:
            continue
        sev_color = SEVERITY_COLORS.get(finding.severity, "")
        table.add_row(
            Text(f"{SEVERITY_EMOJI.get(finding.severity, '')} {finding.severity.value.upper()}", style=sev_color),
            finding.status.value,
            finding.module_id,
            finding.tool_name,
            finding.title,
        )

    console.print(table)

    # Detail view for confirmed findings
    if confirmed:
        console.print()
        console.print("[bold]Finding Details:[/bold]")
        for i, finding in enumerate(confirmed, 1):
            sev_color = SEVERITY_COLORS.get(finding.severity, "")
            console.print(Panel(
                f"[bold]CVSS:[/bold] {finding.cvss_score}  |  "
                f"[bold]CWE:[/bold] {finding.cwe_id or 'N/A'}\n\n"
                f"[bold]Description:[/bold]\n{finding.description}\n\n"
                f"[bold]Payload:[/bold] [cyan]{finding.payload_used}[/cyan]\n\n"
                f"[bold]Evidence:[/bold]\n[yellow]{finding.evidence}[/yellow]\n\n"
                f"[bold]Remediation:[/bold]\n{finding.remediation}",
                title=f"[{sev_color}]{i}. {finding.title}[/{sev_color}]",
                box=box.ROUNDED,
            ))


@main.command("list-modules")
def list_modules():
    """List all available scan modules."""
    table = Table(title="MCPFuzz Modules", box=box.ROUNDED, show_lines=True)
    table.add_column("ID", style="cyan", width=20)
    table.add_column("Name", width=25)
    table.add_column("Description")

    for module in ALL_MODULES:
        table.add_row(module.module_id, module.name, module.description)

    console.print(table)


if __name__ == "__main__":
    main()
