"""POC auto-generator — creates standalone exploit scripts + terminal screenshots per confirmed finding."""

from __future__ import annotations

import os
import re
import shlex
import textwrap
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .models import Finding, ScanResult

# PIL is optional — image generation is skipped gracefully if not installed
try:
    from PIL import Image, ImageDraw, ImageFont
    _PIL_AVAILABLE = True
except ImportError:
    _PIL_AVAILABLE = False


# ─── Terminal colour palette (ANSI-inspired hex) ──────────────────────────────
_BG      = (18, 18, 18)
_GREY    = (120, 120, 120)
_WHITE   = (220, 220, 220)
_CYAN    = (97, 214, 214)
_GREEN   = (106, 213, 106)
_YELLOW  = (249, 196, 78)
_RED     = (237, 80, 80)
_BOLD_RED= (255, 100, 100)
_DIM     = (90, 90, 90)

_FONT_SIZE  = 14
_LINE_H     = 20
_PADDING    = 20
_IMG_WIDTH  = 960


# ─── Public entry point ───────────────────────────────────────────────────────

def generate_all_pocs(result: "ScanResult", output_dir: str | Path) -> list[dict]:
    """Generate a POC script + terminal PNG for every confirmed non-INFO finding.

    Returns a list of dicts: {finding_id, script_path, image_path, skipped_reason}.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    generated = []
    for finding in result.findings:
        from .models import FindingStatus, Severity
        if finding.status != FindingStatus.CONFIRMED:
            continue
        if finding.severity == Severity.INFO:
            continue

        rec: dict = {"finding_id": finding.finding_id}

        if finding.payload_args is None:
            rec["skipped_reason"] = "payload_args not set for this module"
            generated.append(rec)
            continue

        slug = f"{finding.finding_id}-{finding.module_id}"
        script_path = output_dir / f"poc-{slug}.py"
        image_path  = output_dir / f"poc-{slug}.png"

        script_src = _build_script(finding, result.target)
        script_path.write_text(script_src, encoding="utf-8")
        rec["script_path"] = str(script_path)

        if _PIL_AVAILABLE:
            lines = _build_terminal_lines(finding, result.target)
            img = _render_terminal(lines)
            img.save(str(image_path))
            rec["image_path"] = str(image_path)
        else:
            rec["image_path"] = None
            rec["image_skipped_reason"] = "Pillow not installed (pip install Pillow)"

        generated.append(rec)

    return generated


# ─── Script generation ────────────────────────────────────────────────────────

def _build_script(finding: "Finding", target) -> str:
    """Return the full source of a standalone POC script."""
    transport     = target.transport
    server_string = target.server
    tool_name     = finding.tool_name
    payload_args  = finding.payload_args  # dict

    args_repr = _dict_repr(payload_args)

    connect_block, import_block = _transport_connect(transport, server_string)
    check_block = _module_check(finding)

    evidence_short = finding.evidence[:200].replace('"', '\\"')
    banner_line1 = f"POC: {finding.title[:58]}".replace('"', '\\"')
    banner_line2 = f"  {finding.module_id.upper()} | {finding.cwe_id or 'N/A'} | Reporter: Cyberneticsplus"

    # Build the script as a list of lines to avoid dedent/f-string indentation issues
    lines = [
        "#!/usr/bin/env python3",
        '"""',
        f"POC: {finding.title}",
        f"Module   : {finding.module_id}",
        f"CWE      : {finding.cwe_id or 'N/A'}",
        f"CVSS     : {finding.cvss_score}",
        f"Severity : {finding.severity.value.upper()}",
        "Reporter : Cyberneticsplus Services Private Limited",
        "",
        f"Evidence : {finding.evidence[:200]}",
        "",
        "Usage:",
        "  pip install mcp",
        f"  python3 poc-{finding.finding_id}-{finding.module_id}.py",
        '"""',
        "",
        "import asyncio",
    ]

    for imp_line in import_block.splitlines():
        lines.append(imp_line)

    lines += [
        "",
        'RESET  = "\\033[0m"',
        'RED    = "\\033[91m"',
        'GREEN  = "\\033[92m"',
        'YELLOW = "\\033[93m"',
        'CYAN   = "\\033[96m"',
        'BOLD   = "\\033[1m"',
        "",
        "",
        "def banner():",
        "    width = 68",
        f'    lines = ["{banner_line1}", "{banner_line2}", "Reporter: Cyberneticsplus Services Private Limited"]',
        '    print(f"{BOLD}{RED}" + "╔" + "═" * width + "╗")',
        "    for ln in lines:",
        '        print("║  " + ln.ljust(width - 2) + "  ║")',
        '    print("╚" + "═" * width + f"╝{RESET}")',
        "",
        "",
        "async def run():",
        "    banner()",
    ]

    for connect_line in connect_block.splitlines():
        lines.append(f"    {connect_line}")

    lines += [
        "",
        "            # ── Exploit ───────────────────────────────────────────",
        f"            print(f\"{{YELLOW}}[>] Calling {tool_name!r} with arguments: {args_repr}{{RESET}}\")",
        f"            result = await session.call_tool(",
        f"                {tool_name!r},",
        f"                arguments={args_repr},",
        "            )",
        "",
        "            # Extract response text",
        '            response_text = ""',
        "            for item in result.content:",
        '                if hasattr(item, "text"):',
        "                    response_text = item.text",
        "                    break",
        "",
    ]

    for check_line in check_block.splitlines():
        lines.append(f"            {check_line}")

    lines += [
        "",
        '    print(f"{BOLD}[*] POC complete.{RESET}")',
        "",
        "",
        'if __name__ == "__main__":',
        "    asyncio.run(run())",
        "",
    ]

    return "\n".join(lines)


def _transport_connect(transport: str, server_string: str) -> tuple[str, str]:
    """Return (connect_block, import_line) for the given transport."""
    if transport == "stdio":
        # Parse command + args from shell string
        try:
            parts = shlex.split(server_string)
        except ValueError:
            parts = server_string.split()
        cmd  = parts[0] if parts else "npx"
        args = parts[1:] if len(parts) > 1 else []

        import_block = (
            "from mcp import ClientSession, StdioServerParameters\n"
            "from mcp.client.stdio import stdio_client"
        )
        connect = textwrap.dedent(f"""\
            params = StdioServerParameters(
                command={cmd!r},
                args={args!r},
            )

            print(f"{{CYAN}}[*] Connecting (stdio)...{{RESET}}")
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    tools = await session.list_tools()
                    tool_names = [t.name for t in tools.tools]
                    print(f"{{GREEN}}[+] Connected — {{len(tool_names)}} tools discovered{{RESET}}\\n")
        """)

    elif transport in ("sse", "http"):
        import_block = (
            "from mcp import ClientSession\n"
            "from mcp.client.sse import sse_client"
        )
        connect = textwrap.dedent(f"""\
            url = {server_string!r}
            print(f"{{CYAN}}[*] Connecting (SSE) to {{url}}...{{RESET}}")
            async with sse_client(url) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    tools = await session.list_tools()
                    tool_names = [t.name for t in tools.tools]
                    print(f"{{GREEN}}[+] Connected — {{len(tool_names)}} tools discovered{{RESET}}\\n")
        """)
    else:
        import_block = "from mcp import ClientSession, StdioServerParameters\nfrom mcp.client.stdio import stdio_client"
        connect = f'    raise NotImplementedError("Unsupported transport: {transport}")\n'

    return connect, import_block


def _module_check(finding: "Finding") -> str:
    """Return the response-checking block specific to each module."""
    mid = finding.module_id

    if mid == "path_traversal":
        return textwrap.dedent("""\
            if (
                response_text
                and len(response_text) > 20
                and "error" not in response_text.lower()[:60]
                and "not found" not in response_text.lower()[:60]
                and "eacces" not in response_text.lower()[:60]
            ):
                print(f"{RED}{BOLD}[!!!] PATH TRAVERSAL CONFIRMED — server returned file content:{RESET}")
                print(f"{RED}" + "─" * 64)
                print(response_text[:800])
                print("─" * 64 + f"{RESET}\\n")
            else:
                print(f"{GREEN}[=] Blocked or not found: {response_text[:120]}{RESET}\\n")
        """)

    if mid == "ssrf":
        return textwrap.dedent("""\
            # NOTE: OOB SSRF — you need an external callback server.
            # Replace OOB_CALLBACK_URL above with your Interactsh/Burp Collaborator URL.
            # After running, check your callback server for an incoming HTTP request.
            print(f"{YELLOW}[*] Request sent. Check your callback server for an incoming connection.{RESET}")
            print(f"    Response: {response_text[:200]}")
        """)

    if mid == "auth_bypass":
        return textwrap.dedent("""\
            if response_text and len(response_text) > 10:
                print(f"{RED}{BOLD}[!!!] AUTH BYPASS CONFIRMED — tool responded without valid auth:{RESET}")
                print(f"{RED}" + "─" * 64)
                print(response_text[:600])
                print("─" * 64 + f"{RESET}\\n")
            else:
                print(f"{GREEN}[=] Tool appears to require auth (got error or empty response){RESET}\\n")
        """)

    if mid == "command_injection":
        return textwrap.dedent("""\
            # Check for command injection evidence — OS command output in response
            import re as _re
            canary_patterns = [r"uid=\\d+", r"root:", r"bin/sh", r"Windows IP", r"Directory of"]
            if any(_re.search(p, response_text) for p in canary_patterns):
                print(f"{RED}{BOLD}[!!!] COMMAND INJECTION CONFIRMED:{RESET}")
                print(f"{RED}" + "─" * 64)
                print(response_text[:600])
                print("─" * 64 + f"{RESET}\\n")
            else:
                print(f"{GREEN}[=] No command injection evidence in response{RESET}")
                print(f"    Response: {response_text[:200]}")
        """)

    # Generic fallback
    return textwrap.dedent("""\
        print(f"{YELLOW}[>] Response received:{RESET}")
        print("─" * 64)
        print(response_text[:600] if response_text else "(empty)")
        print("─" * 64 + "\\n")
    """)


def _dict_repr(d: dict) -> str:
    """Return a compact Python dict literal string."""
    if not d:
        return "{}"
    parts = []
    for k, v in d.items():
        parts.append(f"{k!r}: {v!r}")
    return "{" + ", ".join(parts) + "}"


# ─── Terminal image generation ────────────────────────────────────────────────

def _build_terminal_lines(finding: "Finding", target) -> list[tuple[str, tuple]]:
    """Return list of (text, colour) pairs for the terminal image."""
    tool_name    = finding.tool_name
    payload_args = finding.payload_args or {}
    raw_response = str(finding.raw_response or "")[:600]

    lines: list[tuple[str, tuple]] = []

    # Banner
    lines.append(("╔" + "═" * 66 + "╗", _BOLD_RED))
    title = f"  POC: {finding.title[:58]}"
    lines.append(("║" + title.ljust(67) + "║", _BOLD_RED))
    cwe_line = f"  {finding.module_id.upper()} | {finding.cwe_id or 'N/A'} | Reporter: Cyberneticsplus"
    lines.append(("║" + cwe_line.ljust(67) + "║", _BOLD_RED))
    lines.append(("╚" + "═" * 66 + "╝", _BOLD_RED))
    lines.append(("", _WHITE))

    # Connection
    transport = target.transport
    lines.append((f"[*] Connecting via {transport}...", _CYAN))
    lines.append(("[+] Connected. Tools discovered.", _GREEN))
    lines.append(("", _WHITE))

    # Payload
    args_str = ", ".join(f"{k}={v!r}" for k, v in payload_args.items())
    lines.append((f"[>] Calling '{tool_name}' with {args_str}", _YELLOW))
    lines.append(("", _WHITE))

    # Result
    _vuln_labels = {
        "path_traversal": "[!!!] PATH TRAVERSAL CONFIRMED — server returned file content:",
        "ssrf":           "[!!!] SSRF CONFIRMED (OOB) — callback received from server:",
        "auth_bypass":    "[!!!] AUTH BYPASS CONFIRMED — tool responded without valid auth:",
        "command_injection": "[!!!] COMMAND INJECTION CONFIRMED:",
    }
    label = _vuln_labels.get(finding.module_id, "[!!!] VULNERABILITY CONFIRMED:")
    lines.append((label, _BOLD_RED))
    lines.append(("─" * 64, _RED))

    # Response content
    for resp_line in (raw_response.splitlines() or ["(see evidence below)"])[:18]:
        lines.append((resp_line[:96], _WHITE))

    lines.append(("─" * 64, _RED))
    lines.append(("", _WHITE))
    lines.append(("[*] POC complete.", _WHITE))

    return lines


def _render_terminal(lines: list[tuple[str, tuple]]) -> "Image.Image":
    """Render a dark terminal image from a list of (text, colour) pairs."""
    from PIL import Image, ImageDraw, ImageFont

    height = _PADDING * 2 + len(lines) * _LINE_H + 10
    img  = Image.new("RGB", (_IMG_WIDTH, height), color=_BG)
    draw = ImageDraw.Draw(img)

    # Try to load a monospace font; fall back to default
    font = None
    font_candidates = [
        "/System/Library/Fonts/Supplemental/Courier New.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
    ]
    for fc in font_candidates:
        if os.path.exists(fc):
            try:
                font = ImageFont.truetype(fc, _FONT_SIZE)
                break
            except Exception:
                pass
    if font is None:
        font = ImageFont.load_default()

    y = _PADDING
    for text, colour in lines:
        draw.text((_PADDING, y), text, fill=colour, font=font)
        y += _LINE_H

    return img


# ─── CLI helper ───────────────────────────────────────────────────────────────

def print_poc_summary(generated: list[dict], console) -> None:
    """Print a Rich summary of generated POC files."""
    written = [g for g in generated if "script_path" in g]
    skipped = [g for g in generated if "skipped_reason" in g]

    if not written and not skipped:
        return

    console.print()
    console.print("[bold]POC files generated:[/bold]")
    for g in written:
        img_note = f"  + {Path(g['image_path']).name}" if g.get("image_path") else "  (no image)"
        console.print(f"  [cyan]{Path(g['script_path']).name}[/cyan]{img_note}")
    if skipped:
        console.print(f"  [dim]{len(skipped)} finding(s) skipped (payload_args not set)[/dim]")
