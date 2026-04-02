"""Base class for all scan modules."""

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING
from mcp import ClientSession
from ..models import Finding

if TYPE_CHECKING:
    from ..utils.callback_server import CallbackServer


class ScanModule(ABC):
    """
    Every test module implements this interface.
    run() receives a live ClientSession and the server's tool list.
    It sends real exploit payloads and returns confirmed/potential findings.
    """

    module_id: str       # e.g. "path_traversal"
    name: str            # e.g. "Path Traversal"
    description: str     # One-line description for --list-modules

    # Injected by scanner before run() is called — None for modules that don't need it
    callback_server: "CallbackServer | None" = None

    # Optional Anthropic client injected when --llm-key is provided
    # Modules that support LLM-enhanced analysis check this before using it
    llm_client: object | None = None

    # The raw server command / URL being scanned — injected by scanner.py
    # Modules can use this for framework detection or context-aware severity decisions
    server_command: str = ""

    # Transport type ("stdio" | "sse" | "http" | "streamable-http") — injected by scanner.py
    # Affects severity calibration: stdio = local process (reduced attack surface),
    # sse/http/streamable-http = network-exposed (full attack surface)
    transport: str = ""

    # Tool parameter names that this module targets.
    # If empty, module runs against all tools and decides relevance internally.
    target_param_names: list[str] = []

    @abstractmethod
    async def run(self, session: ClientSession, tools: list[dict]) -> list[Finding]:
        """
        Run all exploit attempts for this module.
        Returns list of findings — empty list if nothing found.
        Never raises exceptions — catch internally and return Finding with status=ERROR.
        """
        ...

    def _is_relevant_tool(self, tool: dict) -> bool:
        """Check if this tool has parameters this module should target."""
        if not self.target_param_names:
            return True
        schema = tool.get("inputSchema", {})
        properties = schema.get("properties", {})
        tool_name = tool.get("name", "").lower()
        param_names = [k.lower() for k in properties.keys()]
        for target in self.target_param_names:
            if target in param_names or target in tool_name:
                return True
        return False

    def _get_string_params(self, tool: dict) -> list[str]:
        """Return list of parameter names that accept string values."""
        schema = tool.get("inputSchema", {})
        properties = schema.get("properties", {})
        return [
            name for name, spec in properties.items()
            if spec.get("type") == "string" or "type" not in spec
        ]

    @staticmethod
    def _has_no_params(tool: dict) -> bool:
        """Returns True if the tool declares no parameters in its schema.
        No-arg tools should not receive fuzzing payloads in extra kwargs —
        any response they produce is their normal response, not a vulnerability reaction.
        """
        return not bool(tool.get("inputSchema", {}).get("properties"))

    @staticmethod
    async def _get_baseline_text(session: "ClientSession", tool: dict, timeout: float = 8.0) -> str:
        """Call a tool with no/empty arguments to get its baseline response.
        Used to compare against fuzz responses so we only report leaks that are
        NEW relative to what the tool normally returns (prevents FIND-018 class FPs).
        Returns empty string if the baseline call fails or times out.
        """
        import asyncio
        tool_name = tool.get("name", "")
        try:
            result = await asyncio.wait_for(
                session.call_tool(tool_name, arguments={}),
                timeout=timeout,
            )
            parts = []
            for item in result.content:
                if hasattr(item, "text"):
                    parts.append(item.text)
                elif isinstance(item, dict) and "text" in item:
                    parts.append(item["text"])
            return "\n".join(parts)
        except Exception:
            return ""
