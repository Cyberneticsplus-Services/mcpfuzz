"""stdio transport — launches server as subprocess, communicates via stdin/stdout."""

import os
import shlex
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Optional

from mcp import ClientSession, types
from mcp.client.stdio import stdio_client, StdioServerParameters
from mcp.shared.context import RequestContext

from .base import MCPTransport


async def _auto_approve_sampling(
    context: RequestContext["ClientSession", Any],
    params: types.CreateMessageRequestParams,
) -> types.CreateMessageResult | types.ErrorData:
    """
    Sampling stub for MCPFuzz — auto-approves all server sampling requests.

    Some MCP servers (e.g. @mako10k/mcp-shell-server) use MCP Sampling to ask
    the connected LLM for confirmation before executing sensitive operations.
    Without this stub, those requests fail with 'Sampling not supported' and
    commands are never executed, making the server appear clean when it isn't.

    This stub returns a plain-text 'yes' approval so payloads actually execute
    and the scanner can observe real command output.
    """
    return types.CreateMessageResult(
        role="assistant",
        content=types.TextContent(type="text", text="yes"),
        model="mcpfuzz-sampling-stub",
        stopReason="endTurn",
    )


class StdioTransport(MCPTransport):
    """
    Connects to an MCP server running as a subprocess.
    The server command is split on spaces: first token is the executable,
    remaining tokens are arguments.

    Example:
        StdioTransport("npx @modelcontextprotocol/server-filesystem /tmp")
        StdioTransport("python3 my_mcp_server.py")
    """

    def __init__(self, command: str, timeout: int = 30, env: Optional[dict[str, str]] = None):
        parts = shlex.split(command)
        if not parts:
            raise ValueError("Server command cannot be empty")
        self._executable = parts[0]
        self._args = parts[1:]
        self._timeout = timeout
        # Merge extra env vars on top of the current process environment
        self._env = {**os.environ, **env} if env else None

    @asynccontextmanager
    async def connect(self) -> AsyncIterator[ClientSession]:
        params = StdioServerParameters(
            command=self._executable,
            args=self._args,
            env=self._env,
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(
                read,
                write,
                sampling_callback=_auto_approve_sampling,
            ) as session:
                await session.initialize()
                yield session
