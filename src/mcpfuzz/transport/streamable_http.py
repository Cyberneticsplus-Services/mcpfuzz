"""Streamable HTTP transport — connects to MCP servers using MCP SDK ≥1.7 Streamable HTTP protocol."""

from contextlib import asynccontextmanager
from typing import AsyncIterator, Optional

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

from .base import MCPTransport
from .stdio import _auto_approve_sampling


class StreamableHTTPTransport(MCPTransport):
    """
    Connects to an MCP server using the Streamable HTTP protocol (MCP SDK ≥1.7).

    This is distinct from the legacy SSE transport:
    - Legacy SSE:        GET /sse  (persistent event stream)
    - Streamable HTTP:  POST /mcp (JSON body, Accept: text/event-stream response)

    Example:
        StreamableHTTPTransport("http://localhost:3001/mcp")
        StreamableHTTPTransport("http://localhost:3001/mcp", auth_token="Bearer sk-...")
    """

    def __init__(self, url: str, auth_token: Optional[str] = None, timeout: int = 30):
        self._url = url
        self._headers: dict[str, str] = {}
        if auth_token:
            self._headers["Authorization"] = auth_token
        self._timeout = timeout

    @asynccontextmanager
    async def connect(self) -> AsyncIterator[ClientSession]:
        async with streamablehttp_client(
            self._url,
            headers=self._headers,
            timeout=float(self._timeout),
        ) as (read, write, _get_session_id):
            async with ClientSession(
                read,
                write,
                sampling_callback=_auto_approve_sampling,
            ) as session:
                await session.initialize()
                yield session
