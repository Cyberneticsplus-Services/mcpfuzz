"""SSE transport — connects to remote MCP server via HTTP + Server-Sent Events."""

from contextlib import asynccontextmanager
from typing import AsyncIterator, Optional

from mcp import ClientSession
from mcp.client.sse import sse_client

from .base import MCPTransport
from .stdio import _auto_approve_sampling


class SSETransport(MCPTransport):
    """
    Connects to an MCP server running as an HTTP/SSE service.

    Example:
        SSETransport("http://localhost:8080/sse")
        SSETransport("http://localhost:8080", auth_token="Bearer sk-...")
    """

    def __init__(self, url: str, auth_token: Optional[str] = None, timeout: int = 30):
        self._url = url if "/sse" in url else url.rstrip("/") + "/sse"
        self._headers: dict[str, str] = {}
        if auth_token:
            self._headers["Authorization"] = auth_token
        self._timeout = timeout

    @asynccontextmanager
    async def connect(self) -> AsyncIterator[ClientSession]:
        async with sse_client(self._url, headers=self._headers) as (read, write):
            async with ClientSession(
                read,
                write,
                sampling_callback=_auto_approve_sampling,
            ) as session:
                await session.initialize()
                yield session
