"""Abstract transport base — all transports expose a connect() context manager."""

from abc import ABC, abstractmethod
from contextlib import asynccontextmanager
from typing import AsyncIterator

from mcp import ClientSession


class MCPTransport(ABC):
    """
    Base class for all MCP transports.
    Usage:
        async with transport.connect() as session:
            tools = await session.list_tools()
    """

    @asynccontextmanager
    @abstractmethod
    async def connect(self) -> AsyncIterator[ClientSession]:
        yield  # type: ignore
