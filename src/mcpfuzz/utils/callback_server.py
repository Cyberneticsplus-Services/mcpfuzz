"""
MCPFuzz Callback Server — lightweight HTTP listener for OOB (Out-of-Band) detection.

Used by SSRF and blind command injection modules to confirm vulnerabilities
when the exploit payload doesn't return output in the tool response.

Usage:
    async with CallbackServer() as cb:
        url = cb.url("ssrf", token)       # http://127.0.0.1:<port>/ssrf/<token>
        # ... send url as payload to target MCP server ...
        await asyncio.sleep(2)
        if cb.was_hit(token):
            # Confirmed: server fetched our URL
"""

import asyncio
import socket
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Hit:
    token: str
    path: str
    method: str
    headers: dict
    body: str
    received_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("0.0.0.0", 0))
        return s.getsockname()[1]


def _outbound_ip() -> str:
    """
    Return the IP address this machine uses for outbound connections.
    This is the LAN IP (e.g. 192.168.x.x) rather than 127.0.0.1, making
    the callback reachable from Docker containers, VMs, and sandboxed servers
    that can't reach the host via loopback.
    Falls back to 127.0.0.1 if detection fails (e.g. no network).
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


class CallbackServer:
    """
    Async HTTP callback server for OOB vulnerability confirmation.
    Binds to 0.0.0.0 (all interfaces) and advertises the machine's outbound
    LAN IP in callback URLs — reachable from Docker containers, VMs, and
    sandboxed MCP servers that cannot reach 127.0.0.1 on the host.
    Start it as an async context manager — it stops automatically on exit.
    """

    def __init__(self):
        self.port = _find_free_port()
        self._bind_host = "0.0.0.0"
        self._url_host = _outbound_ip()  # LAN IP used in advertised URLs
        self._hits: dict[str, Hit] = {}
        self._server: asyncio.Server | None = None

    def url(self, module: str, token: str) -> str:
        """Generate a unique callback URL for a test."""
        return f"http://{self._url_host}:{self.port}/{module}/{token}"

    def new_token(self) -> str:
        """Generate a new unique token."""
        return str(uuid.uuid4()).replace("-", "")[:16]

    def was_hit(self, token: str) -> Hit | None:
        """Return hit info if the callback was received, None otherwise."""
        return self._hits.get(token)

    async def _handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            raw = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            if not raw:
                return

            text = raw.decode("utf-8", errors="replace")
            lines = text.split("\r\n")

            # Parse request line
            method, path, *_ = (lines[0].split(" ") + ["", ""])[:3]

            # Parse headers
            headers = {}
            body = ""
            in_body = False
            for line in lines[1:]:
                if not line and not in_body:
                    in_body = True
                    continue
                if in_body:
                    body += line
                elif ":" in line:
                    k, _, v = line.partition(":")
                    headers[k.strip().lower()] = v.strip()

            # Extract token from path — format: /<module>/<token>
            parts = path.strip("/").split("/")
            token = parts[-1] if parts else ""

            if token:
                self._hits[token] = Hit(
                    token=token,
                    path=path,
                    method=method,
                    headers=headers,
                    body=body,
                )

            # Respond with 200 OK so the target doesn't retry
            response = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: 2\r\n"
                "Connection: close\r\n"
                "\r\nOK"
            )
            writer.write(response.encode())
            await writer.drain()

        except Exception:
            pass
        finally:
            writer.close()

    async def start(self):
        self._server = await asyncio.start_server(
            self._handle_connection,
            host=self._bind_host,
            port=self.port,
        )

    async def stop(self):
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, *args):
        await self.stop()
