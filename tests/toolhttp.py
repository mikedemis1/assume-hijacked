"""Helpers that talk to a tool the way the real callers do: over HTTP, with a signed token on every
request. The tool app runs in this process (an ASGI transport, no socket), so a test sees the same
middleware and the same MCP server as the container does."""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from contextlib import asynccontextmanager

import httpx2
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from app.agent.gateway import ToolGateway
from app.security.tokens import JtiCache
from app.tools import serve

URL = "http://tool.test/mcp"
MCP_HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
TOOLS_LIST = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
# A call that makes read_ticket ask for its database connection (tools/list never does).
CALL_READ_TICKET = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": {"name": "read_ticket", "arguments": {}}}


def make_keypair() -> tuple[bytes, bytes]:
    """A fresh EC P-256 key pair as PEM bytes (private PKCS8, public SubjectPublicKeyInfo)."""
    private = ec.generate_private_key(ec.SECP256R1())
    return (
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ),
    )


# One pair for the tests that only need some gateway key (the agent tests).
KEYS = make_keypair()


@pytest.fixture(scope="session")
def keypair() -> tuple[bytes, bytes]:
    return make_keypair()


@pytest.fixture(scope="session")
def other_keypair() -> tuple[bytes, bytes]:
    return make_keypair()


class ConnectSpy:
    """Stands in for the tool's database connection and counts how often it is asked for one."""

    def __init__(self) -> None:
        self.calls = 0

    def __call__(self):
        self.calls += 1
        raise RuntimeError("the database was reached")


def bearer(token: str) -> dict[str, str]:
    return {**MCP_HEADERS, "Authorization": f"Bearer {token}"}


async def post(app, headers: dict[str, str], body: dict | None = None) -> httpx2.Response:
    """One raw POST to /mcp, with exactly the headers given. The MCP session manager is not
    started, so only a request the token check refuses can be sent this way."""
    async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url="http://tool.test") as http:
        return await http.post("/mcp", headers=headers, content=json.dumps(body or TOOLS_LIST))


async def post_each(app, *header_sets: dict[str, str], body: dict | None = None, spy=None) -> list:
    """Raw POSTs one after another to one running app (so a token let through can be answered).
    Returns (response, connections the spy had been asked for after that request) per request."""
    answers = []
    async with running(app):
        for headers in header_sets:
            response = await post(app, headers, body)
            answers.append((response, spy.calls if spy is not None else None))
    return answers


@asynccontextmanager
async def running(app):
    """The tool app with its MCP session manager started (the lifespan an ASGI server would run)."""
    async with app.app.router.lifespan_context(app.app):
        yield app


@asynccontextmanager
async def mcp_client(app, auth: httpx2.Auth | None):
    async with running(app):
        transport = httpx2.ASGITransport(app=app)
        async with httpx2.AsyncClient(transport=transport, base_url="http://tool.test", auth=auth) as http:
            async with Client(streamable_http_client(URL, http_client=http)) as client:
                yield client


class RecordingTransport(httpx2.AsyncBaseTransport):
    """Passes every request on and keeps what was sent: the headers and the body."""

    def __init__(self, inner: httpx2.AsyncBaseTransport, sent: list) -> None:
        self._inner = inner
        self._sent = sent

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        self._sent.append((dict(request.headers), request.content))
        return await self._inner.handle_async_request(request)


class AppToolGateway(ToolGateway):
    """The agent's tool client (the production class), with the tools as apps in this process.
    Every call builds the app again (an MCP session manager runs once), all of them sharing one
    replay cache like one server. `sent` collects every request that left the client."""

    def __init__(self, settings, private_pem: bytes, public_pem: bytes, tools=serve.TOOLS, clock=time.time):
        super().__init__({tool: URL for tool in tools}, private_pem, clock)
        seen = JtiCache()
        self.sent: list = []
        self._apps: dict[str, Callable] = {
            tool: (lambda tool=tool: serve.build_app(tool, settings, public_pem, seen=seen, clock=clock))
            for tool in tools
        }

    @asynccontextmanager
    async def _transport(self, name: str):
        app = self._apps[name]()
        async with running(app):
            yield RecordingTransport(httpx2.ASGITransport(app=app), self.sent)
