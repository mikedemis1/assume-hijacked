"""The tool gateway built for tests: the real pipeline, the real database role, the tools as apps in
this process, and a risk engine that is either a stand-in or the real one.

Nothing here weakens the code under test. The gateway is `app.gateway.proxy.Gateway` with the same
checks as in the container; only the edges are replaced (the network by ASGI transports, the
Kubernetes TokenReview by a function).
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Callable
from contextlib import asynccontextmanager

import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from app.agent.gateway import ToolGateway
from app.common.ops import Metrics
from app.gateway import manifest
from app.gateway.auth import CallerAuth
from app.gateway.proxy import Gateway, GatewayDb, Verdict, init_metrics
from app.gateway.server import build_app
from app.risk import service as risk_service
from tests.toolhttp import KEYS, URL, AppToolClient, RecordingTransport, running


class FakeRisk:
    """Stands in for the risk engine: answers what it was told to, and keeps what it was asked."""

    def __init__(self, decision="allow", reasons=(), timed_out=False, before: Callable | None = None):
        self.decision, self.reasons, self.timed_out, self.before = decision, tuple(reasons), timed_out, before
        self.asked: list[tuple[str, str]] = []

    async def decide(self, lease: str, tool: str) -> Verdict:
        self.asked.append((lease, tool))
        if self.before:
            self.before(lease, tool)
        return Verdict(self.decision, self.reasons, self.timed_out)


class RealRisk:
    """The real /decide logic on the test database, called in process (no HTTP)."""

    def __init__(self, settings) -> None:
        self.metrics = Metrics()
        self.decider = risk_service.Decider(lambda: risk_service.connect(settings), self.metrics)

    async def decide(self, lease: str, tool: str) -> Verdict:
        decision, reasons = await asyncio.to_thread(self.decider.decide, lease, tool)
        return Verdict(decision, tuple(reasons))

    def close(self) -> None:
        self.decider.close()


class Built:
    """A gateway pipeline and what a test wants to look at."""

    def __init__(self, gateway, tools, risk, metrics, db, specs):
        self.gateway, self.tools, self.risk, self.metrics, self.db, self.specs = gateway, tools, risk, metrics, db, specs

    def call(self, tool: str, arguments: dict, lease: str, pod: str | None = None):
        from app.gateway.auth import CallerIdentity

        return asyncio.run(self.gateway.call(tool, arguments, lease, CallerIdentity(pod=pod)))


def build(
    settings,
    as_role,
    *,
    risk=None,
    apps: dict[str, Callable] | None = None,
    transports: dict[str, Callable] | None = None,
    tools: tuple[str, ...] | None = None,
    specs=None,
    clock: Callable[[], float] = time.time,
) -> Built:
    private, public = KEYS
    kwargs = {"tools": tools} if tools else {}
    client = AppToolClient(settings, private, public, clock=clock, apps=apps, transports=transports, **kwargs)
    metrics = Metrics()
    specs = specs or manifest.load_manifests()
    init_metrics(metrics, specs)
    db = GatewayDb(lambda: as_role("gateway"))
    risk = risk or FakeRisk()
    gateway = Gateway(db=db, risk=risk, tools=client, specs=specs, metrics=metrics)
    return Built(gateway, client, risk, metrics, db, specs)


# --- the MCP edge: what the agent talks to ---

# The subnet of the agent's edge network (compose.yaml) and an address in it: the harness reaches the
# gateway app as if from there.
AGENT_SUBNET = "10.250.1.0/24"
AGENT_IP = "10.250.1.5"


def compose_auth() -> CallerAuth:
    return CallerAuth(mode="compose", allowed_subnet=AGENT_SUBNET)


def from_agent(app) -> httpx2.ASGITransport:
    """A transport to the gateway app whose requests come from the agent's address."""
    return httpx2.ASGITransport(app=app, client=(AGENT_IP, 50000))


@asynccontextmanager
async def agent_session(app, headers: dict[str, str]):
    """An MCP client of the gateway app, in process, sending `headers` on every request."""
    async with running(app):
        async with httpx2.AsyncClient(transport=from_agent(app), base_url="http://gateway.test", headers=headers) as http:
            async with Client(streamable_http_client(URL, http_client=http)) as client:
                yield client


class AppGatewayClient(ToolGateway):
    """The agent's tool client (the production class) talking to the gateway app in this process."""

    def __init__(self, built: Built, auth: CallerAuth | None = None, headers: dict[str, str] | None = None):
        super().__init__(URL, headers=(lambda: dict(headers)) if headers else None)
        self._built, self._auth = built, auth or compose_auth()
        self.sent: list = []

    @asynccontextmanager
    async def _transport(self):
        app = build_app(self._built.gateway, self._auth)
        async with running(app):
            yield RecordingTransport(from_agent(app), self.sent)

    def wire_bodies(self) -> list[dict]:
        return [json.loads(body) for _, body in self.sent if body]
