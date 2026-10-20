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

from app.agent.gateway import ToolGateway
from app.common.ops import Metrics
from app.gateway import manifest
from app.gateway.auth import AGENT_USER, AUDIENCE, CallerAuth, Review
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

# The agent as the gateway sees it: a projected token that the stand-in TokenReview knows, and the
# pod it was issued to. A lease the agent uses over HTTP is bound to that pod (agent_lease).
AGENT_IP = "10.250.1.5"  # the address a request comes from; the caller check does not read it
AGENT_TOKEN = "token-of-the-agent"
AGENT_POD = "agent-1-deadbeef-abcde"
AGENT_HEADERS = {"Authorization": f"Bearer {AGENT_TOKEN}"}
AGENT_RAW_HEADERS = [(b"authorization", f"Bearer {AGENT_TOKEN}".encode())]


def token_reviewer(tokens: dict[str, tuple[str, str | None]]):
    """A TokenReview stand-in: token -> (service account user, pod). Records what it was asked and
    insists on the gateway's audience."""
    asked: list[tuple[str, str]] = []

    def review(token, audience):
        asked.append((token, audience))
        assert audience == AUDIENCE
        found = tokens.get(token)
        if not found:
            return None
        pod = found[1]() if callable(found[1]) else found[1]  # a test can say "the pod of the run now"
        return Review(username=found[0], pod=pod)

    review.asked = asked
    return review


def agent_auth(extra: dict[str, tuple[str, str | None]] | None = None, pod=AGENT_POD) -> CallerAuth:
    """The caller check as the process builds it (mode k8s), with the stand-in TokenReview that knows
    the agent's token (issued to `pod`, a name or a function giving it), and `extra` tokens when a test
    needs another caller."""
    return CallerAuth(mode="k8s", reviewer=token_reviewer({AGENT_TOKEN: (AGENT_USER, pod), **(extra or {})}))


def agent_lease(admin, ticket: int, tools=None) -> str:
    """A lease as the dispatcher's claim opens it: bound to the agent's pod."""
    from tests.conftest import TOOLS, open_lease

    return open_lease(admin, ticket, tools=tools or TOOLS, bound_pod=AGENT_POD)


def from_agent(app) -> httpx2.ASGITransport:
    """A transport to the gateway app whose requests come from the agent's address."""
    return httpx2.ASGITransport(app=app, client=(AGENT_IP, 50000))


class AppGatewayClient(ToolGateway):
    """The agent's tool client (the production class) talking to the gateway app in this process."""

    def __init__(self, built: Built, auth: CallerAuth | None = None, headers: dict[str, str] | None = None):
        sent = {**AGENT_HEADERS, **(headers or {})}
        super().__init__(URL, headers=lambda: dict(sent))
        self._built, self._auth = built, auth or agent_auth()
        self.sent: list = []

    @asynccontextmanager
    async def _transport(self):
        app = build_app(self._built.gateway, self._auth)
        async with running(app):
            yield RecordingTransport(from_agent(app), self.sent)

    def wire_bodies(self) -> list[dict]:
        return [json.loads(body) for _, body in self.sent if body]
