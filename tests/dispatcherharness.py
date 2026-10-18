"""The dispatcher built for tests: the real HTTP app with the real caller check, the real database
role and the real store. Only the edges are replaced: the network by an ASGI transport that sets the
source address, the TokenReview by a function, the Kubernetes API by a recording fake.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx2

from app.agent import templates
from app.common.ops import Metrics
from app.common.tokenreview import Review
from app.dispatcher import main as dispatcher_main
from app.dispatcher.main import Dispatcher, build_app, init_metrics
from app.dispatcher.store import DispatcherDb

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE_FILE = ROOT / "tests" / "fixtures" / "agent-job-template.json"
# The subnet of the agent's edge to the dispatcher (compose.yaml) and an address in it.
AGENT_SUBNET = "10.250.2.0/24"
AGENT_IP = "10.250.2.5"
TOOL_IP = "10.250.9.7"  # a tool's address on its own edge: not the agent's network
EVENTS = "assume_hijacked.security"


# --- the harness ---------------------------------------------------------------------------------


def request(app, method, path, *, headers=None, content=None, ip=AGENT_IP):
    """One request to the app as if it came from `ip` (None: no peer address at all)."""

    async def go():
        client = None if ip is None else (ip, 50000)
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app, client=client), base_url="http://dispatcher.test"
        ) as http:
            return await http.request(method, path, headers=headers, content=content)

    return asyncio.run(go())


def post(app, path, *, lease=None, body=None, headers=None, ip=AGENT_IP, content=None):
    sent = dict(headers or {})
    if lease is not None:
        sent["X-Lease"] = lease
    if content is None and body is not None:
        content = json.dumps(body)
    return request(app, "POST", path, headers=sent, content=content, ip=ip)


class CountingStore(DispatcherDb):
    """The real store, counting how often it was used: a refused request must leave it at 0."""

    def __init__(self, connect):
        super().__init__(connect)
        self.used = 0

    def _use(self, work):
        self.used += 1
        return super()._use(work)


class Harness:
    def __init__(self, settings, as_role, *, mode="compose", reviewer=None, api=None, max_active=3, template=None):
        self.metrics = Metrics()
        init_metrics(self.metrics)
        self.store = CountingStore(lambda: as_role("dispatcher"))
        self.api = api
        self.dispatcher = Dispatcher(
            self.store,
            mode,
            self.metrics,
            template=template if template is not None else (templates.load_template(TEMPLATE_FILE) if mode == "k8s" else None),
            api=api,
            max_active=max_active,
        )
        # The same function the process uses, so a wrong audience or subnet there is caught here.
        auth = dispatcher_main.caller_auth(mode, AGENT_SUBNET if mode == "compose" else None, reviewer)
        self.app = build_app(self.dispatcher, auth, self.metrics)


def reviewer_for(tokens):
    """A TokenReview stand-in: token -> (service account user, pod name) or nothing."""

    def review(token, audience):
        assert audience == "dispatcher"
        found = tokens.get(token)
        return None if found is None else Review(username=found[0], pod=found[1])

    return review
