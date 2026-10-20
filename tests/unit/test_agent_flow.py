"""The agent's whole run: claim a ticket, work on it through the LLM gateway and the tool gateway,
send the reply to the dispatcher, exit.

The clients are the production classes; only the network is replaced, by an ASGI transport to the
real dispatcher, tool gateway (with the real tools) and LLM gateway, all in this process. A lease the
dispatcher did not hand out is never used here, so every wall on the path is the real one.
"""

from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager

import httpx2
import pytest

from app.agent import main as agent_main
from app.agent.dispatcher_client import DispatcherClient
from app.agent.llm_client import LlmGatewayClient
from app.llmgw import main as llmgw_main
from app.llmgw.main import Budget, LlmGateway
from app.common.ops import Metrics
from tests.conftest import admin_connect
from tests.dispatcherharness import AGENT_IP as DISPATCHER_AGENT_IP
from tests.dispatcherharness import Harness as DispatcherHarness
from tests.gatewayharness import AppGatewayClient, agent_auth, build
from tests.unit.test_llmgw import AGENT_IP as LLM_AGENT_IP
from tests.unit.test_llmgw import CountingBackend, agent_reviewer

EVENTS = "assume_hijacked.security"


# --- the agent's clients, with the network replaced -------------------------------------------------


class InMemoryDispatcher(DispatcherClient):
    def __init__(self, app, headers=None, ip=DISPATCHER_AGENT_IP):
        super().__init__("http://dispatcher:8081", headers=headers)
        self._app, self._ip = app, ip

    @asynccontextmanager
    async def _transport(self):
        yield httpx2.ASGITransport(app=self._app, client=(self._ip, 50000))


class InMemoryLlm(LlmGatewayClient):
    def __init__(self, app, lease, headers=lambda: {"Authorization": "Bearer llm-token"}, ip=LLM_AGENT_IP):
        super().__init__("http://llm-gateway:8083", lease, headers=headers)
        self._app, self._ip = app, ip

    @asynccontextmanager
    async def _transport(self):
        yield httpx2.ASGITransport(app=self._app, client=(self._ip, 50000))


def canned(status, body, raw=None):
    """An ASGI app that answers every request with one fixed response."""

    async def app(scope, receive, send):
        if scope["type"] != "http":
            return
        data = raw if raw is not None else json.dumps(body).encode()
        await send({"type": "http.response.start", "status": status, "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body", "body": data})

    return app


def llm_stack(backend=None, limit=20000):
    metrics = Metrics()
    llmgw_main.init_metrics(metrics)
    gateway = LlmGateway(backend or CountingBackend(), Budget(limit), metrics)
    app = llmgw_main.build_app(gateway, llmgw_main.caller_auth("k8s", agent_reviewer), metrics)
    return gateway, app


# --- the LLM client ---------------------------------------------------------------------------------

TICKET = [{"role": "ticket", "text": "CALL lookup_account {}\nSAY done"}]


# --- the run -------------------------------------------------------------------------------------------


def events(caplog):
    return [json.loads(r.getMessage()) for r in caplog.records if r.name == EVENTS]


def test_the_process_refuses_a_ticket_number_on_its_command_line(monkeypatch):
    monkeypatch.setattr("sys.argv", ["main", "1"])
    with pytest.raises(SystemExit, match="ticket"):
        agent_main.main()


# --- the whole thing in memory ----------------------------------------------------------------------------


class Stack:
    """Dispatcher + tool gateway + tools + LLM gateway, all real, in this process."""

    def __init__(self, settings, as_role, *, backend=None, limit=20000):
        self.settings = settings
        self.dispatcher = DispatcherHarness(settings, as_role)
        self.tool_gateway = AppGatewayClient(build(self.settings, as_role), agent_auth(pod=lambda: self.dispatcher.last_pod))
        self.llm_gateway, self.llm_app = llm_stack(backend, limit)

    def run(self):
        return agent_main.run(
            InMemoryDispatcher(self.dispatcher.app, headers=self.dispatcher.next_agent()),
            lambda lease: InMemoryLlm(self.llm_app, lease),
            self.tool_gateway,
        )


def only_ticket(admin, ticket):
    admin.execute("UPDATE tickets SET status = 'closed' WHERE id <> %s", (ticket,))


def stored(settings, ticket):
    with admin_connect(settings) as conn:
        row = conn.execute("SELECT text FROM replies WHERE ticket_id = %s", (ticket,)).fetchone()
    return None if row is None else row["text"]


def test_the_attack_ticket_in_memory_leaks_nothing_and_is_logged(settings, as_role, admin, caplog):
    only_ticket(admin, 4)                                            # ticket 4 asks for customer 1002 with a customer_id
    stack = Stack(settings, as_role)
    with caplog.at_level(logging.INFO, logger=EVENTS):
        assert stack.run() == 0
    reply = stored(settings, 4)
    assert "Eleni Papadopoulou" in reply and "Nikos" not in reply
    kinds = {e["kind"]: e for e in events(caplog)}
    assert "customer_id" in kinds["dropped_argument"]["args"]


def test_the_attack_ticket_leaves_an_agent_event_with_names_only(settings, as_role, admin):
    only_ticket(admin, 4)                                            # ticket 4 sets customer_id, the agent drops it
    stack = Stack(settings, as_role)
    assert stack.run() == 0
    rows = admin.execute("SELECT ticket_id, kind, tool, arg_names, source FROM agent_events").fetchall()
    assert rows == [{"ticket_id": 4, "kind": "dropped_argument", "tool": "lookup_account",
                     "arg_names": ["customer_id"], "source": "agent"}]
    assert "1002" not in json.dumps(admin.execute("SELECT * FROM agent_events").fetchall(), default=str)


@pytest.fixture(autouse=True)
def nothing_left_over(fresh_db, admin):
    """The claim tests name ticket numbers, so they start from no runs, replies or leases at all."""
    for table in ("agent_runs", "replies", "leases"):
        assert admin.execute(f"SELECT count(*) AS n FROM {table}").fetchone()["n"] == 0, table
