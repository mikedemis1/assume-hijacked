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
from pathlib import Path

import httpx2
import pytest

from app.agent import main as agent_main
from app.agent.core import GIVE_UP
from app.agent.dispatcher_client import Claim, DispatcherClient, DispatcherError
from app.agent.guard import SAFE_REPLY
from app.agent.llm import Reply, ScriptedLLM, ToolCall
from app.agent.llm_client import LlmError, LlmGatewayClient
from app.dispatcher.replies import CREDIT_NOTICE, MEDICAL_QUESTION
from app.llmgw import main as llmgw_main
from app.llmgw.main import Budget, LlmGateway
from app.common.ops import Metrics
from tests.conftest import admin_connect
from tests.dispatcherharness import AGENT_IP as DISPATCHER_AGENT_IP
from tests.dispatcherharness import Harness as DispatcherHarness
from tests.gatewayharness import AppGatewayClient, agent_auth, build
from tests.test_llmgw import AGENT_IP as LLM_AGENT_IP
from tests.test_llmgw import LEASE, CountingBackend, agent_reviewer

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


def test_the_llm_client_returns_what_the_gateway_says():
    _, app = llm_stack()
    client = InMemoryLlm(app, LEASE)
    assert client.next_action(TICKET) == ToolCall("lookup_account", {})
    assert client.next_action([{"role": "ticket", "text": "SAY hello"}]) == Reply("hello")


def test_the_llm_client_sends_the_lease_in_the_header_only_and_replaces_nothing_it_is_given():
    seen = []

    async def app(scope, receive, send):
        if scope["type"] != "http":
            return
        body = b""
        while True:
            message = await receive()
            body += message.get("body", b"")
            if not message.get("more_body"):
                break
        seen.append((dict(scope["headers"]), body))
        await canned(200, {"type": "reply", "text": "ok"})(scope, receive, send)

    client = InMemoryLlm(app, LEASE, headers=lambda: {"Authorization": "Bearer projected", "X-Lease": "forged"})
    client.next_action(TICKET)
    headers, body = seen[0]
    assert headers[b"x-lease"] == LEASE.encode()                  # the lease the run was handed, not "forged"
    assert headers[b"authorization"] == b"Bearer projected"
    assert LEASE.encode() not in body and json.loads(body) == {"transcript": TICKET}


@pytest.mark.parametrize(
    "status, body, category",
    [
        (429, {"error": "budget"}, "budget"),
        (401, {"error": "unauthorized"}, "unauthorized"),
        (400, {"error": "bad_request"}, "bad_request"),
        (413, {"error": "too_large"}, "bad_request"),
        (502, {"error": "upstream"}, "unavailable"),
        (500, {"error": "x"}, "unavailable"),
        (200, {"type": "call", "name": "", "args": {}}, "bad_answer"),
        (200, {"type": "call", "name": 5, "args": {}}, "bad_answer"),
        (200, {"type": "call", "name": "lookup_account", "args": [1]}, "bad_answer"),
        (200, {"type": "reply", "text": 5}, "bad_answer"),
        (200, {"type": "other"}, "bad_answer"),
        (200, ["list"], "bad_answer"),
    ],
)
def test_an_answer_that_is_not_a_step_is_an_error_with_a_category_only(status, body, category):
    client = InMemoryLlm(canned(status, body), LEASE)
    with pytest.raises(LlmError) as err:
        client.next_action(TICKET)
    assert err.value.category == category


def test_a_gateway_that_sends_junk_or_too_much_or_nothing_is_an_error():
    for app in (canned(200, None, raw=b"not json"), canned(200, None, raw=b"x" * 2_000_000)):
        with pytest.raises(LlmError) as err:
            InMemoryLlm(app, LEASE).next_action(TICKET)
        assert err.value.category == "bad_answer"

    class Down(LlmGatewayClient):
        @asynccontextmanager
        async def _transport(self):
            yield httpx2.MockTransport(lambda request: (_ for _ in ()).throw(httpx2.ConnectError("no route")))

    with pytest.raises(LlmError) as err:
        Down("http://llm-gateway:8083", LEASE).next_action(TICKET)
    assert err.value.category == "unavailable"


def test_a_caller_the_gateway_does_not_know_is_unauthorized():
    gateway, app = llm_stack()
    with pytest.raises(LlmError) as err:
        InMemoryLlm(app, LEASE, headers=lambda: {}).next_action(TICKET)       # no token
    assert err.value.category == "unauthorized"
    assert gateway.backend.calls == 0                                # refused before the model


def test_over_budget_is_a_budget_error():
    _, app = llm_stack(limit=40)
    client = InMemoryLlm(app, LEASE)
    with pytest.raises(LlmError) as err:
        for _ in range(10):
            client.next_action(TICKET)
    assert err.value.category == "budget"


# --- the dispatcher client ---------------------------------------------------------------------------


def test_claim_returns_the_ticket_and_the_lease_or_nothing(settings, as_role):
    h = DispatcherHarness(settings, as_role)
    client = InMemoryDispatcher(h.app, headers=h.next_agent())
    claim = client.claim()
    assert claim == Claim(ticket_id=1, lease=claim.lease) and len(claim.lease) == 64
    assert InMemoryDispatcher(h.app, headers=h.next_agent()).claim().ticket_id == 2          # the control: the next pod gets a different ticket


def test_claim_with_nothing_to_do_is_none(settings, as_role, admin):
    admin.execute("UPDATE tickets SET status = 'closed'")
    h = DispatcherHarness(settings, as_role)
    assert InMemoryDispatcher(h.app, headers=h.next_agent()).claim() is None     # no Job was started, so no pod has a run


@pytest.mark.parametrize(
    "status, body, category",
    [
        (401, {"error": "unauthorized"}, "unauthorized"),
        (503, {"error": "unavailable"}, "unavailable"),
        (500, {}, "unavailable"),
        (200, {"ticket_id": "1", "lease": "ab" * 32}, "bad_answer"),
        (200, {"ticket_id": 0, "lease": "ab" * 32}, "bad_answer"),
        (200, {"ticket_id": 1, "lease": "short"}, "bad_answer"),
        (200, {"ticket_id": 1}, "bad_answer"),
        (200, {"ticket_id": True, "lease": "ab" * 32}, "bad_answer"),
    ],
)
def test_a_claim_answer_that_is_not_a_ticket_and_a_lease_is_an_error(status, body, category):
    with pytest.raises(DispatcherError) as err:
        InMemoryDispatcher(canned(status, body)).claim()
    assert err.value.category == category


@pytest.mark.parametrize(
    "status, body, category",
    [(403, {"error": "lease"}, "lease"), (409, {"error": "already_replied"}, "duplicate"),
     (400, {"error": "bad_request"}, "bad_request"), (413, {"error": "too_large"}, "bad_request"),
     (401, {}, "unauthorized"), (503, {}, "unavailable"), (200, {"stored": False}, "bad_answer"), (200, {}, "bad_answer")],
)
def test_a_reply_that_is_not_stored_is_an_error(status, body, category):
    with pytest.raises(DispatcherError) as err:
        InMemoryDispatcher(canned(status, body)).reply("ab" * 32, "Thank you.")
    assert err.value.category == category


def test_the_reply_goes_with_the_lease_in_the_header_and_only_the_text_in_the_body(settings, as_role, admin):
    h = DispatcherHarness(settings, as_role)
    client = InMemoryDispatcher(h.app, headers=h.next_agent())
    claim = client.claim()
    client.reply(claim.lease, "Thank you.")
    assert admin.execute("SELECT ticket_id, text FROM replies").fetchall() == [{"ticket_id": 1, "text": "Thank you."}]
    with pytest.raises(DispatcherError) as err:                      # the lease has ended with the reply
        client.reply(claim.lease, "Again.")
    assert err.value.category == "lease"


# --- the run -------------------------------------------------------------------------------------------


class SpyDispatcher:
    def __init__(self, claim=None, claim_error=None, reply_error=None):
        self._claim, self._claim_error, self._reply_error = claim, claim_error, reply_error
        self.claims, self.replies = 0, []

    def claim(self):
        self.claims += 1
        if self._claim_error:
            raise self._claim_error
        return self._claim

    def reply(self, lease, text):
        self.replies.append((lease, text))
        if self._reply_error:
            raise self._reply_error


class SpyTools:
    def __init__(self):
        self.calls = []

    def call(self, name, args):
        self.calls.append((name, dict(args)))
        if name == "read_ticket":
            return json.dumps({"ticket_id": 7, "body": "SAY Thanks"})
        return "{}"


def events(caplog):
    return [json.loads(r.getMessage()) for r in caplog.records if r.name == EVENTS]


def test_a_run_with_nothing_to_claim_ends_quietly_and_builds_no_model_client(caplog):
    built = []
    spy = SpyDispatcher(claim=None)
    with caplog.at_level(logging.INFO, logger=EVENTS):
        code = agent_main.run(spy, lambda lease: built.append(lease) or ScriptedLLM(), SpyTools())
    assert code == 0 and built == [] and spy.replies == []
    assert [e["kind"] for e in events(caplog)] == ["no_ticket"]


def test_a_run_claims_works_and_replies_once_under_the_lease_it_was_handed(caplog):
    spy, tools, leases = SpyDispatcher(claim=Claim(7, LEASE)), SpyTools(), []
    with caplog.at_level(logging.INFO, logger=EVENTS):
        code = agent_main.run(spy, lambda lease: leases.append(lease) or ScriptedLLM(), tools)
    assert code == 0 and leases == [LEASE]
    assert spy.replies == [(LEASE, "Thanks")]                         # the text, no notice, under the claimed lease
    assert tools.calls == [("read_ticket", {"lease": LEASE})]
    assert [e["kind"] for e in events(caplog)] == ["reply_sent"]
    assert LEASE not in caplog.text


@pytest.mark.parametrize("category", ["unauthorized", "unavailable", "bad_answer"])
def test_a_claim_that_fails_ends_the_run_with_a_code_and_a_category(caplog, category):
    spy = SpyDispatcher(claim_error=DispatcherError(category))
    with caplog.at_level(logging.INFO, logger=EVENTS):
        assert agent_main.run(spy, lambda lease: ScriptedLLM(), SpyTools()) == 1
    (event,) = events(caplog)
    assert (event["kind"], event["category"]) == ("claim_failed", category)


def test_a_reply_that_is_refused_is_a_failed_run(caplog):
    spy = SpyDispatcher(claim=Claim(7, LEASE), reply_error=DispatcherError("lease"))
    with caplog.at_level(logging.INFO, logger=EVENTS):
        assert agent_main.run(spy, lambda lease: ScriptedLLM(), SpyTools()) == 1
    (event,) = events(caplog)
    assert (event["kind"], event["category"], event["ticket_id"]) == ("reply_failed", "lease", 7)
    assert LEASE not in caplog.text


def test_the_run_takes_no_ticket_number_from_anyone():
    import inspect

    assert list(inspect.signature(agent_main.run).parameters) == ["dispatcher", "llm_for", "tools"]


def test_the_process_refuses_a_ticket_number_on_its_command_line(monkeypatch):
    monkeypatch.setattr("sys.argv", ["main", "1"])
    with pytest.raises(SystemExit, match="ticket"):
        agent_main.main()


@pytest.mark.parametrize("missing", ["GATEWAY_URL", "LLM_GATEWAY_URL", "DISPATCHER_URL"])
def test_the_process_does_not_start_without_an_address_it_needs(monkeypatch, missing):
    monkeypatch.setattr("sys.argv", ["main"])
    for name in ("GATEWAY_URL", "LLM_GATEWAY_URL", "DISPATCHER_URL"):
        monkeypatch.setenv(name, "http://x.test")
    monkeypatch.delenv(missing)
    with pytest.raises(SystemExit, match=missing):
        agent_main.main()


def test_the_process_does_not_take_a_lease_from_its_environment(monkeypatch):
    # The lease comes from the claim; a leftover AGENT_LEASE is not read.
    source = Path(agent_main.__file__).read_text(encoding="utf-8")
    assert "AGENT_LEASE" not in source and "argv[1]" not in source


def test_main_sends_security_events_to_stderr_and_nothing_to_stdout(monkeypatch, capsys):
    from app.agent.events import LOGGER

    for handler in list(LOGGER.handlers):
        LOGGER.removeHandler(handler)
    monkeypatch.setattr("sys.argv", ["main"])
    for name in ("GATEWAY_URL", "LLM_GATEWAY_URL", "DISPATCHER_URL"):
        monkeypatch.setenv(name, "http://x.test")
    monkeypatch.setattr(agent_main.config, "load", lambda: type("S", (), {"caller_auth": "k8s"})())
    monkeypatch.setattr(agent_main, "DispatcherClient", lambda url, headers=None: SpyDispatcher(claim=Claim(7, LEASE)))
    monkeypatch.setattr(agent_main, "ToolGateway", lambda url, headers=None: SpyTools())
    monkeypatch.setattr(agent_main, "LlmGatewayClient", lambda url, lease, headers=None: ScriptedLLM())
    try:
        with pytest.raises(SystemExit) as done:
            agent_main.main()
        assert done.value.code == 0
        out = capsys.readouterr()
        assert '"kind": "reply_sent"' in out.err
        assert out.out == ""                                         # the reply is the dispatcher's business, not the log's
    finally:
        for handler in list(LOGGER.handlers):
            LOGGER.removeHandler(handler)
        LOGGER.propagate = True


def test_the_headers_for_each_peer_name_that_peers_audience(monkeypatch, tmp_path):
    # Kubernetes: three projected tokens, one per audience; each client sends only its own.
    for audience in ("tool-gateway", "llm-gateway", "dispatcher"):
        (tmp_path / audience).mkdir()
        (tmp_path / audience / "token").write_text(f"token-for-{audience}", encoding="utf-8")
    from app.common import calls

    seen = {}
    monkeypatch.setattr("sys.argv", ["main"])
    for name in ("GATEWAY_URL", "LLM_GATEWAY_URL", "DISPATCHER_URL"):
        monkeypatch.setenv(name, "http://x.test")
    monkeypatch.setattr(agent_main.config, "load", lambda: type("S", (), {"caller_auth": "k8s"})())
    monkeypatch.setattr(calls, "TOKEN_DIR", tmp_path)
    monkeypatch.setattr(agent_main, "auth_headers", lambda audience, mode: calls.auth_headers(audience, mode, tmp_path))
    monkeypatch.setattr(agent_main, "DispatcherClient", lambda url, headers=None: seen.setdefault("dispatcher", headers()) and SpyDispatcher())
    monkeypatch.setattr(agent_main, "ToolGateway", lambda url, headers=None: seen.setdefault("tools", headers()) and SpyTools())
    monkeypatch.setattr(agent_main, "LlmGatewayClient", lambda url, lease, headers=None: ScriptedLLM())
    with pytest.raises(SystemExit):
        agent_main.main()
    assert seen == {"dispatcher": {"Authorization": "Bearer token-for-dispatcher"},
                    "tools": {"Authorization": "Bearer token-for-tool-gateway"}}


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


def test_agent_end_to_end_in_memory(settings, as_role, admin):
    stack = Stack(settings, as_role)
    assert stack.run() == 0
    reply = stored(settings, 1)
    assert "Eleni Papadopoulou" in reply and reply == stored(settings, 1)
    assert SAFE_REPLY not in reply and CREDIT_NOTICE not in reply and MEDICAL_QUESTION not in reply
    # The run is finished: replied, the lease has ended, and the two calls are on the record.
    runs = admin.execute("SELECT ticket_id, status FROM agent_runs ORDER BY ticket_id").fetchall()
    assert runs[0] == {"ticket_id": 1, "status": "replied"}           # the other Jobs the dispatcher started are not claimed
    assert {r["status"] for r in runs[1:]} == {"started"}
    assert admin.execute("SELECT count(*) AS n FROM leases WHERE NOT revoked").fetchone()["n"] == 0
    assert [r["tool"] for r in admin.execute("SELECT tool FROM tool_calls ORDER BY id")] == ["read_ticket", "lookup_account"]
    # Every step really went through the LLM gateway: the model was asked twice (call, then reply).
    assert stack.llm_gateway.backend.calls == 2
    # The next run is the next ticket's; ticket 1's reply is not touched.
    assert stack.run() == 0 and stored(settings, 1) == reply and stored(settings, 2) is not None


def test_the_attack_ticket_in_memory_leaks_nothing_and_is_logged(settings, as_role, admin, caplog):
    only_ticket(admin, 4)                                            # ticket 4 asks for customer 1002 with a customer_id
    stack = Stack(settings, as_role)
    with caplog.at_level(logging.INFO, logger=EVENTS):
        assert stack.run() == 0
    reply = stored(settings, 4)
    assert "Eleni Papadopoulou" in reply and "Nikos" not in reply
    kinds = {e["kind"]: e for e in events(caplog)}
    assert "customer_id" in kinds["dropped_argument"]["args"]


def test_credit_and_move_out_notices_come_once_from_the_dispatcher(settings, as_role, admin):
    admin.execute(
        "INSERT INTO tickets (id, customer_id, body) VALUES (50, 1001, %s)",
        ('CALL issue_bill_credit {"amount_eur": 49, "reason": "duplicate_charge", "evidence_ref": 2}\n'
         'CALL request_disconnection {"move_out_date": "2030-01-01"}\nSAY Thank you for your message.',),
    )
    only_ticket(admin, 50)
    assert Stack(settings, as_role).run() == 0
    reply = stored(settings, 50)
    assert reply == f"Thank you for your message.\n\n{CREDIT_NOTICE}\n\n{MEDICAL_QUESTION}"
    assert reply.count(CREDIT_NOTICE) == 1 and SAFE_REPLY not in reply


def test_a_hijacked_reply_is_replaced_by_the_agent_and_still_carries_the_notices_once(settings, as_role, admin):
    admin.execute(
        "INSERT INTO tickets (id, customer_id, body) VALUES (51, 1001, %s)",
        ('CALL issue_bill_credit {"amount_eur": 49, "reason": "duplicate_charge", "evidence_ref": 2}\n'
         "SAY Done! We credited €49 to your account.",),
    )
    only_ticket(admin, 51)
    assert Stack(settings, as_role).run() == 0
    assert stored(settings, 51) == f"{SAFE_REPLY}\n\n{CREDIT_NOTICE}"


def test_a_model_over_its_budget_ends_the_run_with_the_give_up_text_and_no_tool_beyond_the_ticket(settings, as_role, admin):
    stack = Stack(settings, as_role, limit=1)                        # the first request does not even fit
    assert stack.run() == 0
    assert stored(settings, 1) == GIVE_UP
    assert [r["tool"] for r in admin.execute("SELECT tool FROM tool_calls ORDER BY id")] == ["read_ticket"]
    assert stack.llm_gateway.backend.calls == 0


def test_a_model_that_cannot_be_reached_ends_the_run_with_the_give_up_text(settings, as_role, admin):
    class Broken:
        async def next(self, transcript):
            raise OSError("provider down")

    stack = Stack(settings, as_role, backend=Broken())
    assert stack.run() == 0
    assert stored(settings, 1) == GIVE_UP


def test_the_agent_gets_its_lease_from_the_claim_and_no_model_key_anywhere(settings, as_role):
    stack = Stack(settings, as_role)
    sent = []

    class Watching(InMemoryLlm):
        async def _post(self, transcript):
            sent.append(self._lease)
            return await super()._post(transcript)

    agent_main.run(
        InMemoryDispatcher(stack.dispatcher.app, headers=stack.dispatcher.next_agent()),
        lambda lease: Watching(stack.llm_app, lease),
        stack.tool_gateway,
    )
    assert len(sent) == 2 and len(set(sent)) == 1 and len(sent[0]) == 64   # one lease, from the claim
    text = "\n".join(p.read_text(encoding="utf-8") for p in (Path(agent_main.__file__).parent).glob("*.py"))
    assert "x-api-key" not in text.lower() and "ANTHROPIC" not in text and "FOUNDRY" not in text


@pytest.fixture(autouse=True)
def nothing_left_over(fresh_db, admin):
    """The claim tests name ticket numbers, so they start from no runs, replies or leases at all."""
    for table in ("agent_runs", "replies", "leases"):
        assert admin.execute(f"SELECT count(*) AS n FROM {table}").fetchone()["n"] == 0, table
