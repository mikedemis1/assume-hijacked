"""The risk service (app/risk/service.py): POST /decide for every tool call, and the loop that
assesses every pending effect request. Plus the database objects it brings (db/sql/06-risk.sql):
heartbeats and beat(), risk_lease_facts, blocked_calls_on_ticket, home_protection, and the one
allowed effect call per lease.

The rules themselves are pure and tested in tests/test_risk_rules.py. Here: that the service
gathers the right facts from the database, writes what it decided, and fails closed.
"""

import dataclasses
import hashlib
import json
import logging
import time
from datetime import timedelta

import psycopg
import pytest
from starlette.testclient import TestClient

from app.common.ops import Heartbeat, Metrics
from app.risk import main as risk_main
from app.risk import service
from app.risk.rules import ENGINE_VERSION, CallFacts
from tests.conftest import TOOLS, open_lease
from tests.test_executor_credits import add_credit, give_account_2_a_duplicate
from tests.test_executor_moveouts import add_moveout

ANNA = "eeab6c5e-f5bc-5d16-af4b-813d9b88be01"


@pytest.fixture
def engine(as_role):
    """One risk_engine connection per test (CONNECTION LIMIT 5; the stack's engine holds two)."""
    return as_role("risk_engine")


def lease_hash(lease):
    return hashlib.sha256(lease.encode()).digest()


def calls(admin):
    return admin.execute(
        "SELECT lease_hash, tool, decision, reasons, actor FROM call_assessments ORDER BY id"
    ).fetchall()


def control(admin):
    return admin.execute("SELECT paused, reason FROM agent_control").fetchone()


def lines(metrics):
    return metrics.render().splitlines()


# --- POST /decide: the judgement on one tool call ---

def test_decide_allows_first_read_and_denies_second_effect(admin, engine):
    lease = open_lease(admin, 1)
    assert service.decide(engine, lease, "read_ticket") == ("allow", ())
    assert service.decide(engine, lease, "issue_bill_credit") == ("allow", ())
    # One effect per ticket: the second effect call on the lease is denied, whichever tool it is.
    assert service.decide(engine, lease, "request_disconnection") == ("deny", ("one_effect_per_ticket",))
    assert service.decide(engine, lease, "issue_bill_credit") == ("deny", ("one_effect_per_ticket",))
    rows = calls(admin)
    assert [(r["tool"], r["decision"], r["reasons"]) for r in rows] == [
        ("read_ticket", "allow", []),
        ("issue_bill_credit", "allow", []),
        ("request_disconnection", "deny", ["one_effect_per_ticket"]),
        ("issue_bill_credit", "deny", ["one_effect_per_ticket"]),
    ]
    # The database keeps sha256(lease), never the lease, and the engine as actor.
    assert {bytes(r["lease_hash"]) for r in rows} == {lease_hash(lease)}
    assert {r["actor"] for r in rows} == {"risk_engine"}


def test_effect_on_another_lease_is_still_allowed(admin, engine):
    # Control for the test above: the effect budget is per lease, not global.
    first, second = open_lease(admin, 1), open_lease(admin, 2)
    assert service.decide(engine, first, "issue_bill_credit") == ("allow", ())
    assert service.decide(engine, second, "issue_bill_credit") == ("allow", ())


def test_decide_pauses_after_three_denials(admin, engine):
    lease = open_lease(admin, 1, tools=["read_ticket"])
    for _ in range(3):
        assert service.decide(engine, lease, "issue_bill_credit") == ("deny", ("tool_not_in_lease",))
    assert control(admin) == {"paused": False, "reason": ""}
    assert service.decide(engine, lease, "read_ticket") == ("pause", ("repeated_denials",))
    assert control(admin) == {"paused": True, "reason": "repeated_denials"}
    paused = admin.execute("SELECT kind, actor FROM events WHERE kind = 'agents_paused'").fetchall()
    assert paused == [{"kind": "agents_paused", "actor": "risk_engine"}]
    # Every agent is stopped now, on any lease.
    other = open_lease(admin, 2)
    assert service.decide(engine, other, "read_ticket") == ("deny", ("paused",))


def test_two_denials_do_not_pause(admin, engine):
    # Control: one denial short of the limit, the next good call is allowed.
    lease = open_lease(admin, 1, tools=["read_ticket"])
    for _ in range(2):
        service.decide(engine, lease, "issue_bill_credit")
    assert service.decide(engine, lease, "read_ticket") == ("allow", ())
    assert control(admin)["paused"] is False


def test_denials_while_paused_do_not_count_against_the_lease(admin, as_role, engine):
    # A call denied because every agent was stopped says nothing about this run. Once a person
    # resumes, the lease is judged on its own denials only.
    lease = open_lease(admin, 1)
    as_role("risk_engine").execute("SELECT pause_agents('test')")
    for _ in range(4):
        assert service.decide(engine, lease, "read_ticket") == ("deny", ("paused",))
    as_role("approver").execute("SELECT resume_agents()")
    assert service.decide(engine, lease, "read_ticket") == ("allow", ())


@pytest.mark.parametrize("state", ["unknown", "expired", "revoked"])
def test_decide_denies_a_lease_that_is_not_live(admin, engine, state):
    lease = "f" * 64 if state == "unknown" else open_lease(admin, 1)
    if state == "expired":
        admin.execute("UPDATE leases SET expires_at = now() - interval '1 second'")
    if state == "revoked":
        admin.execute("SELECT revoke_lease(%s)", (lease,))
    assert service.decide(engine, lease, "read_ticket") == ("deny", ("lease",))


def test_decide_denies_a_tool_not_in_the_lease(admin, engine):
    lease = open_lease(admin, 1, tools=["read_ticket", "lookup_account"])
    assert service.decide(engine, lease, "issue_bill_credit") == ("deny", ("tool_not_in_lease",))
    assert service.decide(engine, lease, "lookup_account") == ("allow", ())  # control


def test_decide_denies_after_the_call_budget(admin, engine):
    lease = open_lease(admin, 1)
    for _ in range(8):
        assert service.decide(engine, lease, "read_ticket") == ("allow", ())
    assert service.decide(engine, lease, "read_ticket") == ("deny", ("call_budget",))


def test_a_missing_stop_switch_counts_as_paused(admin, engine):
    lease = open_lease(admin, 1)
    admin.execute("DELETE FROM agent_control")
    assert service.decide(engine, lease, "read_ticket") == ("deny", ("paused",))


def test_decide_counts_decisions_by_category(admin, engine):
    lease = open_lease(admin, 1, tools=["read_ticket"])
    metrics = Metrics()
    service.decide(engine, lease, "read_ticket", metrics)
    service.decide(engine, lease, "issue_bill_credit", metrics)
    out = lines(metrics)
    assert 'risk_decisions_total{decision="allow"} 1' in out
    assert 'risk_decisions_total{decision="deny"} 1' in out
    assert lease not in metrics.render()


def test_one_allowed_effect_per_lease_is_a_database_rule(admin, engine):
    # Two decisions racing on one lease (a second engine replica, say) could both read "no effect
    # yet". The partial unique index lets only one allowed effect row in.
    statement = "INSERT INTO call_assessments (lease_hash, tool, decision, reasons) VALUES (%s, %s, %s, '{}')"
    h = lease_hash("race")
    engine.execute(statement, (h, "issue_bill_credit", "allow"))
    with pytest.raises(psycopg.errors.UniqueViolation):
        engine.execute(statement, (h, "request_disconnection", "allow"))
    # Controls: denials, reads and another lease's effect are not limited by it.
    engine.execute(statement, (h, "issue_bill_credit", "deny"))
    engine.execute(statement, (h, "read_ticket", "allow"))
    engine.execute(statement, (h, "read_ticket", "allow"))
    engine.execute(statement, (lease_hash("other"), "issue_bill_credit", "allow"))


def test_decide_retries_when_a_concurrent_effect_won(admin, engine, monkeypatch):
    lease = open_lease(admin, 1)
    assert service.decide(engine, lease, "issue_bill_credit") == ("allow", ())
    real = service.call_facts
    stale = []

    def first_stale(conn, h, tool):
        facts = real(conn, h, tool)
        if not stale:  # the first read misses the effect another decision just wrote
            stale.append(True)
            return dataclasses.replace(facts, effect_calls_on_lease=0)
        return facts

    monkeypatch.setattr(service, "call_facts", first_stale)
    assert service.decide(engine, lease, "request_disconnection") == ("deny", ("one_effect_per_ticket",))
    allowed = [r for r in calls(admin) if r["decision"] == "allow"]
    assert len(allowed) == 1


def test_call_facts_reads_the_lease_through_its_function(admin, engine):
    lease = open_lease(admin, 1, tools=["read_ticket"])
    facts = service.call_facts(engine, lease_hash(lease), "read_ticket")
    assert facts == CallFacts(
        tool="read_ticket", lease_live=True, tool_in_lease=True, paused=False,
        calls_on_lease=0, effect_calls_on_lease=0, denied_on_lease=0,
    )


# --- the HTTP edge ---

class FakeDecider:
    def __init__(self, result=("allow", ()), error=None):
        self.result, self.error, self.seen = result, error, []

    def decide(self, lease, tool):
        self.seen.append((lease, tool))
        if self.error:
            raise self.error
        return self.result


def post(decider, body, **kwargs):
    client = TestClient(service.build_app(decider))
    if isinstance(body, (dict, list)):
        return client.post("/decide", json=body, **kwargs)
    return client.post("/decide", content=body, **kwargs)


def test_decide_endpoint_answers_with_the_decision(admin, settings):
    lease = open_lease(admin, 1)
    decider = service.Decider(lambda: service.connect(settings), Metrics())
    try:
        response = post(decider, {"lease": lease, "tool": "read_ticket"})
    finally:
        decider.close()
    assert response.status_code == 200
    assert response.json() == {"decision": "allow", "reasons": []}


BAD_BODIES = {
    "not json": b"{lease",
    "a list": ["x"],
    "no lease": {"tool": "read_ticket"},
    "no tool": {"lease": "a" * 64},
    "lease not a string": {"lease": 5, "tool": "read_ticket"},
    "tool not a string": {"lease": "a" * 64, "tool": ["read_ticket"]},
    "lease too long": {"lease": "a" * 257, "tool": "read_ticket"},
    "empty lease": {"lease": "", "tool": "read_ticket"},
    "tool with odd characters": {"lease": "a" * 64, "tool": "read_ticket; drop"},
    "body too large": b'{"lease": "' + b"a" * 5000 + b'", "tool": "read_ticket"}',
}


@pytest.mark.parametrize("case", BAD_BODIES)
def test_decide_endpoint_denies_a_bad_body(case):
    decider = FakeDecider()
    response = post(decider, BAD_BODIES[case])
    assert response.status_code in (400, 413)
    assert response.json() == {"decision": "deny", "reasons": ["bad_request"]}
    assert decider.seen == []


def test_decide_endpoint_fails_closed_when_the_database_fails(caplog):
    lease = "b" * 64
    decider = FakeDecider(error=psycopg.OperationalError(f"server closed the connection {lease}"))
    with caplog.at_level(logging.DEBUG):
        response = post(decider, {"lease": lease, "tool": "read_ticket"})
    assert response.status_code == 503
    assert response.json() == {"decision": "deny", "reasons": ["risk_unavailable"]}
    # The log names the error class only: never the lease, never the message that may carry it.
    assert lease not in caplog.text
    assert "OperationalError" in caplog.text


def test_decide_endpoint_only_takes_post():
    client = TestClient(service.build_app(FakeDecider()))
    assert client.get("/decide").status_code == 405
    assert client.post("/other", json={}).status_code == 404


def test_decider_reconnects_after_a_lost_connection(admin, settings):
    lease = open_lease(admin, 1)
    opened = []

    def connect():
        conn = service.connect(settings)
        opened.append(conn)
        return conn

    decider = service.Decider(connect, Metrics())
    try:
        assert decider.decide(lease, "read_ticket")[0] == "allow"
        # The server drops the connection (a database restart, say).
        admin.execute("SELECT pg_terminate_backend(%s)", (opened[0].info.backend_pid,))
        with pytest.raises(psycopg.OperationalError):
            decider.decide(lease, "read_ticket")
        assert decider.decide(lease, "read_ticket")[0] == "allow"
    finally:
        decider.close()
    assert len(opened) == 2


# --- /decide is bounded: a body, a connection and a statement each have a limit ---

async def raw_decide(headers, chunks):
    """POST /decide straight to the app with the given header lines and body chunks. Returns the
    status, the answer and how many chunks the app asked for."""
    asked, sent = [0], {}
    queue = list(chunks)

    async def receive():
        asked[0] += 1
        body = queue.pop(0) if queue else b""
        return {"type": "http.request", "body": body, "more_body": bool(queue)}

    async def send(message):
        if message["type"] == "http.response.start":
            sent["status"] = message["status"]
        elif message["type"] == "http.response.body":
            sent["body"] = sent.get("body", b"") + message.get("body", b"")

    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST", "path": "/decide",
        "raw_path": b"/decide", "query_string": b"", "scheme": "http", "server": ("risk", 8082),
        "client": ("1.2.3.4", 1), "headers": [(b"host", b"risk"), *headers],
    }
    await service.build_app(FakeDecider())(scope, receive, send)
    return sent["status"], sent["body"], asked[0]


def test_decide_refuses_a_declared_body_over_the_cap_with_413_without_reading_it():
    import asyncio

    status, body, asked = asyncio.run(raw_decide([(b"content-length", b"10000000")], [b"x" * 100]))
    assert status == 413
    assert json.loads(body) == {"decision": "deny", "reasons": ["bad_request"]}
    assert asked == 0                                  # not one byte of the body was taken in
    # The control: a declared length at the cap is read and judged on its content.
    ok = json.dumps({"lease": "a" * 64, "tool": "read_ticket"}).encode()
    status, body, asked = asyncio.run(raw_decide([(b"content-length", str(len(ok)).encode())], [ok]))
    assert status == 200 and json.loads(body)["decision"] == "allow" and asked >= 1


def test_decide_stops_reading_a_body_with_no_length_once_it_passes_the_cap():
    import asyncio

    chunks = [b"x" * 600 for _ in range(50)]          # chunked: no content-length header
    status, body, asked = asyncio.run(raw_decide([], chunks))
    assert status == 413 and json.loads(body)["reasons"] == ["bad_request"]
    assert asked <= 3                                  # 600 + 600 passes 1024; it did not read 50 chunks


def test_decide_refuses_a_content_length_that_is_not_a_number():
    import asyncio

    status, _, asked = asyncio.run(raw_decide([(b"content-length", b"lots")], [b"{}"]))
    assert status == 400 and asked == 0


def test_the_connection_decide_uses_has_a_connect_timeout_and_a_statement_timeout(settings):
    conn = service.connect_for_decide(settings)
    try:
        assert conn.info.get_parameters()["connect_timeout"] == "2"
        assert conn.execute("SHOW statement_timeout").fetchone()["statement_timeout"] == "1500ms"
        started = time.monotonic()
        with pytest.raises(psycopg.errors.QueryCanceled):
            conn.execute("SELECT pg_sleep(10)")
        assert time.monotonic() - started < 4
    finally:
        conn.close()
    # The effect loop's connection is not cut short: it does batches of work.
    loop = service.connect(settings)
    try:
        assert loop.execute("SHOW statement_timeout").fetchone()["statement_timeout"] == "0"
    finally:
        loop.close()


def test_decide_answers_deny_when_a_statement_runs_too_long(admin, settings, monkeypatch):
    lease = open_lease(admin, 1)
    real = service.call_facts

    def slow(conn, h, tool):
        conn.execute("SELECT pg_sleep(10)")
        return real(conn, h, tool)

    monkeypatch.setattr(service, "call_facts", slow)
    decider = service.Decider(lambda: service.connect_for_decide(settings), Metrics())
    try:
        started = time.monotonic()
        response = post(decider, {"lease": lease, "tool": "read_ticket"})
        elapsed = time.monotonic() - started
    finally:
        decider.close()
    assert response.status_code == 503 and response.json() == {"decision": "deny", "reasons": ["risk_unavailable"]}
    assert elapsed < 3, elapsed                        # the gateway gives up at 2 s; the engine at ~1.5 s
    assert calls(admin) == []                          # nothing was written for a decision it did not make
    # The control: without the slow statement the same lease is allowed.
    monkeypatch.setattr(service, "call_facts", real)
    decider = service.Decider(lambda: service.connect_for_decide(settings), Metrics())
    try:
        assert post(decider, {"lease": lease, "tool": "read_ticket"}).json()["decision"] == "allow"
    finally:
        decider.close()


# --- assess_pending: a tier for every pending effect request ---

def assessments(admin):
    return {
        r["request_id"]: (r["tier"], r["reasons"])
        for r in admin.execute("SELECT request_id, tier, reasons FROM risk_assessments ORDER BY request_id")
    }


def test_assess_pending_gives_each_pending_request_one_assessment(admin, engine, settings, now):
    t0 = add_credit(admin, 49, 2, tier=None)  # a real duplicate charge, within the limit
    t1 = add_credit(admin, 10, 4, reason="outage", tier=None)  # no automatic evidence check
    t2 = add_credit(admin, 300, 999, tier=None)  # above both limits, no such charge
    protected = add_moveout(admin, account_id=3, ticket_id=3, tier=None)  # SP-1003, life support
    plain = add_moveout(admin, tier=None)  # SP-1001
    metrics = Metrics()
    assert service.assess_pending(engine, settings, now, metrics) == 5
    assert assessments(admin) == {
        t0: ("T0", []),
        t1: ("T1", ["no_auto_evidence"]),
        t2: ("T2", ["above_auto_limit", "above_200", "evidence_unconfirmed"]),
        protected: ("HUMAN_ONLY", ["protected_or_unknown_home"]),
        plain: ("T1", []),
    }
    rows = admin.execute("SELECT DISTINCT actor, engine_version FROM risk_assessments").fetchall()
    assert rows == [{"actor": "risk_engine", "engine_version": ENGINE_VERSION}]
    assert service.assess_pending(engine, settings, now, metrics) == 0  # nothing left to assess
    out = lines(metrics)
    assert 'risk_tiers_total{tier="T1"} 2' in out
    assert 'risk_tiers_total{tier="HUMAN_ONLY"} 1' in out


def test_assess_pending_leaves_assessed_and_decided_requests_alone(admin, engine, settings, now):
    assessed = add_credit(admin, 49, 2, tier="T2")
    decided = add_credit(admin, 49, 4, tier=None)
    admin.execute("UPDATE action_requests SET status = 'needs_staff' WHERE id = %s", (decided,))
    assert service.assess_pending(engine, settings, now) == 0
    assert assessments(admin) == {assessed: ("T2", [])}


def test_evidence_must_be_a_duplicate_on_the_requests_own_account(admin, engine, settings, now):
    not_duplicate = add_credit(admin, 49, 1, tier=None)  # first of the pair
    give_account_2_a_duplicate(admin)
    other_account = add_credit(admin, 30, 11, tier=None)  # account 2's real duplicate, claimed by account 1
    above_charge = add_credit(admin, 50, 2, tier=None)  # more than the 49.00 charge
    own = add_credit(admin, 30, 11, account_id=2, ticket_id=2, tier=None)  # control: account 2 itself
    service.assess_pending(engine, settings, now)
    got = assessments(admin)
    for rid in (not_duplicate, other_account, above_charge):
        assert "evidence_unconfirmed" in got[rid][1], rid
    assert got[own] == ("T0", [])


def test_a_flood_of_move_outs_is_held(admin, engine, settings, now):
    tight = dataclasses.replace(settings, moveout_max_per_hour=3)
    ids = [add_moveout(admin, tier=None) for _ in range(5)]
    service.assess_pending(engine, tight, now)
    got = assessments(admin)
    assert [got[i][0] for i in ids] == ["T1", "T1", "T1", "HOLD", "HOLD"]
    assert got[ids[-1]][1] == ["flood"]


def test_move_outs_filed_more_than_an_hour_ago_are_not_a_flood(admin, engine, settings, now):
    tight = dataclasses.replace(settings, moveout_max_per_hour=3)
    for _ in range(3):
        old = add_moveout(admin, tier="T1")
        admin.execute("UPDATE action_requests SET created_at = now() - interval '2 hours' WHERE id = %s", (old,))
    new = add_moveout(admin, tier=None)
    service.assess_pending(engine, tight, now)
    assert assessments(admin)[new] == ("T1", [])


def test_stale_register_makes_a_move_out_human_only(admin, engine, settings, now):
    admin.execute("UPDATE register_sync SET last_success = now() - interval '25 hours'")
    rid = add_moveout(admin, tier=None)
    service.assess_pending(engine, settings, now)
    assert assessments(admin)[rid] == ("HUMAN_ONLY", ["protected_or_unknown_home"])


def refuse_credits(admin, count, decided_at):
    for _ in range(count):
        rid = add_credit(admin, 49, 2, tier="T0")
        admin.execute(
            "UPDATE action_requests SET status = 'rejected', decided_at = %s WHERE id = %s", (decided_at, rid)
        )


def test_recent_refusals_on_the_account_raise_the_tier(admin, engine, settings, now):
    refuse_credits(admin, 2, now - timedelta(minutes=10))
    rid = add_credit(admin, 49, 4, tier=None)
    service.assess_pending(engine, settings, now)
    assert assessments(admin)[rid] == ("T1", ["recent_refusals"])


def test_old_refusals_do_not_count(admin, engine, settings, now):
    # Control: the same two refusals, two hours ago.
    refuse_credits(admin, 2, now - timedelta(hours=2))
    rid = add_credit(admin, 49, 4, tier=None)
    service.assess_pending(engine, settings, now)
    assert assessments(admin)[rid] == ("T0", [])


def test_blocked_calls_on_the_ticket_raise_the_tier(admin, engine, settings, now):
    # A run on ticket 1 had a call denied: whatever it filed afterwards gets a person's look.
    lease = open_lease(admin, 1, tools=["read_ticket"])
    service.decide(engine, lease, "issue_bill_credit")  # deny: tool_not_in_lease
    on_ticket_1 = add_credit(admin, 49, 2, ticket_id=1, tier=None)
    on_ticket_4 = add_credit(admin, 49, 4, ticket_id=4, tier=None)  # control: same account, other ticket
    service.assess_pending(engine, settings, now)
    got = assessments(admin)
    assert got[on_ticket_1] == ("T1", ["blocked_calls"])
    assert got[on_ticket_4] == ("T0", [])


def test_calls_denied_only_because_agents_were_paused_are_not_blocked_calls(admin, as_role, engine, settings, now):
    lease = open_lease(admin, 1)
    as_role("risk_engine").execute("SELECT pause_agents('test')")
    service.decide(engine, lease, "read_ticket")  # deny: paused
    rid = add_credit(admin, 49, 2, tier=None)
    service.assess_pending(engine, settings, now)
    assert assessments(admin)[rid] == ("T0", [])


def test_one_bad_request_does_not_stop_the_assessments(admin, engine, settings, now, monkeypatch, caplog):
    first = add_credit(admin, 49, 2, tier=None)
    second = add_credit(admin, 49, 4, tier=None)
    real = service.effect_facts

    def boom_on_first(conn, req, settings_, now_):
        if req["id"] == first:
            raise RuntimeError("boom")
        return real(conn, req, settings_, now_)

    monkeypatch.setattr(service, "effect_facts", boom_on_first)
    metrics = Metrics()
    assert service.assess_pending(engine, settings, now, metrics) == 1
    assert set(assessments(admin)) == {second}
    assert 'risk_errors_total{stage="assess"} 1' in lines(metrics)
    assert f'"request": {first}' in caplog.text


def test_risk_loop_beats_in_memory_and_in_the_database(admin, engine, settings, now):
    rid = add_credit(admin, 49, 2, tier=None)
    metrics = Metrics()
    clock = [100.0]
    heartbeat = Heartbeat(max_age_s=60, clock=lambda: clock[0])
    clock[0] = 200.0
    assert not heartbeat.alive(clock[0])
    risk_main.poll(engine, settings, now, metrics, heartbeat)
    assert heartbeat.alive(clock[0])
    assert rid in assessments(admin)
    beat = admin.execute(
        "SELECT last_beat > now() - interval '1 minute' AS fresh FROM heartbeats WHERE component = 'risk-engine'"
    ).fetchone()
    assert beat == {"fresh": True}
    assert f"risk_last_assess_timestamp_seconds {now.timestamp()!r}" in lines(metrics)


# --- database objects the service uses ---

def _login_roles(admin, *, exclude=()):
    rows = admin.execute("SELECT rolname FROM pg_roles WHERE rolcanlogin ORDER BY rolname").fetchall()
    return [r["rolname"] for r in rows if r["rolname"] not in ("postgres", *exclude)]


COMPONENTS = {
    "executor": "executor",
    "risk_engine": "risk-engine",
    "dispatcher": "dispatcher",
    "register_sync": "register-sync",
    "gateway": "tool-gateway",
}


def beats(admin):
    return {r["component"] for r in admin.execute("SELECT component FROM heartbeats")}


@pytest.mark.parametrize("role", COMPONENTS)
def test_each_component_beats_only_its_own_name(admin, as_role, role):
    conn = as_role(role)
    for other in set(COMPONENTS.values()) - {COMPONENTS[role]}:
        with pytest.raises(psycopg.errors.RaiseException, match="may not beat"):
            conn.execute("SELECT beat(%s)", (other,))
    with pytest.raises(psycopg.errors.RaiseException, match="may not beat"):
        conn.execute("SELECT beat(%s)", (None,))
    assert beats(admin) == set()
    conn.execute("SELECT beat(%s)", (COMPONENTS[role],))  # control: its own name
    conn.execute("SELECT beat(%s)", (COMPONENTS[role],))  # and again: one row, moved forward
    rows = admin.execute(
        "SELECT component, last_beat > now() - interval '1 minute' AS fresh FROM heartbeats"
    ).fetchall()
    assert rows == [{"component": COMPONENTS[role], "fresh": True}]


def test_roles_without_a_component_cannot_beat(admin, as_role):
    allowed = []
    for role in _login_roles(admin, exclude=tuple(COMPONENTS)):
        try:
            as_role(role).execute("SELECT beat('executor')")
        except psycopg.errors.InsufficientPrivilege:
            continue
        allowed.append(role)
    assert allowed == []
    assert beats(admin) == set()


def test_beat_checks_the_caller_not_only_the_grant(admin):
    # A grant added by mistake: approver has no component name, so it is still refused.
    with admin.transaction(force_rollback=True):
        admin.execute("GRANT EXECUTE ON FUNCTION beat(text) TO approver")
        admin.execute("SET SESSION AUTHORIZATION approver")
        with pytest.raises(psycopg.errors.RaiseException, match="may not beat"):
            with admin.transaction():
                admin.execute("SELECT beat('executor')")
        admin.execute("RESET SESSION AUTHORIZATION")


def test_heartbeats_are_written_only_through_beat(admin, as_role):
    allowed = []
    for role in _login_roles(admin):
        conn = as_role(role)
        for statement in ("INSERT INTO heartbeats (component, last_beat) VALUES ('executor', now() + interval '1 year')",
                          "UPDATE heartbeats SET last_beat = now() + interval '1 year'",
                          "DELETE FROM heartbeats"):
            try:
                conn.execute(statement)
            except psycopg.errors.InsufficientPrivilege:
                continue
            allowed.append(f"{role}: {statement}")
    assert allowed == []


def test_risk_lease_facts_answers_yes_or_no_only(admin, engine):
    lease = open_lease(admin, 1, tools=["read_ticket"])
    h = lease_hash(lease)
    one = "SELECT lease_live, tool_in_lease FROM risk_lease_facts(%s, %s)"
    assert engine.execute(one, (h, "read_ticket")).fetchall() == [{"lease_live": True, "tool_in_lease": True}]
    assert engine.execute(one, (h, "issue_bill_credit")).fetchall() == [{"lease_live": True, "tool_in_lease": False}]
    assert engine.execute(one, (lease_hash("nope"), "read_ticket")).fetchall() == [
        {"lease_live": False, "tool_in_lease": False}
    ]
    admin.execute("SELECT revoke_lease(%s)", (lease,))
    assert engine.execute(one, (h, "read_ticket")).fetchall() == [{"lease_live": False, "tool_in_lease": False}]


def test_risk_engine_cannot_read_leases_or_flags_directly(engine):
    for statement in ("SELECT token_hash FROM leases", "SELECT supply_point_id FROM flags",
                      "SELECT last_success FROM register_sync", "SELECT * FROM accounts",
                      "SELECT body FROM tickets"):
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            engine.execute(statement)


def test_home_protection_per_request(admin, engine):
    plain, protected = add_moveout(admin, tier=None), add_moveout(admin, account_id=3, ticket_id=3, tier=None)
    one = "SELECT home_protection(%s) AS p"
    assert engine.execute(one, (plain,)).fetchone()["p"] == "NO"
    assert engine.execute(one, (protected,)).fetchone()["p"] == "YES"
    admin.execute("UPDATE register_sync SET last_success = now() - interval '25 hours'")
    assert engine.execute(one, (plain,)).fetchone()["p"] == "UNKNOWN"


def _not_a_pending_move_out(admin):
    """Requests the engine has no reason to ask about, each for the protected home SP-1003."""
    credit = add_credit(admin, 49, 7, account_id=3, ticket_id=3, tier=None)
    decided = add_moveout(admin, account_id=3, ticket_id=3, tier=None)
    admin.execute("UPDATE action_requests SET status = 'manual_only' WHERE id = %s", (decided,))
    assessed = add_moveout(admin, account_id=3, ticket_id=3, tier="T1")
    return {"a credit request": credit, "a decided move-out": decided, "an assessed move-out": assessed,
            "an unknown request": 999}


def test_home_protection_answers_only_for_a_pending_move_out_awaiting_its_assessment(admin, engine):
    # The flags are health data. The engine needs one answer per move-out it assesses; it must not
    # be able to ask about any account it likes by pointing at an old or unrelated request.
    one = "SELECT home_protection(%s) AS p"
    for case, request_id in _not_a_pending_move_out(admin).items():
        with pytest.raises(psycopg.errors.RaiseException, match="not a pending move-out"):
            engine.execute(one, (request_id,))
    # Control: the same home through a pending, unassessed move-out.
    assert engine.execute(one, (add_moveout(admin, account_id=3, ticket_id=3, tier=None),)).fetchone()["p"] == "YES"


def test_assess_pending_still_reads_protection_for_each_new_move_out(admin, engine, settings, now):
    protected = add_moveout(admin, account_id=3, ticket_id=3, tier=None)
    service.assess_pending(engine, settings, now)
    row = admin.execute("SELECT tier, reasons FROM risk_assessments WHERE request_id = %s", (protected,)).fetchone()
    assert row == {"tier": "HUMAN_ONLY", "reasons": ["protected_or_unknown_home"]}


RISK_ENGINE_FUNCTIONS = {
    # signature: callers
    "risk_lease_facts(bytea,text)": {"risk_engine"},
    "blocked_calls_on_ticket(integer)": {"risk_engine"},
    "home_protection(integer)": {"risk_engine"},
    "beat(text)": set(COMPONENTS),
}


@pytest.mark.parametrize("signature", RISK_ENGINE_FUNCTIONS)
def test_new_risk_functions_are_definers_with_a_fixed_search_path_and_named_callers(admin, signature):
    row = admin.execute(
        "SELECT p.prosecdef, p.proconfig, pg_get_userbyid(p.proowner) AS owner, "
        "ARRAY(SELECT r.rolname FROM pg_roles r "
        "      WHERE r.rolname !~ '^pg_' AND r.rolname <> pg_get_userbyid(p.proowner) "
        "        AND NOT r.rolsuper AND has_function_privilege(r.oid, p.oid, 'EXECUTE')) AS callers "
        "FROM pg_proc p WHERE p.oid = %s::regprocedure",
        (signature,),
    ).fetchone()
    assert row["prosecdef"] is True
    assert row["proconfig"] == ["search_path=public, pg_temp"]
    assert row["owner"] == "risk_owner"
    assert set(row["callers"]) == RISK_ENGINE_FUNCTIONS[signature]


@pytest.mark.parametrize(
    "call", ["risk_lease_facts(sha256('x'), 'read_ticket')", "blocked_calls_on_ticket(1)", "home_protection(1)"]
)
def test_risk_engine_functions_check_the_caller_not_only_the_grant(admin, call):
    signature = {"risk": "risk_lease_facts(bytea,text)", "bloc": "blocked_calls_on_ticket(integer)",
                 "home": "home_protection(integer)"}[call[:4]]
    with admin.transaction(force_rollback=True):
        admin.execute(f"GRANT EXECUTE ON FUNCTION {signature} TO gateway")
        admin.execute("SET SESSION AUTHORIZATION gateway")
        with pytest.raises(psycopg.errors.RaiseException, match="may not"):
            with admin.transaction():
                admin.execute(f"SELECT {call}")
        admin.execute("RESET SESSION AUTHORIZATION")


def test_rls_is_forced_on_heartbeats(admin):
    row = admin.execute(
        "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = 'heartbeats' AND relkind = 'r'"
    ).fetchone()
    assert row == {"relrowsecurity": True, "relforcerowsecurity": True}


def test_tool_names_in_the_lease_are_the_short_ones():
    # The gateway sends the short tool name; the leases list the same names (05-lease.sql).
    assert set(TOOLS) >= service.EFFECT_TOOLS
