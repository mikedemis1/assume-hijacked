"""The dispatcher: which ticket an agent gets, the lease it works under, the reply guard run again
outside the agent, and (in Kubernetes) the Jobs.

The dispatcher is built the way the container builds it: the real HTTP app with the real caller check,
the real database role (`dispatcher`) and the real store. Only the edges are replaced: the network by
an ASGI transport that sets the source address, the TokenReview by a function, the Kubernetes API by a
recording fake.
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import psycopg
import pytest

from app.agent import core, templates
from app.agent.guard import SAFE_REPLY
from app.common.ops import Metrics
from app.dispatcher import k8s, main as dispatcher_main, replies
from app.dispatcher.main import Dispatcher, init_metrics
from app.dispatcher.store import DispatcherDb
from app.gateway.auth import AGENT_USER
from tests.conftest import TOOLS, open_lease
from tests.dispatcherharness import (  # the harness is shared with tests/test_agent.py
    AGENT_IP,
    EVENTS,
    ROOT,
    TEMPLATE_FILE,
    TOOL_IP,
    Harness,
    post,
    request,
    reviewer_for,
)


@pytest.fixture
def compose_dispatcher(settings, as_role):
    return Harness(settings, as_role)


def metric(h, name, **labels):
    text = h.metrics.render()
    key = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
    for line in text.splitlines():
        if line.startswith(f"{name}{{{key}}} "):
            return float(line.rsplit(" ", 1)[1])
    raise AssertionError(f"no series {name}{{{key}}}")


def claim(h, **kwargs):
    return post(h.app, "/claim", **kwargs)


def tool_call(admin, lease, tool, outcome="ok"):
    """A row of the gateway's record of calls, as the gateway writes it."""
    admin.execute(
        "INSERT INTO tool_calls (lease_hash, tool, arg_names, dropped_args, outcome) VALUES (%s, %s, '{}', '{}', %s)",
        (hashlib.sha256(lease.encode()).digest(), tool, outcome),
    )


def stored(admin, ticket):
    row = admin.execute("SELECT text FROM replies WHERE ticket_id = %s", (ticket,)).fetchone()
    return None if row is None else row["text"]


def runs(admin):
    return admin.execute("SELECT ticket_id, status, job_name FROM agent_runs ORDER BY ticket_id").fetchall()


def live(admin, lease):
    return admin.execute("SELECT count(*) AS n FROM lease_scope(%s)", (lease,)).fetchone()["n"] == 1


def claimed(h):
    answer = claim(h)
    assert answer.status_code == 200, answer.text
    return answer.json()["ticket_id"], answer.json()["lease"]


# --- POST /claim in Compose ----------------------------------------------------------------------


def test_claim_opens_lease_for_one_ticket(compose_dispatcher, admin):
    h = compose_dispatcher
    answer = claim(h)
    assert answer.status_code == 200
    body = answer.json()
    assert set(body) == {"ticket_id", "lease"}
    assert body["ticket_id"] == 1                      # the lowest open ticket without a run
    lease = body["lease"]
    assert len(lease) == 64 and int(lease, 16) >= 0
    # The lease is live, names that ticket, lists every tool and is bound to no pod (Compose).
    scope = admin.execute("SELECT ticket_id, allowed_tools, bound_pod FROM lease_scope(%s)", (lease,)).fetchone()
    assert scope == {"ticket_id": 1, "allowed_tools": list(TOOLS), "bound_pod": None}
    # One run, claimed, holding the lease's hash and never the lease.
    row = admin.execute("SELECT ticket_id, status, lease_hash, job_name FROM agent_runs").fetchone()
    assert row == {"ticket_id": 1, "status": "claimed", "lease_hash": hashlib.sha256(lease.encode()).digest(),
                   "job_name": None}
    assert lease not in json.dumps(admin.execute("SELECT * FROM agent_runs").fetchall(), default=str)
    assert metric(h, "dispatcher_claims_total", outcome="issued") == 1


def test_a_second_claim_gets_the_next_ticket_and_an_empty_queue_gets_204(compose_dispatcher, admin):
    h = compose_dispatcher
    assert [claimed(h)[0] for _ in range(4)] == [1, 2, 3, 4]
    empty = claim(h)
    assert empty.status_code == 204 and empty.content == b""
    assert len(runs(admin)) == 4
    assert metric(h, "dispatcher_claims_total", outcome="none") == 1


def test_a_ticket_that_is_not_open_or_already_has_a_run_is_never_handed_out(compose_dispatcher, admin):
    admin.execute("UPDATE tickets SET status = 'closed' WHERE id IN (1, 2)")
    admin.execute("INSERT INTO agent_runs (ticket_id, status) VALUES (3, 'started')")
    assert claimed(compose_dispatcher)[0] == 4
    assert claim(compose_dispatcher).status_code == 204


def test_claims_at_the_same_moment_never_share_a_ticket(settings, as_role, admin):
    # Three dispatchers (three connections; the role is limited to five, and the stack's own
    # dispatcher may hold one) claim at once over the four tickets. Nobody gets the same ticket.
    harnesses = [Harness(settings, as_role) for _ in range(3)]
    answers = [None] * 3
    gate = threading.Barrier(3)

    def go(i):
        gate.wait()
        answers[i] = claim(harnesses[i])

    threads = [threading.Thread(target=go, args=(i,)) for i in range(3)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert [a.status_code for a in answers] == [200, 200, 200]
    tickets = [a.json()["ticket_id"] for a in answers]
    assert len(set(tickets)) == 3 and set(tickets) <= {1, 2, 3, 4}
    leases = {a.json()["lease"] for a in answers}
    assert len(leases) == 3
    # The one ticket left goes to the next claim, and then there is none.
    last = claim(harnesses[0])
    assert last.status_code == 200 and sorted([*tickets, last.json()["ticket_id"]]) == [1, 2, 3, 4]
    assert claim(harnesses[1]).status_code == 204
    assert sorted(r["ticket_id"] for r in runs(admin)) == [1, 2, 3, 4]


def test_a_failed_claim_leaves_no_run_and_no_lease(settings, as_role, admin, monkeypatch):
    h = Harness(settings, as_role)
    monkeypatch.setattr(DispatcherDb, "_lease_for_run", staticmethod(lambda *a: (_ for _ in ()).throw(RuntimeError("x"))))
    assert claim(h).status_code == 503
    assert runs(admin) == []
    assert admin.execute("SELECT count(*) AS n FROM leases").fetchone()["n"] == 0
    monkeypatch.undo()
    assert claim(h).status_code == 200                       # the control: the same ticket is still there
    assert [r["ticket_id"] for r in runs(admin)] == [1]


def test_a_database_that_fails_is_a_503_without_details(settings, as_role, monkeypatch, caplog):
    h = Harness(settings, as_role)

    def broken(work):
        raise psycopg.OperationalError("connection to server at 10.1.2.3 failed: password for dispatcher")

    monkeypatch.setattr(h.store, "_use", broken)
    with caplog.at_level(logging.INFO):
        answer = claim(h)
        replied = post(h.app, "/reply", lease="ab" * 32, body={"text": "hello"})
    assert (answer.status_code, answer.json()) == (503, {"error": "unavailable"})
    assert (replied.status_code, replied.json()) == (503, {"error": "unavailable"})
    assert "10.1.2.3" not in caplog.text and "password" not in answer.text + replied.text
    assert metric(h, "dispatcher_errors_total", stage="database") == 2


# --- the caller check in Compose -----------------------------------------------------------------


@pytest.mark.parametrize(
    "ip", [TOOL_IP, "10.250.1.5", "10.250.3.1", "10.250.2.0".replace("2.0", "255.1"), "127.0.0.1", "::1", "", None]
)
def test_a_caller_outside_the_agents_subnet_is_refused_before_anything_runs(compose_dispatcher, admin, ip):
    h = compose_dispatcher
    lease = open_lease(admin, 1)
    refused_claim = claim(h, ip=ip or None)
    refused_reply = post(h.app, "/reply", lease=lease, body={"text": "hello"}, ip=ip or None)
    assert (refused_claim.status_code, refused_claim.json()) == (401, {"error": "unauthorized"})
    assert refused_reply.status_code == 401
    assert refused_claim.headers["www-authenticate"] == "Bearer"
    # Nothing ran: the store was never asked, no run or reply exists, the lease is still live.
    assert h.store.used == 0
    assert runs(admin) == [] and stored(admin, 1) is None and live(admin, lease)
    # The control: the same two calls from the agent's own address are served.
    assert claim(h).status_code == 200
    assert post(h.app, "/reply", lease=lease, body={"text": "hello"}).status_code == 200
    assert h.store.used > 0
    assert metric(h, "dispatcher_callers_refused_total", reason="wrong_network") >= 2


def test_the_subnet_is_edge_to_edge_first_and_last_address(compose_dispatcher):
    for ip in ("10.250.2.1", "10.250.2.254", "::ffff:10.250.2.9"):
        assert claim(compose_dispatcher, ip=ip).status_code in (200, 204), ip
    for ip in ("10.250.1.255", "10.250.3.0", "10.251.2.5", "192.168.2.5"):
        assert claim(compose_dispatcher, ip=ip).status_code == 401, ip


def test_forwarded_headers_do_not_replace_the_peer_address(compose_dispatcher):
    forged = {"X-Forwarded-For": AGENT_IP, "X-Real-IP": AGENT_IP, "Forwarded": f"for={AGENT_IP}"}
    assert claim(compose_dispatcher, ip=TOOL_IP, headers=forged).status_code == 401


def test_compose_mode_does_not_start_without_the_subnet(monkeypatch):
    for name in ("CALLER_SUBNET", "DISPATCH_MODE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("DB_PASSWORD_DISPATCHER", "x")
    monkeypatch.setenv("CALLER_AUTH", "compose")
    monkeypatch.setattr(dispatcher_main, "start_ops_server", lambda *a: pytest.fail("started without a caller check"))
    with pytest.raises(SystemExit, match="CALLER_SUBNET"):
        dispatcher_main.main()
    monkeypatch.setenv("CALLER_SUBNET", "not-a-subnet")
    with pytest.raises(SystemExit):
        dispatcher_main.main()


def test_the_process_does_not_start_without_its_password_or_with_mixed_modes(monkeypatch):
    monkeypatch.delenv("DB_PASSWORD_DISPATCHER", raising=False)
    with pytest.raises(SystemExit, match="DB_PASSWORD_DISPATCHER"):
        dispatcher_main.main()
    monkeypatch.setenv("DB_PASSWORD_DISPATCHER", "x")
    monkeypatch.setenv("CALLER_AUTH", "compose")
    monkeypatch.setenv("DISPATCH_MODE", "k8s")
    with pytest.raises(SystemExit, match="does not match"):
        dispatcher_main.main()
    monkeypatch.setenv("CALLER_AUTH", "k8s")
    monkeypatch.setenv("DISPATCH_MODE", "compose")
    with pytest.raises(SystemExit, match="does not match"):
        dispatcher_main.main()
    monkeypatch.setenv("DISPATCH_MODE", "nonsense")
    with pytest.raises(SystemExit, match="DISPATCH_MODE"):
        dispatcher_main.main()


def test_the_k8s_process_does_not_start_with_a_changed_template(monkeypatch, tmp_path):
    broken = json.loads(TEMPLATE_FILE.read_text())
    broken["spec"]["template"]["spec"]["serviceAccountName"] = "llm-gateway"
    path = tmp_path / "job.json"
    path.write_text(json.dumps(broken))
    monkeypatch.setenv("DB_PASSWORD_DISPATCHER", "x")
    monkeypatch.setenv("CALLER_AUTH", "k8s")
    monkeypatch.setenv("DISPATCH_MODE", "k8s")
    monkeypatch.setenv("AGENT_JOB_TEMPLATE_FILE", str(path))
    monkeypatch.setattr(dispatcher_main, "start_ops_server", lambda *a: pytest.fail("started with a changed template"))
    with pytest.raises(SystemExit, match="serviceAccountName"):
        dispatcher_main.main()
    monkeypatch.setenv("AGENT_JOB_TEMPLATE_FILE", str(tmp_path / "missing.json"))
    with pytest.raises(SystemExit, match="cannot be read"):
        dispatcher_main.main()


def test_the_process_reads_the_peer_address_and_no_proxy_header():
    import inspect

    assert "proxy_headers=False" in inspect.getsource(dispatcher_main.main)


# --- POST /reply: the guard, run again outside the agent ----------------------------------------

HIJACKED = [
    ("money", "Good news: your bill credit of 49 EUR has been approved.", "currency"),
    ("promise", "We will refund you in full.", "money_wording"),
    ("number", "Your account number is 123456.", "unapproved_number"),
    ("number_word", "You will receive forty nine units.", "number_word"),
    ("lookalike", "Your сredit is on its way", "script_mix"),
]


@pytest.mark.parametrize("name, text, reason", HIJACKED, ids=[h[0] for h in HIJACKED])
def test_reply_runs_guard_again_outside_agent(compose_dispatcher, admin, name, text, reason):
    # The agent is taken over and sends what the model wrote without its own guard having run.
    h = compose_dispatcher
    ticket, lease = claimed(h)
    answer = post(h.app, "/reply", lease=lease, body={"text": text})
    assert (answer.status_code, answer.json()) == (200, {"stored": True})   # it does not say it replaced the text
    assert stored(admin, ticket) == SAFE_REPLY
    assert metric(h, "dispatcher_replies_blocked_total", reason=reason) == 1


def test_an_honest_reply_goes_out_unchanged_and_the_account_numbers_are_allowed(compose_dispatcher, admin):
    # The control: the guard is not a wall that blocks everything. Ticket 1's account is at Patision 10
    # on tariff G1, so "10" and "1" are numbers a tool showed the model.
    h = compose_dispatcher
    ticket, lease = claimed(h)
    text = "Your home at Patision 10 is on tariff G1 and the account is active."
    assert post(h.app, "/reply", lease=lease, body={"text": text}).status_code == 200
    assert stored(admin, ticket) == text
    assert metric(h, "dispatcher_replies_blocked_total", reason="unapproved_number") == 0


def test_the_numbers_allowed_are_the_ticket_owners_not_another_customers(compose_dispatcher, admin):
    # Customer 1002 lives at Egnatias 5. On ticket 1 (Patision 10) a reply with 5 is not allowed.
    h = compose_dispatcher
    ticket, lease = claimed(h)
    assert post(h.app, "/reply", lease=lease, body={"text": "You live at Egnatias 5."}).status_code == 200
    assert stored(admin, ticket) == SAFE_REPLY


def test_the_notices_come_from_the_record_of_calls_not_from_the_agent(compose_dispatcher, admin):
    h = compose_dispatcher
    ticket, lease = claimed(h)
    tool_call(admin, lease, "read_ticket")
    tool_call(admin, lease, "issue_bill_credit", "denied")        # asked, and refused: the notice still goes on
    tool_call(admin, lease, "request_disconnection", "ok")
    # The agent says nothing about any of this.
    assert post(h.app, "/reply", lease=lease, body={"text": "Thank you, we are checking."}).status_code == 200
    assert stored(admin, ticket) == "\n\n".join(["Thank you, we are checking.", replies.CREDIT_NOTICE, replies.MEDICAL_QUESTION])


@pytest.mark.parametrize(
    "calls, credit, moveout",
    [
        ([], False, False),
        ([("issue_bill_credit", "ok")], True, False),
        ([("issue_bill_credit", "tool_error")], True, False),
        ([("issue_bill_credit", "denied")], True, False),
        ([("request_disconnection", "ok")], False, True),
        ([("request_disconnection", "denied")], False, False),          # nothing went in, no question
        ([("request_disconnection", "tool_error")], False, False),
        ([("request_disconnection", "ok"), ("issue_bill_credit", "ok")], True, True),
        ([("lookup_account", "ok"), ("set_temp_protection", "ok")], False, False),
    ],
)
def test_the_dispatcher_adds_the_notices_by_the_agents_rules(compose_dispatcher, admin, calls, credit, moveout):
    h = compose_dispatcher
    ticket, lease = claimed(h)
    for tool, outcome in calls:
        tool_call(admin, lease, tool, outcome)
    assert post(h.app, "/reply", lease=lease, body={"text": "We are looking into it."}).status_code == 200
    # The reply, then the credit notice if a credit was asked for, then the medical question if a
    # move-out went in, each after a blank line.
    expected = "\n\n".join(
        ["We are looking into it."] + ([replies.CREDIT_NOTICE] if credit else []) + ([replies.MEDICAL_QUESTION] if moveout else [])
    )
    assert stored(admin, ticket) == expected
    assert replies.finish("We are looking into it.", "", credit, moveout).text == expected


def test_other_leases_calls_do_not_count(compose_dispatcher, admin):
    h = compose_dispatcher
    ticket, lease = claimed(h)
    other = open_lease(admin, 2)
    tool_call(admin, other, "issue_bill_credit")
    tool_call(admin, other, "request_disconnection")
    assert post(h.app, "/reply", lease=lease, body={"text": "Thank you."}).status_code == 200
    assert stored(admin, ticket) == "Thank you."


def test_the_notices_that_name_a_credit_are_added_after_the_guard(compose_dispatcher, admin):
    # The notice says "credit", which the guard blocks; it must not be blocked on its way out.
    from app.agent.guard import block_reason

    assert block_reason(replies.CREDIT_NOTICE, set())
    h = compose_dispatcher
    ticket, lease = claimed(h)
    tool_call(admin, lease, "issue_bill_credit")
    post(h.app, "/reply", lease=lease, body={"text": "Thank you."})
    assert replies.CREDIT_NOTICE in stored(admin, ticket) and SAFE_REPLY not in stored(admin, ticket)


def test_an_agent_that_sends_the_notice_itself_is_blocked_like_any_money_text(compose_dispatcher, admin):
    h = compose_dispatcher
    ticket, lease = claimed(h)
    post(h.app, "/reply", lease=lease, body={"text": "Hello. " + replies.CREDIT_NOTICE})
    assert stored(admin, ticket) == SAFE_REPLY


def test_the_gave_up_text_and_the_safe_text_pass_the_guard(compose_dispatcher, admin):
    for text in (core.GIVE_UP, SAFE_REPLY):
        assert replies.finish(text, "", False, False).blocked is None


def test_the_ticket_comes_from_the_lease_not_from_the_body(compose_dispatcher, admin):
    h = compose_dispatcher
    ticket, lease = claimed(h)
    assert ticket == 1
    answer = post(h.app, "/reply", lease=lease, body={"text": "Thank you.", "ticket_id": 2, "lease": "x", "status": "replied"})
    assert answer.status_code == 200
    assert stored(admin, 1) == "Thank you." and stored(admin, 2) is None


# --- POST /reply: the lease ----------------------------------------------------------------------


def test_reply_revokes_lease(compose_dispatcher, admin, as_role):
    h = compose_dispatcher
    ticket, lease = claimed(h)
    assert live(admin, lease)                                         # the control: live before the reply
    assert post(h.app, "/reply", lease=lease, body={"text": "Thank you."}).status_code == 200
    assert not live(admin, lease)
    assert admin.execute("SELECT revoked FROM leases").fetchone()["revoked"] is True
    assert runs(admin) == [{"ticket_id": 1, "status": "replied", "job_name": None}]
    # The lease no longer works anywhere: not for a second reply, not for a tool.
    again = post(h.app, "/reply", lease=lease, body={"text": "Another."})
    assert (again.status_code, again.json()) == (403, {"error": "lease"})
    assert stored(admin, ticket) == "Thank you."


def test_reply_waits_for_an_inflight_effect_before_deciding_its_notice(compose_dispatcher, as_role, admin):
    h = compose_dispatcher
    ticket, lease = claimed(h)
    entered, release = threading.Event(), threading.Event()
    def effect():
        with as_role("tool_issue_bill_credit").transaction() as transaction:
            transaction.connection.execute("SELECT api_request_credit(%s, 1, 'duplicate_charge', 2)", (lease,))
            entered.set()
            assert release.wait(10), "test did not release the effect transaction"
    with ThreadPoolExecutor(max_workers=2) as pool:
        pending = pool.submit(effect)
        try:
            assert entered.wait(5), "effect did not enter its transaction"
            reply = pool.submit(post, h.app, "/reply", lease=lease, body={"text": "Thank you."})
            deadline, blocked = time.monotonic() + 5, False
            while time.monotonic() < deadline and not reply.done():
                blocked = admin.execute(
                    "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname = current_database() "
                    "AND query LIKE 'SELECT * FROM finish_reply_facts%%' AND wait_event_type = 'Lock') AS blocked"
                ).fetchone()["blocked"]
                if blocked:
                    break
                time.sleep(0.02)
            assert blocked, "reply completion did not wait for the in-flight tool transaction"
        finally:
            release.set()
        pending.result(timeout=10)
        assert reply.result(timeout=10).status_code == 200
    assert replies.CREDIT_NOTICE in stored(admin, ticket)
    with pytest.raises(psycopg.errors.RaiseException, match="lease invalid"):
        as_role("tool_read_ticket").execute("SELECT * FROM api_read_ticket(%s)", (lease,))


def test_reply_notices_ignore_requests_filed_before_the_lease_opened(compose_dispatcher, admin, as_role):
    # A request left on the same ticket by an earlier run is not this run's doing, so it adds no
    # notice. The control: the same two kinds of request filed by the tools during the lease do.
    h = compose_dispatcher
    admin.execute(
        "INSERT INTO action_requests (kind, ticket_id, account_id, amount_eur, reason, evidence_ref, move_out_date, created_at) "
        "VALUES ('move_out', 1, 1, NULL, NULL, NULL, current_date, now() - interval '1 hour'), "
        "('credit', 1, 1, 1.00, 'duplicate_charge', 2, NULL, now() - interval '1 hour')"
    )
    ticket, lease = claimed(h)
    assert post(h.app, "/reply", lease=lease, body={"text": "Thank you."}).status_code == 200
    assert stored(admin, ticket) == "Thank you."
    admin.execute("DELETE FROM replies")
    admin.execute("DELETE FROM agent_runs")
    ticket, lease = claimed(h)
    as_role("tool_request_disconnection").execute("SELECT api_request_moveout(%s, current_date)", (lease,))
    as_role("tool_issue_bill_credit").execute("SELECT api_request_credit(%s, 1, 'duplicate_charge', 2)", (lease,))
    assert post(h.app, "/reply", lease=lease, body={"text": "Thank you."}).status_code == 200
    assert replies.CREDIT_NOTICE in stored(admin, ticket) and replies.MEDICAL_QUESTION in stored(admin, ticket)


BAD_LEASES = {
    "unknown": "ab" * 32,
    "empty": "",
    "short": "abc",
    "upper case": "AB" * 32,
    "not hex": "zz" * 32,
    "padded": "ab" * 32 + " ",
    "sql": "' OR '1'='1",
}


@pytest.mark.parametrize("name", list(BAD_LEASES))
def test_a_reply_with_an_unknown_or_malformed_lease_is_refused_and_stores_nothing(compose_dispatcher, admin, name):
    h = compose_dispatcher
    lease = BAD_LEASES[name]
    answer = request(h.app, "POST", "/reply", headers={"X-Lease": lease} if lease else {}, content=json.dumps({"text": "Hi"}))
    assert (answer.status_code, answer.json()) == (403, {"error": "lease"})
    assert admin.execute("SELECT count(*) AS n FROM replies").fetchone()["n"] == 0
    assert metric(h, "dispatcher_replies_total", outcome="lease") == 1


def test_an_expired_or_revoked_lease_cannot_reply(compose_dispatcher, admin):
    h = compose_dispatcher
    _, lease = claimed(h)
    admin.execute("UPDATE leases SET expires_at = now() - interval '1 second'")
    assert post(h.app, "/reply", lease=lease, body={"text": "Late."}).status_code == 403
    admin.execute("UPDATE leases SET expires_at = now() + interval '1 hour', revoked = true")
    assert post(h.app, "/reply", lease=lease, body={"text": "Revoked."}).status_code == 403
    assert stored(admin, 1) is None
    admin.execute("UPDATE leases SET revoked = false")
    assert post(h.app, "/reply", lease=lease, body={"text": "Fine."}).status_code == 200         # the control


def test_two_lease_headers_are_no_lease(compose_dispatcher, admin):
    h = compose_dispatcher
    _, lease = claimed(h)
    two = request(
        h.app, "POST", "/reply", headers=[("X-Lease", lease), ("X-Lease", lease)], content=json.dumps({"text": "Hi"})
    )
    assert two.status_code == 403 and stored(admin, 1) is None
    assert post(h.app, "/reply", lease=lease, body={"text": "Hi"}).status_code == 200


def test_a_ticket_that_has_a_reply_gets_409_and_the_lease_ends(compose_dispatcher, admin):
    h = compose_dispatcher
    ticket, lease = claimed(h)
    admin.execute("INSERT INTO replies (ticket_id, text) VALUES (%s, 'Written by a colleague.')", (ticket,))
    answer = post(h.app, "/reply", lease=lease, body={"text": "Thank you."})
    assert (answer.status_code, answer.json()) == (409, {"error": "already_replied"})
    assert stored(admin, ticket) == "Written by a colleague."
    assert not live(admin, lease)


BAD_BODIES = {
    "not json": b"{nope",
    "a list": b'["text"]',
    "no text": b'{"reply": "hi"}',
    "text is a number": b'{"text": 5}',
    "text is null": b'{"text": null}',
    "empty text": b'{"text": ""}',
    "too long": json.dumps({"text": "a" * (replies.MAX_TEXT_CHARS + 1)}).encode(),
    "nested": b"[" * 5000 + b"]" * 5000,
    "empty body": b"",
}


@pytest.mark.parametrize("name", list(BAD_BODIES))
def test_a_reply_body_that_is_not_text_is_a_400_and_stores_nothing(compose_dispatcher, admin, name):
    h = compose_dispatcher
    _, lease = claimed(h)
    answer = post(h.app, "/reply", lease=lease, content=BAD_BODIES[name])
    assert (answer.status_code, answer.json()) == (400, {"error": "bad_request"})
    assert stored(admin, 1) is None and live(admin, lease)
    ok = post(h.app, "/reply", lease=lease, body={"text": "a" * replies.MAX_TEXT_CHARS})   # the control: the largest text
    assert ok.status_code == 200


def test_a_body_over_16_kib_is_refused_declared_or_chunked(compose_dispatcher, admin):
    h = compose_dispatcher
    _, lease = claimed(h)
    big = json.dumps({"text": "a" * (16 * 1024)})

    async def chunks():
        for i in range(0, len(big), 1024):
            yield big[i:i + 1024].encode()

    declared = post(h.app, "/reply", lease=lease, content=big)
    chunked = request(h.app, "POST", "/reply", headers={"X-Lease": lease}, content=chunks())
    assert (declared.status_code, chunked.status_code) == (413, 413)
    assert stored(admin, 1) is None and live(admin, lease)
    assert metric(h, "dispatcher_replies_total", outcome="too_large") == 2


def test_only_the_two_routes_and_post_are_served(compose_dispatcher):
    h = compose_dispatcher
    assert request(h.app, "GET", "/claim").status_code == 405
    assert request(h.app, "GET", "/reply").status_code == 405
    assert request(h.app, "POST", "/other").status_code == 404
    assert request(h.app, "GET", "/healthz").status_code == 404


def test_events_and_answers_carry_no_reply_text_and_no_lease(compose_dispatcher, admin, caplog):
    h = compose_dispatcher
    ticket, lease = claimed(h)
    secret = "Heart condition at Secret Street, SECRET-MARKER"
    with caplog.at_level(logging.INFO, logger=EVENTS):
        answer = post(h.app, "/reply", lease=lease, body={"text": secret})
    assert answer.status_code == 200
    kinds = [json.loads(r.getMessage())["kind"] for r in caplog.records if r.name == EVENTS]
    assert "reply_stored" in kinds                                  # the control: events were captured
    assert "SECRET-MARKER" not in caplog.text and lease not in caplog.text
    assert "SECRET-MARKER" not in h.metrics.render()
    assert "SECRET-MARKER" not in answer.text and lease not in answer.text


def test_a_blocked_reply_is_logged_by_category_only(compose_dispatcher, caplog):
    h = compose_dispatcher
    _, lease = claimed(h)
    with caplog.at_level(logging.INFO, logger=EVENTS):
        post(h.app, "/reply", lease=lease, body={"text": "Your credit of 49 EUR is approved"})
    events = [json.loads(r.getMessage()) for r in caplog.records if r.name == EVENTS]
    blocked = [e for e in events if e["kind"] == "reply_blocked"]
    assert [(e["reason"], e["ticket_id"], e["where"]) for e in blocked] == [("currency", 1, "dispatcher")]
    assert "approved" not in caplog.text and "EUR" not in caplog.text


# --- Kubernetes: Jobs, pods and tickets ---------------------------------------------------------


class FakeKube:
    """Stands in for the Kubernetes API: keeps every Job it was asked to create."""

    def __init__(self, answer=None, fail_for=()):
        self.created: list[dict] = []
        self._answer, self._fail_for = answer, set(fail_for)

    def post(self, path, body):
        assert path == "/apis/batch/v1/namespaces/ah-agent/jobs", path
        if int(body["metadata"]["labels"]["ah/ticket"]) in self._fail_for:
            raise OSError("403 Forbidden: jobs.batch is forbidden for dispatcher")
        self.created.append(copy.deepcopy(body))
        return self._answer(body) if self._answer else {"metadata": {"name": body["metadata"]["name"]}}

    def api(self):
        return k8s.KubeApi(api_url="https://kube.test", post=self.post)


def pod_of(job_name, suffix="x7k2p"):
    return f"{job_name}-{suffix}"


@pytest.fixture
def kube_harness(settings, as_role):
    kube = FakeKube()
    tokens: dict = {}
    h = Harness(settings, as_role, mode="k8s", reviewer=reviewer_for(tokens), api=kube.api())
    h.kube, h.tokens = kube, tokens

    def agent(pod, token=None, user=AGENT_USER):
        token = token or f"token-of-{pod}"
        tokens[token] = (user, pod)
        return {"Authorization": f"Bearer {token}"}

    h.agent = agent
    return h


def test_dispatch_creates_one_job_per_open_ticket_from_the_template(kube_harness, admin):
    h = kube_harness
    assert h.dispatcher.dispatch_once() == 3                           # max_active
    assert [run["ticket_id"] for run in runs(admin)] == [1, 2, 3]
    assert all(run["status"] == "started" and run["job_name"] for run in runs(admin))
    template = templates.load_template(TEMPLATE_FILE)
    for job in h.kube.created:
        label = job["metadata"]["labels"]["ah/ticket"]
        assert job["metadata"]["name"] == [r["job_name"] for r in runs(admin) if str(r["ticket_id"]) == label][0]
        assert templates.JOB_NAME.fullmatch(job["metadata"]["name"])
        # Only the name and the label differ from the template.
        expected = copy.deepcopy(template)
        expected["metadata"]["name"] = job["metadata"]["name"]
        expected["metadata"]["labels"]["ah/ticket"] = label
        expected["spec"]["template"]["metadata"]["labels"]["ah/ticket"] = label
        assert job == expected
    assert metric(h, "dispatcher_jobs_total", outcome="created") == 3
    # No more while three are running; a finished one makes room.
    assert h.dispatcher.dispatch_once() == 0 and len(h.kube.created) == 3
    assert metric(h, "dispatcher_jobs_total", outcome="full") >= 1
    admin.execute("UPDATE agent_runs SET status = 'replied', lease_hash = '\\x01' WHERE ticket_id = 1")
    assert h.dispatcher.dispatch_once() == 1
    assert [r["ticket_id"] for r in runs(admin)] == [1, 2, 3, 4]


def test_a_run_older_than_ten_minutes_no_longer_takes_a_place(kube_harness, admin):
    h = kube_harness
    h.dispatcher.dispatch_once()
    admin.execute("UPDATE agent_runs SET created_at = now() - interval '11 minutes'")
    assert h.dispatcher.dispatch_once() == 1                           # ticket 4; the three stale runs are not counted


def test_compose_mode_never_calls_the_kubernetes_api(compose_dispatcher, admin):
    assert compose_dispatcher.dispatcher.dispatch_once() == 0
    assert runs(admin) == []


def test_a_job_the_api_refuses_leaves_the_run_failed_and_the_next_ticket_goes_on(settings, as_role, admin):
    kube = FakeKube(fail_for={1})
    h = Harness(settings, as_role, mode="k8s", reviewer=reviewer_for({}), api=kube.api(), max_active=5)
    assert h.dispatcher.dispatch_once() == 3                           # tickets 2, 3, 4
    assert [(r["ticket_id"], r["status"]) for r in runs(admin)] == [
        (1, "failed"), (2, "started"), (3, "started"), (4, "started")]
    assert metric(h, "dispatcher_jobs_total", outcome="failed") == 1
    assert h.dispatcher.dispatch_once() == 0                           # a failed run is not tried again


def test_an_api_answer_that_names_another_job_counts_as_failed(settings, as_role, admin):
    kube = FakeKube(answer=lambda body: {"metadata": {"name": "something-else"}})
    h = Harness(settings, as_role, mode="k8s", reviewer=reviewer_for({}), api=kube.api(), max_active=1)
    assert h.dispatcher.dispatch_once() == 0
    assert runs(admin)[0]["status"] == "failed"


def test_closed_tickets_and_tickets_with_a_run_get_no_job(kube_harness, admin):
    h = kube_harness
    admin.execute("UPDATE tickets SET status = 'closed' WHERE id IN (1, 2)")
    admin.execute("INSERT INTO agent_runs (ticket_id, status) VALUES (3, 'failed')")
    assert h.dispatcher.dispatch_once() == 1
    assert [j["metadata"]["labels"]["ah/ticket"] for j in h.kube.created] == ["4"]


def test_claim_k8s_mode_maps_pod_to_ticket(kube_harness, admin):
    h = kube_harness
    h.dispatcher.dispatch_once()
    jobs = {int(j["metadata"]["labels"]["ah/ticket"]): j["metadata"]["name"] for j in h.kube.created}
    pod2 = pod_of(jobs[2])
    answer = claim(h, headers=h.agent(pod2), ip="10.0.0.9")            # any address: the token decides
    assert answer.status_code == 200
    ticket, lease = answer.json()["ticket_id"], answer.json()["lease"]
    assert ticket == 2                                                  # the ticket of the Job, not the lowest
    scope = admin.execute("SELECT ticket_id, bound_pod FROM lease_scope(%s)", (lease,)).fetchone()
    assert scope == {"ticket_id": 2, "bound_pod": pod2}                 # bound to the pod that asked
    assert {r["ticket_id"]: r["status"] for r in runs(admin)} == {1: "started", 2: "claimed", 3: "started"}
    # The pod of ticket 1's Job gets ticket 1, a different lease, bound to it.
    pod1 = pod_of(jobs[1], "abcde")
    first = claim(h, headers=h.agent(pod1))
    assert first.json()["ticket_id"] == 1 and first.json()["lease"] != lease
    # A second claim from the same pod gets nothing, and no second lease exists.
    assert claim(h, headers=h.agent(pod2)).status_code == 204
    assert admin.execute("SELECT count(*) AS n FROM leases WHERE ticket_id = 2").fetchone()["n"] == 1


@pytest.mark.parametrize(
    "pod",
    [
        "agent-99-deadbeef-abcde",               # a well formed name of a Job nobody made
        "agent-1-deadbeef",                       # no pod suffix
        "agent-1-DEADBEEF-abcde",                 # not lower case hex
        "x-agent-1-deadbeef-abcde",
        "agent-1-deadbeef-abcde-fgh",
        "dispatcher-5d9c7b-xk2lp",                # some other component's pod
        "agent-1-deadbeef-ABCDE",
        "",
    ],
)
def test_a_pod_that_belongs_to_no_run_gets_204(kube_harness, admin, pod):
    h = kube_harness
    h.dispatcher.dispatch_once()
    # The control first: the Job's real pod claims.
    job = h.kube.created[0]["metadata"]["name"]
    assert claim(h, headers=h.agent(pod_of(job))).status_code == 200
    before = admin.execute("SELECT count(*) AS n FROM leases").fetchone()["n"]
    answer = claim(h, headers=h.agent(pod))
    assert answer.status_code in (204, 401), pod                          # an empty pod name is no pod: 401
    assert admin.execute("SELECT count(*) AS n FROM leases").fetchone()["n"] == before


@pytest.mark.parametrize("tail", ["", "-abcde-fgh", "-ABCDE", "-abcd", "-abcdef", "_abcde", "-ab.de", "-abcde\n"])
def test_a_pod_named_after_a_real_job_but_not_the_way_the_job_controller_names_it_gets_nothing(kube_harness, admin, tail):
    h = kube_harness
    h.dispatcher.dispatch_once()
    job = h.kube.created[0]["metadata"]["name"]
    assert claim(h, headers=h.agent(job + tail)).status_code in (204, 401)
    assert all(r["status"] == "started" for r in runs(admin))
    assert claim(h, headers=h.agent(pod_of(job))).status_code == 200                # the control


def test_a_pod_of_a_job_whose_name_only_looks_like_a_run_gets_nothing(kube_harness, admin):
    h = kube_harness
    h.dispatcher.dispatch_once()
    real = h.kube.created[0]["metadata"]["name"]
    forged = real[:-8] + ("0" * 8 if not real.endswith("0" * 8) else "1" * 8)
    assert claim(h, headers=h.agent(pod_of(forged))).status_code == 204


def test_k8s_claim_needs_the_agents_service_account_and_a_pod(kube_harness, admin):
    h = kube_harness
    h.dispatcher.dispatch_once()
    job = h.kube.created[0]["metadata"]["name"]
    pod = pod_of(job)
    before = lambda: (admin.execute("SELECT count(*) AS n FROM leases").fetchone()["n"], runs(admin))  # noqa: E731
    state = before()
    h.tokens["t-llm"] = ("system:serviceaccount:ah-agent:llm-gateway", pod)
    h.tokens["t-dispatcher"] = ("system:serviceaccount:ah-intake:dispatcher", pod)
    h.tokens["t-nopod"] = (AGENT_USER, None)
    for name, headers in {
        "no header": {},
        "wrong scheme": {"Authorization": f"Basic token-of-{pod}"},
        "unknown token": {"Authorization": "Bearer nobody"},
        "other service account": {"Authorization": "Bearer t-llm"},
        "dispatcher's own account": {"Authorization": "Bearer t-dispatcher"},
        "token without a pod": {"Authorization": "Bearer t-nopod"},
        "two headers": [("Authorization", "Bearer t-llm"), ("Authorization", "Bearer t-llm")],
    }.items():
        answer = request(h.app, "POST", "/claim", headers=headers, ip=AGENT_IP)
        assert answer.status_code == 401, name
    assert before() == state                                           # nothing was claimed
    assert claim(h, headers=h.agent(pod)).status_code == 200            # the control


def test_a_token_review_that_breaks_means_not_verified(settings, as_role, admin):
    def broken(token, audience):
        raise RuntimeError("the API server is down")

    kube = FakeKube()
    h = Harness(settings, as_role, mode="k8s", reviewer=broken, api=kube.api())
    h.dispatcher.dispatch_once()
    assert claim(h, headers={"Authorization": "Bearer anything"}).status_code == 401
    assert post(h.app, "/reply", lease="ab" * 32, body={"text": "Hi"}, headers={"Authorization": "Bearer anything"}).status_code == 401
    assert h.store.used > 0 and all(r["status"] == "started" for r in runs(admin))


def test_k8s_reply_needs_the_pod_the_lease_is_bound_to(kube_harness, admin):
    h = kube_harness
    h.dispatcher.dispatch_once()
    jobs = {int(j["metadata"]["labels"]["ah/ticket"]): j["metadata"]["name"] for j in h.kube.created}
    mine, theirs = pod_of(jobs[1]), pod_of(jobs[2])
    lease = claim(h, headers=h.agent(mine)).json()["lease"]
    other = h.agent(theirs)
    refused = post(h.app, "/reply", lease=lease, body={"text": "Thank you."}, headers=other)
    assert (refused.status_code, refused.json()) == (403, {"error": "lease"})
    assert stored(admin, 1) is None and live(admin, lease)
    # Not from the same pod under another account either (the account check is the caller check's).
    h.tokens["t-llm"] = ("system:serviceaccount:ah-agent:llm-gateway", mine)
    assert post(h.app, "/reply", lease=lease, body={"text": "Hi"}, headers={"Authorization": "Bearer t-llm"}).status_code == 401
    ok = post(h.app, "/reply", lease=lease, body={"text": "Thank you."}, headers=h.agent(mine))
    assert ok.status_code == 200 and stored(admin, 1) == "Thank you."
    assert not live(admin, lease)


def test_a_lease_bound_to_no_pod_is_not_accepted_from_a_pod(kube_harness, admin):
    # For instance a lease opened by hand: in Kubernetes only the pod it is bound to may reply.
    h = kube_harness
    lease = open_lease(admin, 1)
    pod = pod_of("agent-1-deadbeef")
    assert post(h.app, "/reply", lease=lease, body={"text": "Hi"}, headers=h.agent(pod)).status_code == 403
    assert stored(admin, 1) is None


def test_a_compose_dispatcher_does_not_accept_a_lease_bound_to_a_pod(compose_dispatcher, admin):
    lease = open_lease(admin, 1, bound_pod="agent-1-deadbeef-abcde")
    assert post(compose_dispatcher.app, "/reply", lease=lease, body={"text": "Hi"}).status_code == 403


def test_k8s_mode_refuses_to_exist_without_a_template_or_an_api(settings, as_role):
    with pytest.raises(ValueError, match="template"):
        Dispatcher(DispatcherDb(lambda: as_role("dispatcher")), "k8s", Metrics())
    with pytest.raises(ValueError, match="DISPATCH_MODE"):
        Dispatcher(DispatcherDb(lambda: as_role("dispatcher")), "nonsense", Metrics())


def test_the_metrics_start_at_zero_and_name_no_text():
    metrics = Metrics()
    init_metrics(metrics)
    text = metrics.render()
    for series in (
        'dispatcher_claims_total{outcome="issued"} 0',
        'dispatcher_claims_total{outcome="none"} 0',
        'dispatcher_replies_total{outcome="stored"} 0',
        'dispatcher_replies_blocked_total{reason="currency"} 0',
        'dispatcher_callers_refused_total{reason="wrong_network"} 0',
        'dispatcher_jobs_total{outcome="created"} 0',
    ):
        assert series in text, series


# --- the Job template ----------------------------------------------------------------------------

TOKENS = [
    {"serviceAccountToken": {"audience": a, "expirationSeconds": 600, "path": f"{a}/token"}}
    for a in ("tool-gateway", "llm-gateway", "dispatcher")
]


def template():
    return json.loads(TEMPLATE_FILE.read_text(encoding="utf-8"))


def test_job_template_is_fixed():
    """Every field of the Job the dispatcher creates, written out. A Job made for ticket 7 is this and
    nothing else (the image, env and resources are the values the chart rendered)."""
    source = template()
    image = source["spec"]["template"]["spec"]["containers"][0]["image"]
    job = templates.build_job(source, 7, name="agent-7-0a1b2c3d")
    pod = job["spec"]["template"]["spec"]
    container = pod["containers"][0]
    restricted = {
        "allowPrivilegeEscalation": False,
        "capabilities": {"drop": ["ALL"]},
        "readOnlyRootFilesystem": True,
        "runAsGroup": 10001,
        "runAsNonRoot": True,
        "runAsUser": 10001,
        "seccompProfile": {"type": "RuntimeDefault"},
    }
    assert job["apiVersion"] == "batch/v1" and job["kind"] == "Job"
    assert job["metadata"] == {
        "name": "agent-7-0a1b2c3d",
        "namespace": "ah-agent",
        "labels": {"app.kubernetes.io/name": "agent", "ah/ticket": "7"},
    }
    assert set(job) == {"apiVersion", "kind", "metadata", "spec"}
    assert job["spec"]["backoffLimit"] == 0
    assert job["spec"]["activeDeadlineSeconds"] == 300
    assert job["spec"]["ttlSecondsAfterFinished"] == 600
    assert set(job["spec"]) == {"backoffLimit", "activeDeadlineSeconds", "ttlSecondsAfterFinished", "template"}
    assert job["spec"]["template"]["metadata"] == {"labels": {"app.kubernetes.io/name": "agent", "ah/ticket": "7"}}
    assert pod["serviceAccountName"] == "agent"
    assert pod["automountServiceAccountToken"] is False
    assert pod["runtimeClassName"] == "kata-vm-isolation"
    assert pod["restartPolicy"] == "Never"
    assert pod["enableServiceLinks"] is False
    assert pod["securityContext"] == {
        "fsGroup": 10001, "runAsGroup": 10001, "runAsNonRoot": True, "runAsUser": 10001,
        "seccompProfile": {"type": "RuntimeDefault"},
    }
    assert set(pod) == {
        "serviceAccountName", "automountServiceAccountToken", "runtimeClassName", "restartPolicy",
        "enableServiceLinks", "securityContext", "containers", "volumes",
    }
    assert [c["name"] for c in pod["containers"]] == ["agent"]
    assert container["image"] == image and templates.IMAGE.fullmatch(image) and "@sha256:" in image
    assert container["command"] == ["python", "-m", "app.agent.main"]
    assert container["securityContext"] == restricted
    assert container["volumeMounts"] == [{"name": "ah-tokens", "mountPath": "/var/run/secrets/ah", "readOnly": True}]
    assert set(container) == {"name", "image", "imagePullPolicy", "command", "env", "volumeMounts", "securityContext", "resources"}
    # No Secret anywhere: plain env values only, no envFrom, no valueFrom, no secret volume.
    assert all(set(item) == {"name", "value"} for item in container["env"])
    assert {item["name"] for item in container["env"]} <= {
        "APP_ENV", "CALLER_AUTH", "GATEWAY_URL", "LLM_GATEWAY_URL", "DISPATCHER_URL"}
    assert pod["volumes"] == [{"name": "ah-tokens", "projected": {"sources": TOKENS}}]
    assert "secret" not in json.dumps(job).lower().replace("secrets/ah", "")
    # The ticket text is not in the Job.
    assert "Hello" not in json.dumps(job)


def test_the_template_in_the_tests_is_accepted_and_has_the_chart_s_shape():
    loaded = templates.load_template(TEMPLATE_FILE)
    assert loaded["metadata"]["labels"]["ah/ticket"] == ""
    assert "name" not in loaded["metadata"]
    assert templates.DEFAULT_TEMPLATE_FILE == "/etc/ah/agent-job-template/job.json"


def mutated(*path_and_value):
    *path, value = path_and_value
    job = template()
    node = job
    for key in path[:-1]:
        node = node[key]
    if value is DELETE:
        del node[path[-1]]
    else:
        node[path[-1]] = value
    return job


DELETE = object()
SPEC = ("spec", "template", "spec")
CONTAINER = (*SPEC, "containers", 0)
MUTATIONS = {
    "service account": mutated(*SPEC, "serviceAccountName", "llm-gateway"),
    "service account default": mutated(*SPEC, "serviceAccountName", "default"),
    "api token mounted": mutated(*SPEC, "automountServiceAccountToken", True),
    "api token as 0": mutated(*SPEC, "automountServiceAccountToken", 0),
    "runtime class": mutated(*SPEC, "runtimeClassName", "runc"),
    "no runtime class": mutated(*SPEC, "runtimeClassName", DELETE),
    "image by tag": mutated(*CONTAINER, "image", "localhost:5001/assume-hijacked:latest"),
    "image short digest": mutated(*CONTAINER, "image", "localhost:5001/assume-hijacked@sha256:abc"),
    "image digest upper": mutated(*CONTAINER, "image", "localhost:5001/assume-hijacked@sha256:" + "A" * 64),
    "image with a space": mutated(*CONTAINER, "image", "evil @sha256:" + "a" * 64),
    "command": mutated(*CONTAINER, "command", ["sh", "-c", "env"]),
    "command extra": mutated(*CONTAINER, "command", ["python", "-m", "app.agent.main", "--x"]),
    "args": mutated(*CONTAINER, "args", ["--x"]),
    "env from a secret": mutated(*CONTAINER, "env", [{"name": "APP_ENV", "valueFrom": {"secretKeyRef": {"name": "s", "key": "k"}}}]),
    "env with a secret name": mutated(*CONTAINER, "env", [{"name": "DB_PASSWORD_GATEWAY", "value": "x"}]),
    "env twice": mutated(*CONTAINER, "env", [{"name": "APP_ENV", "value": "a"}, {"name": "APP_ENV", "value": "b"}]),
    "env value not text": mutated(*CONTAINER, "env", [{"name": "APP_ENV", "value": 5}]),
    "envFrom": mutated(*CONTAINER, "envFrom", [{"secretRef": {"name": "gateway-secrets"}}]),
    "privileged": mutated(*CONTAINER, "securityContext", "privileged", True),
    "escalation": mutated(*CONTAINER, "securityContext", "allowPrivilegeEscalation", True),
    "capability added": mutated(*CONTAINER, "securityContext", "capabilities", {"drop": ["ALL"], "add": ["NET_ADMIN"]}),
    "no drop all": mutated(*CONTAINER, "securityContext", "capabilities", {"drop": ["NET_RAW"]}),
    "writable root": mutated(*CONTAINER, "securityContext", "readOnlyRootFilesystem", False),
    "root user": mutated(*CONTAINER, "securityContext", "runAsUser", 0),
    "not non-root": mutated(*CONTAINER, "securityContext", "runAsNonRoot", False),
    "no seccomp": mutated(*CONTAINER, "securityContext", "seccompProfile", DELETE),
    "unconfined seccomp": mutated(*CONTAINER, "securityContext", "seccompProfile", {"type": "Unconfined"}),
    "pod root user": mutated(*SPEC, "securityContext", "runAsUser", 0),
    "pod securityContext gone": mutated(*SPEC, "securityContext", DELETE),
    "second container": mutated(*SPEC, "containers", [template()["spec"]["template"]["spec"]["containers"][0]] * 2),
    "container name": mutated(*CONTAINER, "name", "sidecar"),
    "init container": mutated(*SPEC, "initContainers", [{"name": "i", "image": "x"}]),
    "ephemeral container": mutated(*SPEC, "ephemeralContainers", [{"name": "i", "image": "x"}]),
    "host network": mutated(*SPEC, "hostNetwork", True),
    "host pid": mutated(*SPEC, "hostPID", True),
    "node name": mutated(*SPEC, "nodeName", "ah-control-plane"),
    "node selector": mutated(*SPEC, "nodeSelector", {"ah/pool": "system"}),
    "toleration": mutated(*SPEC, "tolerations", [{"operator": "Exists"}]),
    "priority class": mutated(*SPEC, "priorityClassName", "system-node-critical"),
    "dns config": mutated(*SPEC, "dnsConfig", {"nameservers": ["1.1.1.1"]}),
    "host aliases": mutated(*SPEC, "hostAliases", [{"ip": "1.1.1.1", "hostnames": ["x"]}]),
    "restart policy": mutated(*SPEC, "restartPolicy", "OnFailure"),
    "service links": mutated(*SPEC, "enableServiceLinks", True),
    "backoff": mutated("spec", "backoffLimit", 3),
    "deadline": mutated("spec", "activeDeadlineSeconds", 3600),
    "ttl": mutated("spec", "ttlSecondsAfterFinished", 86400),
    "manual selector": mutated("spec", "manualSelector", True),
    "parallelism": mutated("spec", "parallelism", 50),
    "completions": mutated("spec", "completions", 50),
    "namespace": mutated("metadata", "namespace", "ah-gateway"),
    "kind": mutated("kind", "CronJob"),
    "api version": mutated("apiVersion", "batch/v1beta1"),
    "owner": mutated("metadata", "ownerReferences", [{"kind": "Pod"}]),
    "annotation": mutated("metadata", "annotations", {"x": "y"}),
    "app label": mutated("metadata", "labels", "app.kubernetes.io/name", "tool-gateway"),
    "pod app label": mutated("spec", "template", "metadata", "labels", "app.kubernetes.io/name", "llm-gateway"),
    "extra label": mutated("metadata", "labels", "x", "y"),
    "no volumes": mutated(*SPEC, "volumes", DELETE),
    "secret volume": mutated(*SPEC, "volumes", [{"name": "ah-tokens", "secret": {"secretName": "gateway-secrets"}}]),
    "host path": mutated(*SPEC, "volumes", [{"name": "ah-tokens", "hostPath": {"path": "/"}}]),
    "token audience": mutated(*SPEC, "volumes", 0, "projected", "sources", 0, "serviceAccountToken", "audience", "https://kubernetes.default.svc"),
    "token lifetime": mutated(*SPEC, "volumes", 0, "projected", "sources", 0, "serviceAccountToken", "expirationSeconds", 86400),
    "token path": mutated(*SPEC, "volumes", 0, "projected", "sources", 0, "serviceAccountToken", "path", "../token"),
    "fourth token": mutated(*SPEC, "volumes", 0, "projected", "sources", TOKENS + [{"serviceAccountToken": {"audience": "x", "path": "x"}}]),
    "token for the api": mutated(*SPEC, "volumes", 0, "projected", "sources", TOKENS[:2] + [{"serviceAccountToken": {"path": "api/token"}}]),
    "secret source": mutated(*SPEC, "volumes", 0, "projected", "sources", TOKENS + [{"secret": {"name": "s"}}]),
    "mount path": mutated(*CONTAINER, "volumeMounts", [{"name": "ah-tokens", "mountPath": "/", "readOnly": True}]),
    "mount writable": mutated(*CONTAINER, "volumeMounts", [{"name": "ah-tokens", "mountPath": "/var/run/secrets/ah"}]),
    "mount subpath": mutated(*CONTAINER, "volumeMounts", [{"name": "ah-tokens", "mountPath": "/var/run/secrets/ah", "readOnly": True, "subPath": "x"}]),
    "second mount": mutated(*CONTAINER, "volumeMounts", [{"name": "ah-tokens", "mountPath": "/var/run/secrets/ah", "readOnly": True}] * 2),
    "pull policy": mutated(*CONTAINER, "imagePullPolicy", "Sometimes"),
    "resources": mutated(*CONTAINER, "resources", {"limits": {"cpu": "64"}}),
    "resources gpu": mutated(*CONTAINER, "resources", {"limits": {"nvidia.com/gpu": "1"}}),
    "lifecycle": mutated(*CONTAINER, "lifecycle", {"postStart": {"exec": {"command": ["id"]}}}),
    "ports": mutated(*CONTAINER, "ports", [{"containerPort": 80, "hostPort": 80}]),
    "workdir": mutated(*CONTAINER, "workingDir", "/"),
    "extra top key": mutated("status", {"x": 1}),
    "extra spec key": mutated("spec", "selector", {"matchLabels": {"a": "b"}}),
}


@pytest.mark.parametrize("name", list(MUTATIONS))
def test_a_changed_template_is_refused(name, tmp_path):
    job = MUTATIONS[name]
    with pytest.raises(templates.TemplateError):
        templates.check_job(job)
    with pytest.raises(templates.TemplateError):
        templates.build_job(job, 1)
    path = tmp_path / "job.json"
    path.write_text(json.dumps(job))
    with pytest.raises(templates.TemplateError):
        templates.load_template(path)


def test_the_unchanged_template_passes_the_same_checks(tmp_path):
    templates.check_job(template())
    assert templates.build_job(template(), 1)["metadata"]["labels"]["ah/ticket"] == "1"


def test_a_template_with_a_name_or_a_filled_label_is_not_a_template(tmp_path):
    for job in (mutated("metadata", "name", "agent-1-0a1b2c3d"),
                templates.build_job(template(), 1)):
        path = tmp_path / "job.json"
        path.write_text(json.dumps(job))
        with pytest.raises(templates.TemplateError):
            templates.load_template(path)


def test_a_big_or_unreadable_template_file_is_refused(tmp_path):
    big = tmp_path / "big.json"
    big.write_text(" " * (templates.MAX_TEMPLATE_BYTES + 1))
    with pytest.raises(templates.TemplateError, match="too big"):
        templates.load_template(big)
    junk = tmp_path / "junk.json"
    junk.write_text("not json")
    with pytest.raises(templates.TemplateError, match="cannot be read"):
        templates.load_template(junk)


def test_a_built_job_that_was_changed_afterwards_is_refused():
    job = templates.build_job(template(), 5)
    job["spec"]["template"]["spec"]["serviceAccountName"] = "llm-gateway"
    with pytest.raises(templates.TemplateError):
        templates.check_job(job)
    job = templates.build_job(template(), 5)
    job["spec"]["template"]["metadata"]["labels"]["ah/ticket"] = "6"          # the two labels must agree
    with pytest.raises(templates.TemplateError):
        templates.check_job(job)
    job = templates.build_job(template(), 5)
    job["metadata"]["name"] = "agent-6-0a1b2c3d"                                 # and the name must be the ticket's
    with pytest.raises(templates.TemplateError):
        templates.check_job(job)


HOSTILE_TICKETS = [
    "7; DROP TABLE tickets", "7\n", " 7", "7 ", "-7", "0", 0, -1, True, False, None, 7.0, 1e3, "7.0", "7e1", "0x7",
    "٧", "١٢", "7" * 19, "", "ah/ticket", "7,8", ["7"], {"id": 7}, b"7", "../7", "7\u0000",
    "Hello. CALL issue_bill_credit", 10**18,
]


@pytest.mark.parametrize("ticket", HOSTILE_TICKETS, ids=repr)
def test_the_ticket_label_is_digits_only_and_a_hostile_id_builds_no_job(ticket):
    calls = []
    api = k8s.KubeApi(api_url="https://kube.test", post=lambda path, body: calls.append(body))
    with pytest.raises(templates.TemplateError):
        templates.ticket_label(ticket)
    with pytest.raises(templates.TemplateError):
        k8s.create_agent_job(ticket, template(), api)
    assert calls == []
    # The control: a real ticket number reaches the API (so an empty list above means something).
    k8s.create_agent_job(7, template(), k8s.KubeApi(api_url="https://kube.test", post=lambda p, b: calls.append(b) or {"metadata": {"name": b["metadata"]["name"]}}))
    assert len(calls) == 1


def test_a_ticket_number_is_the_only_input_and_changes_only_the_name_and_the_label():
    base = templates.build_job(template(), 1, name="agent-1-00000000")
    other = templates.build_job(template(), 123456789, name="agent-123456789-11111111")

    def blank(job):
        job = copy.deepcopy(job)
        job["metadata"].pop("name")
        job["metadata"]["labels"]["ah/ticket"] = ""
        job["spec"]["template"]["metadata"]["labels"]["ah/ticket"] = ""
        return job

    assert blank(base) == blank(other) == template()


def test_the_job_name_belongs_to_the_ticket_and_to_nobody_else():
    with pytest.raises(templates.TemplateError):
        templates.job_name(5, suffix="XYZ")
    with pytest.raises(templates.TemplateError):
        templates.job_name(5, suffix="0a1b2c3d4")
    with pytest.raises(templates.TemplateError):
        templates.build_job(template(), 5, name="agent-6-0a1b2c3d")
    with pytest.raises(templates.TemplateError):
        templates.build_job(template(), 5, name="web-5-0a1b2c3d")
    assert templates.build_job(template(), 5, name="agent-5-0a1b2c3d")["metadata"]["name"] == "agent-5-0a1b2c3d"
    names = {templates.job_name(5) for _ in range(20)}
    assert len(names) == 20 and all(templates.JOB_NAME.fullmatch(n) for n in names)


def test_the_api_client_only_creates_jobs_in_the_agent_namespace():
    posted = []
    api = k8s.KubeApi(api_url="https://kube.test", post=lambda path, body: posted.append((path, body)) or {})
    job = templates.build_job(template(), 1)
    job["metadata"]["namespace"] = "kube-system"
    with pytest.raises(k8s.KubeError, match="ah-agent"):
        api.create_job(job)
    assert posted == []
    job["metadata"]["namespace"] = "ah-agent"
    api.create_job(job)
    assert [p for p, _ in posted] == ["/apis/batch/v1/namespaces/ah-agent/jobs"]


def test_an_api_error_is_one_error_without_the_job_or_the_api_text():
    def refuse(path, body):
        raise OSError("HTTP Error 403: Forbidden jobs.batch is forbidden: User system:serviceaccount:ah-intake:dispatcher")

    api = k8s.KubeApi(api_url="https://kube.test", post=refuse)
    with pytest.raises(k8s.KubeError) as err:
        k8s.create_agent_job(1, template(), api)
    assert "forbidden" not in str(err.value).lower() and "OSError" in str(err.value)


def test_the_api_client_posts_json_with_its_own_token_over_https(tmp_path, monkeypatch):
    (tmp_path / "token").write_text("sa-token\n")
    seen = {}

    class Answer:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, n):
            return b'{"metadata": {"name": "agent-1-0a1b2c3d"}}'

    def fake_urlopen(req, timeout, context):
        seen.update(url=req.full_url, auth=req.get_header("Authorization"), method=req.get_method(),
                    body=json.loads(req.data), timeout=timeout, context=context)
        return Answer()

    monkeypatch.setattr(k8s.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(k8s.ssl, "create_default_context", lambda cafile: ("context", cafile))
    api = k8s.KubeApi(api_url="https://10.96.0.1:443", sa_dir=str(tmp_path))
    assert k8s.create_agent_job(1, template(), api, name="agent-1-0a1b2c3d") == "agent-1-0a1b2c3d"
    assert seen["url"] == "https://10.96.0.1:443/apis/batch/v1/namespaces/ah-agent/jobs"
    assert seen["auth"] == "Bearer sa-token" and seen["method"] == "POST"
    assert seen["context"] == ("context", str(tmp_path / "ca.crt"))
    assert seen["body"]["metadata"]["labels"]["ah/ticket"] == "1"


def test_pod_names_map_to_job_names_only_in_the_shape_the_job_controller_makes():
    assert templates.pod_job_name("agent-12-0a1b2c3d-x7k2p") == "agent-12-0a1b2c3d"
    for bad in ("agent-12-0a1b2c3d", "agent-12-0a1b2c3d-x7k2", "agent-12-0a1b2c3d-x7k2pq", "agent--0a1b2c3d-x7k2p",
                "agent-12-0A1B2C3D-x7k2p", "agent-12-0a1b2c3d-X7K2P", None, 5, ""):
        assert templates.pod_job_name(bad) is None, bad


# --- the database ---------------------------------------------------------------------------------


def test_the_dispatcher_role_has_column_grants_and_no_more(admin, as_role):
    conn = as_role("dispatcher")
    tables = admin.execute(
        "SELECT table_name, privilege_type FROM information_schema.role_table_grants "
        "WHERE grantee = 'dispatcher' AND table_schema = 'public' ORDER BY 1, 2"
    ).fetchall()
    assert tables == []                                                 # no table-wide privilege at all
    columns = admin.execute(
        "SELECT table_name, column_name, privilege_type FROM information_schema.column_privileges "
        "WHERE grantee = 'dispatcher' AND table_schema = 'public' ORDER BY 1, 3, 2"
    ).fetchall()
    found = {}
    for row in columns:
        found.setdefault((row["table_name"], row["privilege_type"]), []).append(row["column_name"])
    assert found == {
        ("agent_runs", "INSERT"): ["job_name", "status", "ticket_id"],
        ("agent_runs", "SELECT"): ["created_at", "id", "job_name", "status", "ticket_id"],
        ("agent_runs", "UPDATE"): ["lease_hash", "status"],
        ("replies", "INSERT"): ["text", "ticket_id"],
        ("replies", "SELECT"): ["ticket_id"],
        ("tickets", "SELECT"): ["id", "status"],
    }
    # What it cannot do, tried as the role.
    for sql in (
        "SELECT body FROM tickets",
        "SELECT * FROM customers",
        "SELECT * FROM accounts",
        "SELECT * FROM tool_calls",
        "SELECT * FROM leases",
        "SELECT lease_hash FROM agent_runs",
        "SELECT text FROM replies",
        "UPDATE replies SET text = 'x'",
        "DELETE FROM replies",
        "DELETE FROM agent_runs",
        "UPDATE tickets SET status = 'closed'",
        "INSERT INTO agent_runs (ticket_id, lease_hash, status) VALUES (1, '\\x01', 'claimed')",
        "INSERT INTO action_requests (kind, ticket_id, account_id) VALUES ('move_out', 1, 1)",
    ):
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute(sql)
    # And what it can (the controls).
    assert conn.execute("SELECT id, status FROM tickets ORDER BY id").fetchall()[0] == {"id": 1, "status": "open"}
    assert conn.execute("INSERT INTO replies (ticket_id, text) VALUES (1, 'x') RETURNING ticket_id").fetchone() == {"ticket_id": 1}


@pytest.mark.parametrize("role", [*[f"tool_{t}" for t in TOOLS], "gateway", "risk_engine", "executor", "register_sync"])
def test_no_other_role_can_use_the_runs_the_replies_or_reply_facts(admin, as_role, role):
    conn = as_role(role)
    lease = open_lease(admin, 1)
    for sql, args in (
        ("SELECT * FROM agent_runs", ()),
        ("SELECT * FROM replies", ()),
        ("INSERT INTO replies (ticket_id, text) VALUES (1, 'x')", ()),
        ("INSERT INTO agent_runs (ticket_id, status) VALUES (1, 'started')", ()),
        ("SELECT * FROM reply_facts(%s)", (lease,)),
    ):
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute(sql, args)
    assert admin.execute("SELECT count(*) AS n FROM replies").fetchone()["n"] == 0


def test_row_level_security_is_on_for_the_dispatchers_tables_and_names_no_tool_role(admin):
    rows = admin.execute(
        "SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity FROM pg_class c "
        "WHERE c.relname IN ('agent_runs', 'replies') ORDER BY 1"
    ).fetchall()
    assert [(r["relname"], r["relrowsecurity"], r["relforcerowsecurity"]) for r in rows] == [
        ("agent_runs", True, True), ("replies", True, True)]
    for table in ("agent_runs", "replies"):
        policy = admin.execute(
            "SELECT roles FROM pg_policies WHERE tablename = %s AND policyname = 'trusted_all'", (table,)
        ).fetchone()
        assert "dispatcher" in policy["roles"] and not [r for r in policy["roles"] if r.startswith("tool_")]


def test_reply_facts_for_a_live_lease_and_nothing_else(admin, as_role):
    lease = open_lease(admin, 1)
    other = open_lease(admin, 2)
    tool_call(admin, lease, "issue_bill_credit", "denied")
    tool_call(admin, lease, "request_disconnection", "tool_error")
    tool_call(admin, other, "request_disconnection", "ok")
    conn = as_role("dispatcher")
    row = conn.execute("SELECT * FROM reply_facts(%s)", (lease,)).fetchone()
    assert row == {"account_text": "G1 residential active Patision 10, Athens", "credit_asked": True,
                   "moveout_submitted": False}
    assert conn.execute("SELECT * FROM reply_facts(%s)", (other,)).fetchone()["moveout_submitted"] is True
    admin.execute("UPDATE leases SET revoked = true WHERE token_hash = sha256(convert_to(%s, 'UTF8'))", (lease,))
    assert conn.execute("SELECT * FROM reply_facts(%s)", (lease,)).fetchall() == []
    assert conn.execute("SELECT * FROM reply_facts(%s)", ("nonsense",)).fetchall() == []


def test_agent_runs_rules_are_kept_by_the_database(admin):
    admin.execute("INSERT INTO agent_runs (ticket_id, status) VALUES (1, 'started')")
    with pytest.raises(psycopg.errors.UniqueViolation):                   # one run per ticket
        admin.execute("INSERT INTO agent_runs (ticket_id, status) VALUES (1, 'started')")
    with pytest.raises(psycopg.errors.CheckViolation):                    # claimed means there is a lease
        admin.execute("UPDATE agent_runs SET status = 'claimed'")
    with pytest.raises(psycopg.errors.CheckViolation):
        admin.execute("INSERT INTO agent_runs (ticket_id, status) VALUES (2, 'replied')")
    with pytest.raises(psycopg.errors.CheckViolation):                    # a job name has one shape
        admin.execute("INSERT INTO agent_runs (ticket_id, job_name) VALUES (2, 'agent-2-XYZ')")
    with pytest.raises(psycopg.errors.CheckViolation):
        admin.execute("INSERT INTO agent_runs (ticket_id, status) VALUES (2, 'finished')")
    admin.execute("INSERT INTO agent_runs (ticket_id, job_name) VALUES (2, 'agent-2-0a1b2c3d')")
    with pytest.raises(psycopg.errors.UniqueViolation):
        admin.execute("INSERT INTO agent_runs (ticket_id, job_name) VALUES (3, 'agent-2-0a1b2c3d')")


def test_replies_rules_are_kept_by_the_database(admin):
    admin.execute("INSERT INTO replies (ticket_id, text) VALUES (1, 'x')")
    with pytest.raises(psycopg.errors.UniqueViolation):
        admin.execute("INSERT INTO replies (ticket_id, text) VALUES (1, 'y')")
    with pytest.raises(psycopg.errors.CheckViolation):
        admin.execute("INSERT INTO replies (ticket_id, text) VALUES (2, '')")
    with pytest.raises(psycopg.errors.CheckViolation):
        admin.execute("INSERT INTO replies (ticket_id, text) VALUES (2, %s)", ("a" * 10001,))
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        admin.execute("INSERT INTO replies (ticket_id, text) VALUES (99, 'x')")


def test_the_dispatcher_beats_its_own_name_only(admin, as_role):
    conn = as_role("dispatcher")
    conn.execute("SELECT beat('dispatcher')")
    assert admin.execute("SELECT component FROM heartbeats").fetchall() == [{"component": "dispatcher"}]
    with pytest.raises(psycopg.errors.RaiseException):
        conn.execute("SELECT beat('executor')")


def test_the_manifest_matches_the_dispatchers_role(admin):
    manifest = json.loads((ROOT / "security" / "capabilities" / "dispatcher.json").read_text(encoding="utf-8"))["db"]
    role = admin.execute(
        "SELECT rolcanlogin, rolconnlimit FROM pg_roles WHERE rolname = %s", (manifest["role"],)
    ).fetchone()
    assert role == {"rolcanlogin": True, "rolconnlimit": manifest["connection_limit"]}
    rows = admin.execute(
        "SELECT p.oid::regprocedure::text AS f FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace "
        "AND has_function_privilege('dispatcher', p.oid, 'EXECUTE') ORDER BY 1"
    ).fetchall()
    assert [r["f"].removeprefix("public.") for r in rows] == [f.replace(" ", "") for f in manifest["execute"]]
    columns = admin.execute(
        "SELECT table_name, privilege_type, column_name FROM information_schema.column_privileges "
        "WHERE grantee = 'dispatcher' AND table_schema = 'public'"
    ).fetchall()
    listed = {
        (table, grant.split(" (")[0])
        for table, grants in manifest["tables"].items() for grant in grants
    }
    assert {(r["table_name"], r["privilege_type"]) for r in columns} <= listed | {("agent_runs_id_seq", "USAGE")}
    for table, grants in manifest["tables"].items():
        for grant in grants:
            kind, _, cols = grant.partition(" (")
            if cols:
                have = sorted(r["column_name"] for r in columns if r["table_name"] == table and r["privilege_type"] == kind)
                assert have == sorted(c.strip() for c in cols.rstrip(")").split(",")), (table, kind)


def test_the_resources_of_the_chart_pass_and_big_ones_do_not():
    job = template()
    for resources in (
        {"limits": {"cpu": "500m", "memory": "256Mi"}, "requests": {"cpu": "50m", "memory": "64Mi"}},
        {"limits": {"cpu": "2", "memory": "1Gi"}},
        {},
    ):
        job["spec"]["template"]["spec"]["containers"][0]["resources"] = resources
        templates.check_job(job)
    for resources in (
        {"limits": {"cpu": "2001m"}}, {"limits": {"cpu": "3"}}, {"limits": {"memory": "2Gi"}},
        {"limits": {"memory": "1025Mi"}}, {"limits": {"cpu": "0.5"}}, {"limits": {"cpu": 1}}, {"claims": []},
        {"limits": {"ephemeral-storage": "1Gi"}}, [],
    ):
        job["spec"]["template"]["spec"]["containers"][0]["resources"] = resources
        with pytest.raises(templates.TemplateError):
            templates.check_job(job)
