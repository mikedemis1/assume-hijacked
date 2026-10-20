"""The two database roles of the demo UI (db/sql/09-demo.sql): demo_portal opens a ticket for one
customer and reads the reply to that customer's own tickets, and nothing else; demo_ops reads the
audit tables by column and never ticket text, customer data, flags or argument values."""

import psycopg
import pytest

from tests.conftest import open_lease


def refused(conn, statement, args=()):
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        conn.execute(statement, args)


# --- demo_portal ---------------------------------------------------------------------------------

@pytest.mark.parametrize("table", [
    "tickets", "replies", "customers", "accounts", "supply_points", "charges", "flags", "action_requests",
    "tool_calls", "agent_runs", "leases", "risk_assessments", "call_assessments", "events", "approvals",
    "demo_tickets", "demo_customers",
])
def test_the_portal_role_reads_no_table(as_role, table):
    refused(as_role("demo_portal"), f"SELECT * FROM {table}")


def test_the_portal_role_writes_no_table(as_role):
    conn = as_role("demo_portal")
    refused(conn, "INSERT INTO tickets (id, customer_id, body) VALUES (5000, 1001, 'x')")
    refused(conn, "INSERT INTO replies (ticket_id, text, kind) VALUES (1, 'x', 'agent')")
    refused(conn, "UPDATE tickets SET customer_id = 1002")
    refused(conn, "SELECT nextval('demo_ticket_id_seq')")


@pytest.mark.parametrize("call", [
    "demo_request_errors(ARRAY[1])", "open_lease(1, ARRAY['read_ticket'], NULL)", "lease_scope('x')",
    "finish_reply_facts('x', 'y')", "beat('demo')", "pause_agents('x')",
    "resume_agents('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'::uuid)",
    "approve_request(1, 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'::uuid)",
    "record_agent_events('x', 'y', '[]'::jsonb)",
])
def test_the_portal_role_runs_no_other_function(as_role, call):
    refused(as_role("demo_portal"), f"SELECT * FROM {call}")


def test_the_portal_lists_the_demo_customers_by_id_and_name_only(admin, as_role):
    conn = as_role("demo_portal")
    expected = [{"id": 1001, "name": "Eleni Papadopoulou"}, {"id": 1002, "name": "Nikos Georgiou"},
                {"id": 1003, "name": "Maria Ioannou"}]
    assert conn.execute("SELECT * FROM portal_customers()").fetchall() == expected
    # A customer that is not a demo customer is neither listed nor given a ticket.
    admin.execute("INSERT INTO customers VALUES (2000, 'Real Customer', '+30 690 000 2000')")
    assert conn.execute("SELECT * FROM portal_customers()").fetchall() == expected
    with pytest.raises(psycopg.errors.RaiseException):
        conn.execute("SELECT portal_open_ticket(2000, 'Hello')")


def test_a_ticket_is_opened_for_the_customer_given_and_above_the_seed_ids(admin, as_role):
    conn = as_role("demo_portal")
    first = conn.execute("SELECT portal_open_ticket(1002, 'Hello there') AS id").fetchone()["id"]
    second = conn.execute("SELECT portal_open_ticket(1001, 'And again') AS id").fetchone()["id"]
    assert 1000 <= first < second
    rows = admin.execute("SELECT id, customer_id, body, status FROM tickets WHERE id >= 1000 ORDER BY id").fetchall()
    assert rows == [{"id": first, "customer_id": 1002, "body": "Hello there", "status": "open"},
                    {"id": second, "customer_id": 1001, "body": "And again", "status": "open"}]
    marked = admin.execute("SELECT ticket_id, customer_id FROM demo_tickets ORDER BY ticket_id").fetchall()
    assert marked == [{"ticket_id": first, "customer_id": 1002}, {"ticket_id": second, "customer_id": 1001}]


@pytest.mark.parametrize("customer, body", [
    (1001, ""), (1001, "   \n "), (1001, None), (1001, "x" * 2001), (9999, "Hello"), (None, "Hello"),
])
def test_a_ticket_with_no_text_a_long_text_or_no_such_customer_is_refused(admin, as_role, customer, body):
    with pytest.raises((psycopg.errors.RaiseException, psycopg.errors.NotNullViolation)):
        as_role("demo_portal").execute("SELECT portal_open_ticket(%s, %s)", (customer, body))
    assert admin.execute("SELECT count(*) AS n FROM tickets WHERE id >= 1000").fetchone()["n"] == 0
    assert admin.execute("SELECT count(*) AS n FROM demo_tickets").fetchone()["n"] == 0


def test_the_longest_message_is_taken(admin, as_role):
    ticket = as_role("demo_portal").execute("SELECT portal_open_ticket(1001, %s) AS id", ("x" * 2000,)).fetchone()["id"]
    assert admin.execute("SELECT length(body) AS n FROM tickets WHERE id = %s", (ticket,)).fetchone()["n"] == 2000


def test_a_customer_reads_the_reply_to_their_own_ticket_and_nobody_else_does(admin, as_role):
    conn = as_role("demo_portal")
    mine = conn.execute("SELECT portal_open_ticket(1001, 'Mine') AS id").fetchone()["id"]
    pending = conn.execute("SELECT portal_open_ticket(1001, 'No answer yet') AS id").fetchone()["id"]
    admin.execute("INSERT INTO replies (ticket_id, text, kind) VALUES (%s, 'Your tariff is G1.', 'agent')", (mine,))
    admin.execute("INSERT INTO replies (ticket_id, text, kind) VALUES (1, 'A seeded ticket of customer 1001.', 'agent')")

    def reply(customer, ticket):
        return conn.execute("SELECT text FROM portal_reply(%s, %s)", (customer, ticket)).fetchall()

    assert reply(1001, mine) == [{"text": "Your tariff is G1."}]
    # Control: the same ticket for another customer, a ticket still being answered, a seeded
    # ticket of the same customer's id range, and a ticket that does not exist look the same: no row.
    assert reply(1002, mine) == []
    assert reply(1001, pending) == []
    assert reply(1002, 1) == []
    assert reply(1001, 424242) == []
    # Only tickets the demo opened are answered here: not a seeded ticket of the same customer
    # (ticket 1 belongs to 1001 and has a reply above), and not one filed some other way, even
    # in the demo's id range and for the same customer.
    assert reply(1001, 1) == []
    other = admin.execute("INSERT INTO tickets (id, customer_id, body) VALUES (1500, 1001, 'filed by hand') RETURNING id").fetchone()["id"]
    admin.execute("INSERT INTO replies (ticket_id, text, kind) VALUES (%s, 'A reply the demo did not ask for.', 'agent')", (other,))
    assert reply(1001, other) == []


# --- demo_ops ------------------------------------------------------------------------------------

@pytest.mark.parametrize("statement", [
    "SELECT id, status FROM tickets",
    "SELECT reasons FROM call_assessments",
    "SELECT * FROM demo_tickets",
    "SELECT * FROM demo_customers",
    "SELECT body FROM tickets",
    "SELECT customer_id FROM tickets",
    "SELECT text FROM replies",
    "SELECT * FROM customers",
    "SELECT * FROM accounts",
    "SELECT * FROM supply_points",
    "SELECT * FROM charges",
    "SELECT * FROM flags",
    "SELECT * FROM leases",
    "SELECT * FROM events",
    "SELECT approver FROM approvals",
    "SELECT job_name FROM agent_runs",
    "SELECT actor FROM tool_calls",
    "SELECT reason FROM action_requests",
    "SELECT evidence_ref, move_out_date, account_id FROM action_requests",
    "SELECT score, engine_version, actor FROM risk_assessments",
    "SELECT paused FROM agent_control",
    "SELECT * FROM heartbeats",
])
def test_the_ops_role_cannot_read_text_customer_data_flags_or_other_columns(as_role, statement):
    refused(as_role("demo_ops"), statement)


def test_the_ops_role_reads_the_audit_columns_and_writes_nothing(as_role):
    conn = as_role("demo_ops")
    for statement in (
        "SELECT ticket_id, lease_hash, status, created_at FROM agent_runs",
        "SELECT id, lease_hash, tool, arg_names, dropped_args, outcome, reason, created_at FROM tool_calls",
        "SELECT id, lease_hash, tool, decision, created_at FROM call_assessments",
        "SELECT id, kind, ticket_id, amount_eur, status, decision_reason, created_at FROM action_requests",
        "SELECT request_id, tier, reasons, created_at FROM risk_assessments",
        "SELECT ticket_id, created_at FROM replies", "SELECT request_id, created_at FROM credits",
        "SELECT request_id, created_at FROM disconnection_orders",
        "SELECT request_id, approver_role, created_at FROM approvals",
    ):
        conn.execute(statement).fetchall()
    refused(conn, "INSERT INTO tool_calls (lease_hash, tool, arg_names, dropped_args, outcome) "
                  "VALUES ('\\x00', 'x', '{}', '{}', 'ok')")
    refused(conn, "UPDATE tickets SET status = 'closed'")
    refused(conn, "DELETE FROM replies")
    refused(conn, "SELECT portal_open_ticket(1001, 'x')")
    refused(conn, "SELECT * FROM portal_reply(1001, 1)")
    refused(conn, "SELECT * FROM portal_customers()")
    refused(conn, "SELECT open_lease(1, ARRAY['read_ticket'], NULL)")


def test_request_errors_show_the_request_id_and_the_error_class_only(admin, as_role):
    admin.execute("INSERT INTO events (kind, detail) VALUES ('executor_error', 'credit request=7: RaiseException')")
    admin.execute("INSERT INTO events (kind, detail) VALUES ('executor_error', 'move_out request=8: CheckViolation')")
    # Other events and other shapes of detail are not shown, whatever they hold.
    admin.execute("INSERT INTO events (kind, detail) VALUES ('ALERT', 'credit request=7: Secret')")
    admin.execute("INSERT INTO events (kind, detail) VALUES ('executor_error', 'credit request=7: Eleni 1001 +30 690')")
    admin.execute("INSERT INTO events (kind, detail) VALUES ('executor_error', 'credit request=9: RaiseException')")
    rows = as_role("demo_ops").execute(
        "SELECT request_id, error FROM demo_request_errors(ARRAY[7, 8]) ORDER BY request_id").fetchall()
    assert rows == [{"request_id": 7, "error": "RaiseException"}, {"request_id": 8, "error": "CheckViolation"}]


def test_a_run_ties_a_ticket_to_the_calls_of_its_lease_by_hash_only(admin, as_role):
    lease = open_lease(admin, 1)
    admin.execute("INSERT INTO agent_runs (ticket_id, status) VALUES (1, 'started')")
    admin.execute("UPDATE agent_runs SET lease_hash = sha256(%s::bytea), status = 'claimed' WHERE ticket_id = 1",
                  (lease.encode(),))
    admin.execute("INSERT INTO tool_calls (lease_hash, tool, arg_names, dropped_args, outcome, reason) "
                  "VALUES (sha256(%s::bytea), 'lookup_account', '{}', '{customer_id}', 'ok', '')", (lease.encode(),))
    conn = as_role("demo_ops")
    run = conn.execute("SELECT lease_hash FROM agent_runs WHERE ticket_id = 1").fetchone()
    calls = conn.execute("SELECT tool, dropped_args FROM tool_calls WHERE lease_hash = %s", (run["lease_hash"],)).fetchall()
    assert calls == [{"tool": "lookup_account", "dropped_args": ["customer_id"]}]


def test_the_panel_reads_agent_events_by_name_and_reply_kind_but_never_reply_text(admin, as_role):
    ticket = as_role("demo_portal").execute("SELECT portal_open_ticket(1001, 'Mine') AS id").fetchone()["id"]
    admin.execute("INSERT INTO agent_events (ticket_id, lease_hash, kind, tool, arg_names) "
                  "VALUES (%s, '\x02'::bytea, 'dropped_argument', 'lookup_account', ARRAY['customer_id'])", (ticket,))
    admin.execute("INSERT INTO replies (ticket_id, text, kind) VALUES (%s, 'Secret words', 'template')", (ticket,))
    ops = as_role("demo_ops")
    assert ops.execute("SELECT kind, tool, arg_names FROM agent_events").fetchall() == [
        {"kind": "dropped_argument", "tool": "lookup_account", "arg_names": ["customer_id"]}]
    assert ops.execute("SELECT kind FROM replies").fetchall() == [{"kind": "template"}]
    refused(ops, "SELECT text FROM replies")
    refused(ops, "INSERT INTO agent_events (ticket_id, lease_hash, kind, tool, arg_names) VALUES (1, '\x03'::bytea, 'unknown_tool', 'x', '{}')")
