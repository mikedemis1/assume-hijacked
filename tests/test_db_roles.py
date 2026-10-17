import os
import time
import uuid

import psycopg
import pytest
from psycopg.rows import dict_row

from tests.conftest import STACK_DB_NAME, open_lease, reset_db

TOOL_ROLES = [
    "tool_read_ticket",
    "tool_lookup_account",
    "tool_request_disconnection",
    "tool_issue_bill_credit",
    "tool_set_temp_protection",
]


def _login_roles(admin, *, exclude=()):
    rows = admin.execute("SELECT rolname FROM pg_roles WHERE rolcanlogin ORDER BY rolname").fetchall()
    return [r["rolname"] for r in rows if r["rolname"] not in exclude]


def test_only_executor_can_read_flags(admin, as_role):  # ②
    # Every login role in the database, so a role added later is checked without editing this test.
    roles = _login_roles(admin, exclude=("postgres", "executor"))
    assert set(TOOL_ROLES + ["approver"]) <= set(roles)
    for role in roles:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            as_role(role).execute("SELECT * FROM flags")


@pytest.mark.parametrize("role", TOOL_ROLES)
def test_tools_cannot_change_flags_directly(as_role, role):  # ③
    conn = as_role(role)
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        conn.execute("DELETE FROM flags")
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        conn.execute("INSERT INTO flags (supply_point_id, source) VALUES ('SP-1001', 'x')")


@pytest.mark.parametrize("role", TOOL_ROLES)
def test_tools_cannot_order_disconnections(as_role, role):  # ⑦
    conn = as_role(role)
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        conn.execute(
            "INSERT INTO disconnection_orders (request_id, supply_point_id, created_at) "
            "VALUES (1, 'SP-1003', now())"
        )


@pytest.mark.parametrize("role", TOOL_ROLES + ["executor", "approver"])
@pytest.mark.parametrize("statement", ["DELETE FROM events", "UPDATE events SET detail = ''", "TRUNCATE events"])
def test_nobody_can_erase_the_audit_trail(as_role, role, statement):
    conn = as_role(role)
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        conn.execute(statement)


@pytest.mark.parametrize("role", TOOL_ROLES + ["approver"])
@pytest.mark.parametrize("column, value", [("actor", "executor"), ("created_at", "2099-01-01")])
def test_events_actor_and_time_cannot_be_forged(as_role, role, column, value):
    conn = as_role(role)
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        conn.execute(
            f"INSERT INTO events (kind, detail, {column}) VALUES ('ALERT', 'move-out rate limit reached', %s)",
            (value,),
        )


def test_tool_cannot_create_temp_tables_to_shadow_function_tables(as_role):
    conn = as_role("tool_set_temp_protection")
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        conn.execute("CREATE TEMP TABLE tickets (id int, customer_id int, body text, status text)")


def test_tool_cannot_insert_request_status(as_role):
    conn = as_role("tool_issue_bill_credit")
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        conn.execute(
            "INSERT INTO action_requests (kind, ticket_id, account_id, status) "
            "VALUES ('credit', 1, 1, 'executed')"
        )


def _password_of(role):
    return os.environ["POSTGRES_PASSWORD" if role == "postgres" else f"DB_PASSWORD_{role.upper()}"]


def test_each_role_has_its_own_password(admin, settings):
    roles = _login_roles(admin)
    assert len(roles) >= 8  # postgres, 5 tools, executor, approver
    accepted = []
    for owner in roles:
        for other in roles:
            if owner == other:
                continue
            try:
                psycopg.connect(
                    host=settings.db_host,
                    port=settings.db_port,
                    dbname=settings.db_name,
                    user=other,
                    password=_password_of(owner),
                ).close()
            except psycopg.OperationalError:
                continue
            accepted.append(f"{other} accepted the password of {owner}")
    assert accepted == []


# A tool role cannot insert a request at all (no table grants), and each api function sets its
# own kind, so the credit tool has no way to file a move-out and the other way round.
def test_credit_tool_cannot_file_a_move_out(as_role, admin):
    conn = as_role("tool_issue_bill_credit")
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        conn.execute(
            "INSERT INTO action_requests (kind, ticket_id, account_id, move_out_date) "
            "VALUES ('move_out', 1, 1, current_date + 14)"
        )
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        conn.execute("SELECT api_request_moveout(%s, current_date + 14)", (open_lease(admin, 1),))


def test_disconnection_tool_cannot_file_a_credit(as_role, admin):
    conn = as_role("tool_request_disconnection")
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        conn.execute(
            "INSERT INTO action_requests (kind, ticket_id, account_id, amount_eur, reason, evidence_ref) "
            "VALUES ('credit', 1, 1, 49, 'duplicate_charge', 2)"
        )
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        conn.execute("SELECT api_request_credit(%s, 49, 'duplicate_charge', 2)", (open_lease(admin, 1),))


@pytest.mark.parametrize(
    "session_role, values",
    [
        ("tool_issue_bill_credit", "('move_out', 1, 1, NULL, current_date + 14)"),
        ("tool_request_disconnection", "('credit', 1, 1, 49, NULL)"),
    ],
)
def test_request_trigger_still_checks_the_kind_by_calling_tool(admin, session_role, values):
    # The backstop behind the api functions: should a tool role ever get an INSERT grant by
    # mistake, check_action_request still refuses the other kind. It looks at session_user, which
    # stays the tool role inside the api functions (current_user is their owner there).
    with admin.transaction():
        admin.execute(f"GRANT INSERT ON action_requests TO {session_role}")
        admin.execute(f"GRANT USAGE ON SEQUENCE action_requests_id_seq TO {session_role}")
        admin.execute(f"SET SESSION AUTHORIZATION {session_role}")
        with pytest.raises(psycopg.errors.RaiseException, match="cannot file"):
            with admin.transaction():
                admin.execute(
                    "INSERT INTO action_requests (kind, ticket_id, account_id, amount_eur, move_out_date) "
                    f"VALUES {values}"
                )
        admin.execute("RESET SESSION AUTHORIZATION")
        raise psycopg.Rollback


@pytest.mark.parametrize(
    "role, call",
    [
        ("tool_issue_bill_credit", "SELECT api_request_credit(%s, 49, 'duplicate_charge', 7)"),
        ("tool_request_disconnection", "SELECT api_request_moveout(%s, current_date + 14)"),
    ],
)
def test_request_account_comes_from_the_ticket_owner(as_role, admin, role, call):
    # The api functions take no account or ticket argument: both come from the lease. Evidence 7
    # is a charge on account 2; the request is still for ticket 1's account.
    as_role(role).execute(call, (open_lease(admin, 1),))
    row = admin.execute("SELECT ticket_id, account_id FROM action_requests").fetchone()
    assert row == {"ticket_id": 1, "account_id": 1}


@pytest.mark.parametrize("amount", ["0", "-5", "NaN"])
def test_request_amount_must_be_a_positive_number(as_role, admin, amount):
    conn = as_role("tool_issue_bill_credit")
    with pytest.raises(psycopg.errors.RaiseException, match="positive finite number"):
        conn.execute(
            "SELECT api_request_credit(%s, %s::numeric, 'duplicate_charge', 2)", (open_lease(admin, 1), amount)
        )
    # Behind the function's own check, the column constraint refuses them even from the superuser.
    with pytest.raises(psycopg.errors.CheckViolation):
        admin.execute(
            "INSERT INTO action_requests (kind, ticket_id, account_id, amount_eur) VALUES ('credit', 1, 1, %s::numeric)",
            (amount,),
        )


@pytest.mark.parametrize("reason", ["because I said so", "DUPLICATE_CHARGE"])
def test_request_reason_must_be_on_the_closed_list_in_the_database_too(as_role, admin, reason):
    # The tool code checks the reason first; a hijacked tool process could skip that check.
    with pytest.raises(psycopg.errors.RaiseException, match="reason"):
        as_role("tool_issue_bill_credit").execute(
            "SELECT api_request_credit(%s, 49, %s, 2)", (open_lease(admin, 1), reason)
        )


@pytest.mark.parametrize("role", ["tool_lookup_account", "tool_request_disconnection", "tool_issue_bill_credit"])
def test_only_read_ticket_can_read_the_ticket_body(as_role, admin, role):
    lease = open_lease(admin, 1)
    conn = as_role(role)
    # Not the table, not even who owns a ticket, and not read_ticket's function.
    for query, params in [
        ("SELECT id, customer_id FROM tickets", None),
        ("SELECT body FROM tickets", None),
        ("SELECT * FROM api_read_ticket(%s)", (lease,)),
    ]:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute(query, params)
    body = as_role("tool_read_ticket").execute("SELECT body FROM api_read_ticket(%s)", (lease,)).fetchone()
    assert body == {"body": "What is my tariff?"}


def test_one_account_per_customer(admin):
    with pytest.raises(psycopg.errors.UniqueViolation):
        admin.execute("INSERT INTO accounts VALUES (4, 1001, 'SP-1002', 'G1 residential', 'active')")


def test_stack_database_is_untouched_by_the_suite(settings, admin, as_role):
    # The suite resets and writes only supplier_test. A row in the stack database must survive
    # a full reset and a write through a role connection; if the suite were pointed at the
    # stack database, the TRUNCATE would remove it.
    # Side effect: as superuser it briefly writes one sentinel row (kind TEST_SENTINEL) to
    # supplier.events, the stack's own audit table, and deletes it again in `finally`.
    assert settings.db_name != STACK_DB_NAME
    assert admin.execute("SELECT current_database() AS db").fetchone()["db"] == settings.db_name
    marker = uuid.uuid4().hex  # unique per run, so rows left in the stack database by an earlier run do not matter
    stack = psycopg.connect(
        host=settings.db_host,
        port=settings.db_port,
        dbname=STACK_DB_NAME,
        user="postgres",
        password=os.environ["POSTGRES_PASSWORD"],
        autocommit=True,
        row_factory=dict_row,
    )
    try:
        stack.execute("INSERT INTO events (kind, detail) VALUES ('TEST_SENTINEL', %s)", (marker,))
        reset_db(admin)
        as_role("executor").execute("INSERT INTO events (kind, detail) VALUES ('TEST_WRITE', %s)", (marker,))
        in_stack = stack.execute("SELECT kind FROM events WHERE detail = %s", (marker,)).fetchall()
        in_test = admin.execute("SELECT kind FROM events WHERE detail = %s", (marker,)).fetchall()
        assert in_stack == [{"kind": "TEST_SENTINEL"}]
        assert in_test == [{"kind": "TEST_WRITE"}]
    finally:
        stack.execute("DELETE FROM events WHERE detail = %s", (marker,))
        stack.close()


@pytest.mark.parametrize(
    "role, query",
    [
        ("tool_lookup_account", "SELECT phone FROM customers"),  # gap I7: the tool never returns phone
        ("tool_read_ticket", "SELECT customer_id FROM tickets"),
        ("tool_request_disconnection", "SELECT supply_point_id FROM accounts"),
        ("tool_issue_bill_credit", "SELECT supply_point_id FROM accounts"),
        ("tool_request_disconnection", "SELECT name FROM customers"),
        ("tool_issue_bill_credit", "SELECT address FROM supply_points"),
        ("tool_set_temp_protection", "SELECT supply_point_id FROM accounts"),
        ("tool_read_ticket", "SELECT body FROM tickets"),
        ("tool_lookup_account", "SELECT name FROM customers"),
        ("tool_read_ticket", "SELECT token_hash FROM leases"),
    ],
)
def test_tools_read_only_the_columns_their_code_needs(as_role, role, query):
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        as_role(role).execute(query)


ADVISORY_LOCK_FUNCTIONS = r"^pg_(try_)?advisory_(xact_)?lock(_shared)?$"


def test_only_the_executor_can_take_advisory_locks(admin, as_role):  # gap I9
    # Every overload the server has, read from the catalog, so none is missed.
    functions = admin.execute(
        "SELECT proname, pronargs FROM pg_proc WHERE proname ~ %s ORDER BY proname, pronargs",
        (ADVISORY_LOCK_FUNCTIONS,),
    ).fetchall()
    assert len(functions) == 16  # 8 names, each as (bigint) and (int, int)
    roles = _login_roles(admin, exclude=("postgres", "executor"))
    allowed = []
    for role in roles:
        conn = as_role(role)
        # If a call ever succeeds, the role may hold a session lock that the next role would
        # wait on: time out, count it as allowed, and let the locks go.
        conn.execute("SET lock_timeout = '500ms'")
        for f in functions:
            args = "(1)" if f["pronargs"] == 1 else "(1, 1)"
            try:
                conn.execute(f"SELECT {f['proname']}{args}")
            except psycopg.errors.InsufficientPrivilege:
                continue
            except psycopg.errors.LockNotAvailable:
                pass
            allowed.append(f"{role} may call {f['proname']}{args}")
        conn.execute("SELECT pg_advisory_unlock_all()")
    assert allowed == []


def test_executor_can_take_advisory_locks(as_role):
    assert as_role("executor").execute("SELECT pg_try_advisory_xact_lock(1) AS ok").fetchone()["ok"] is True


def test_every_login_role_has_a_connection_limit(admin):  # gap I9
    rows = admin.execute(
        "SELECT rolname, rolconnlimit FROM pg_roles WHERE rolcanlogin AND rolname <> 'postgres'"
    ).fetchall()
    limits = {r["rolname"]: r["rolconnlimit"] for r in rows}
    assert limits == {
        **{role: 5 for role in TOOL_ROLES},
        "executor": 3,
        "approver": 5,
        **{role: 5 for role in ("gateway", "risk_engine", "dispatcher", "register_sync")},
    }


def test_a_tool_role_cannot_open_more_connections_than_its_limit(admin, settings):  # gap I9
    from app import db

    role = "tool_read_ticket"
    # Connections closed by earlier tests can take a moment to leave the server.
    for _ in range(50):
        if admin.execute("SELECT count(*) AS n FROM pg_stat_activity WHERE usename = %s", (role,)).fetchone()["n"] == 0:
            break
        time.sleep(0.1)
    opened = []
    try:
        for _ in range(5):
            opened.append(db.connect(settings, role))
        with pytest.raises(psycopg.OperationalError, match="too many connections"):
            opened.append(db.connect(settings, role))
    finally:
        for conn in opened:
            conn.close()


def test_executor_sessions_time_out_on_locks_and_statements(as_role):  # gap I9
    conn = as_role("executor")
    assert conn.execute("SHOW lock_timeout").fetchone()["lock_timeout"] == "5s"
    assert conn.execute("SHOW statement_timeout").fetchone()["statement_timeout"] == "30s"


@pytest.mark.parametrize(
    "move_out_date", ["NULL::date", "(now() AT TIME ZONE 'UTC')::date - 1"], ids=["none", "yesterday"]
)
def test_move_out_request_needs_a_date_of_today_or_later(as_role, admin, move_out_date):
    # NULL would wait at notice_sent forever; a past date would skip the customer's real date.
    conn = as_role("tool_request_disconnection")
    with pytest.raises(psycopg.errors.RaiseException, match="today or later"):
        conn.execute(f"SELECT api_request_moveout(%s, {move_out_date})", (open_lease(admin, 1),))
    assert admin.execute("SELECT count(*) AS n FROM action_requests").fetchone()["n"] == 0


def test_move_out_request_for_today_is_accepted(as_role, admin):
    as_role("tool_request_disconnection").execute(
        "SELECT api_request_moveout(%s, (now() AT TIME ZONE 'UTC')::date)", (open_lease(admin, 1),)
    )
    assert admin.execute("SELECT count(*) AS n FROM action_requests").fetchone()["n"] == 1


def test_tool_sessions_end_when_left_idle_in_a_transaction(admin):
    # set_temp_protection holds a home's lock until its transaction ends. This setting ends a hung
    # tool's transaction; it does not stop a hijacked tool, which can change it in its own session.
    rows = admin.execute(
        "SELECT rolname, rolconfig FROM pg_roles WHERE rolname = ANY(%s)", (TOOL_ROLES,)
    ).fetchall()
    missing = [
        r["rolname"] for r in rows
        if "idle_in_transaction_session_timeout=10s" not in (r["rolconfig"] or [])
    ]
    assert len(rows) == len(TOOL_ROLES) and missing == []
