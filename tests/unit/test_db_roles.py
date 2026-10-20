import time

import psycopg
import pytest


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


@pytest.mark.parametrize("role", TOOL_ROLES)
def test_tools_cannot_order_disconnections(as_role, role):  # ⑦
    conn = as_role(role)
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        conn.execute(
            "INSERT INTO disconnection_orders (request_id, supply_point_id, created_at) "
            "VALUES (1, 'SP-1003', now())"
        )


@pytest.mark.parametrize("statement", ["DELETE FROM events", "UPDATE events SET detail = ''", "TRUNCATE events"])
def test_nobody_can_erase_the_audit_trail(as_role, statement):
    for role in TOOL_ROLES + ["executor", "approver"]:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            as_role(role).execute(statement)


@pytest.mark.parametrize("column, value", [("actor", "executor"), ("created_at", "2099-01-01")])
def test_events_actor_and_time_cannot_be_forged(as_role, column, value):
    for role in TOOL_ROLES + ["approver"]:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            as_role(role).execute(
                f"INSERT INTO events (kind, detail, {column}) VALUES ('ALERT', 'an alert nobody raised', %s)",
                (value,),
            )


def test_tool_cannot_insert_request_status(as_role):
    conn = as_role("tool_issue_bill_credit")
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        conn.execute(
            "INSERT INTO action_requests (kind, ticket_id, account_id, status) "
            "VALUES ('credit', 1, 1, 'executed')"
        )


# A tool role cannot insert a request at all (no table grants), and each api function sets its
# own kind, so the credit tool has no way to file a move-out and the other way round.


ADVISORY_LOCK_FUNCTIONS = r"^pg_(try_)?advisory_(xact_)?lock(_shared)?$"


def test_only_the_executor_can_take_advisory_locks(admin, as_role):
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


def test_a_tool_role_cannot_open_more_connections_than_its_limit(admin, settings):
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


def test_executor_sessions_time_out_on_locks_and_statements(as_role):
    conn = as_role("executor")
    assert conn.execute("SHOW lock_timeout").fetchone()["lock_timeout"] == "5s"
    assert conn.execute("SHOW statement_timeout").fetchone()["statement_timeout"] == "30s"


def test_asi03_only_executor_reads_flags(admin, as_role):  # ②
    # Every login role in the database, so a role added later is checked without editing this test.
    roles = _login_roles(admin, exclude=("postgres", "executor"))
    assert set(TOOL_ROLES + ["approver"]) <= set(roles)
    for role in roles:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            as_role(role).execute("SELECT * FROM flags")
