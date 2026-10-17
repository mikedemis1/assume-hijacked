"""Leases (db/sql/05-lease.sql) and the five lease-based tool functions.

A lease ties one agent run to one ticket and a list of tools. A tool role can reach the data only
through its one SECURITY DEFINER function, and that function answers only for a live lease that
lists the tool. The database keeps only the sha256 of a lease.
"""

import hashlib
import os
import time

import psycopg
import pytest

from tests.conftest import ROOT, TOOLS, open_lease

TOOL_ROLES = [f"tool_{tool}" for tool in TOOLS]

# One call per api function, with arguments that work for a lease on ticket 1 (customer 1001).
API_CALLS = {
    "read_ticket": ("SELECT * FROM api_read_ticket(%s)", ()),
    "lookup_account": ("SELECT * FROM api_lookup_account(%s)", ()),
    "request_disconnection": (
        "SELECT api_request_moveout(%s, (now() AT TIME ZONE 'UTC')::date + 14)", ()
    ),
    "issue_bill_credit": (
        "SELECT api_request_credit(%s, %s, %s, %s)", (49, "duplicate_charge", 2)
    ),
    "set_temp_protection": ("SELECT api_set_temp_protection(%s)", ()),
}


def call_api(conn, tool, lease):
    query, extra = API_CALLS[tool]
    return conn.execute(query, (lease, *extra)).fetchall()


def test_open_lease_returns_token_and_stores_only_hash(admin, as_role):
    lease = as_role("dispatcher").execute(
        "SELECT open_lease(%s, %s, %s) AS lease", (1, ["read_ticket"], "agent-pod-1")
    ).fetchone()["lease"]
    assert len(lease) == 64 and int(lease, 16) >= 0  # 32 random bytes, hex
    row = admin.execute(
        "SELECT token_hash, ticket_id, allowed_tools, bound_pod, revoked, "
        "expires_at - created_at AS lifetime, expires_at > now() AS live FROM leases"
    ).fetchone()
    assert row["token_hash"] == hashlib.sha256(lease.encode()).digest()
    assert row["ticket_id"] == 1 and row["allowed_tools"] == ["read_ticket"]
    assert row["bound_pod"] == "agent-pod-1" and row["revoked"] is False and row["live"] is True
    assert 14 * 60 < row["lifetime"].total_seconds() <= 15 * 60 + 1
    # The lease itself is in no column: only its hash.
    dump = admin.execute("SELECT leases::text AS t FROM leases").fetchone()["t"]
    assert lease not in dump
    # Two leases are never the same.
    assert open_lease(admin, 1, ["read_ticket"]) != lease


def test_lease_scope_answers_for_live_leases_only(admin, as_role):
    lease = open_lease(admin, 3, ["lookup_account", "read_ticket"])
    for role in ("gateway", "dispatcher"):
        rows = as_role(role).execute(
            "SELECT ticket_id, allowed_tools, bound_pod FROM lease_scope(%s)", (lease,)
        ).fetchall()
        assert rows == [{"ticket_id": 3, "allowed_tools": ["lookup_account", "read_ticket"], "bound_pod": None}]
    as_role("dispatcher").execute("SELECT revoke_lease(%s)", (lease,))
    assert as_role("gateway").execute("SELECT * FROM lease_scope(%s)", (lease,)).fetchall() == []
    assert as_role("gateway").execute("SELECT * FROM lease_scope(%s)", ("0" * 64,)).fetchall() == []


@pytest.mark.parametrize(
    "role", TOOL_ROLES + ["executor", "approver", "risk_engine", "register_sync", "gateway"]
)
def test_only_dispatcher_opens_and_revokes_and_only_gateway_and_dispatcher_read_scope(admin, as_role, role):
    lease = open_lease(admin, 1, ["read_ticket"])
    statements = ["SELECT open_lease(1, ARRAY['read_ticket'], NULL)", "SELECT revoke_lease(%s)"]
    if role != "gateway":
        statements.append("SELECT * FROM lease_scope(%s)")
    conn = as_role(role)
    for statement in statements:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute(statement, (lease,) if "%s" in statement else None)


def test_open_lease_refuses_unknown_tools_and_empty_lists(as_role):
    conn = as_role("dispatcher")
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute("SELECT open_lease(1, ARRAY['drop_tables'], NULL)")
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute("SELECT open_lease(1, ARRAY[]::text[], NULL)")


def _expire(admin, lease):
    admin.execute(
        "UPDATE leases SET expires_at = now() - interval '1 second' WHERE token_hash = sha256(convert_to(%s, 'UTF8'))",
        (lease,),
    )


@pytest.mark.parametrize("tool", TOOLS)
@pytest.mark.parametrize("state", ["live", "expired", "revoked", "unknown"])
def test_lease_functions_refuse_expired_revoked_unknown(admin, as_role, tool, state):
    lease = open_lease(admin, 1, TOOLS)
    if state == "expired":
        _expire(admin, lease)
    elif state == "revoked":
        as_role("dispatcher").execute("SELECT revoke_lease(%s)", (lease,))
    elif state == "unknown":
        lease = hashlib.sha256(b"never issued").hexdigest()
    conn = as_role(f"tool_{tool}")
    if state == "live":  # the control: the same call works on a live lease
        assert call_api(conn, tool, lease)
        return
    with pytest.raises(psycopg.errors.RaiseException, match="lease invalid"):
        call_api(conn, tool, lease)
    # Nothing was written by a refused call.
    assert admin.execute("SELECT count(*) AS n FROM action_requests").fetchone()["n"] == 0
    assert admin.execute("SELECT count(*) AS n FROM flags WHERE supply_point_id = 'SP-1001'").fetchone()["n"] == 0


def test_expiry_uses_the_database_clock_not_the_transaction_start(admin, as_role):
    # now() is frozen at the start of a transaction; a tool session that opens one early must not
    # keep an expired lease alive. The check uses clock_timestamp().
    lease = open_lease(admin, 1, ["read_ticket"])
    conn = as_role("tool_read_ticket")
    conn.autocommit = False
    try:
        conn.execute("SELECT 1")  # the transaction, and its now(), start here
        admin.execute(
            "UPDATE leases SET expires_at = clock_timestamp() + interval '100 milliseconds' "
            "WHERE token_hash = sha256(convert_to(%s, 'UTF8'))",
            (lease,),
        )
        time.sleep(0.3)  # now() of the open transaction is still before expires_at
        with pytest.raises(psycopg.errors.RaiseException, match="lease invalid"):
            call_api(conn, "read_ticket", lease)
    finally:
        conn.rollback()


@pytest.mark.parametrize("tool", TOOLS)
def test_lease_function_refuses_tool_not_in_lease(admin, as_role, tool):
    others = [t for t in TOOLS if t != tool]
    lease = open_lease(admin, 1, others)
    with pytest.raises(psycopg.errors.RaiseException, match="lease invalid"):
        call_api(as_role(f"tool_{tool}"), tool, lease)
    # Control: a lease that lists the tool works for the same call.
    assert call_api(as_role(f"tool_{tool}"), tool, open_lease(admin, 1, [tool]))


@pytest.mark.parametrize("function_tool", TOOLS)
@pytest.mark.parametrize("role", TOOL_ROLES)
def test_each_tool_role_executes_only_its_function(admin, as_role, role, function_tool):
    lease = open_lease(admin, 1, TOOLS)
    conn = as_role(role)
    if role == f"tool_{function_tool}":
        assert call_api(conn, function_tool, lease)
    else:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            call_api(conn, function_tool, lease)


API_FUNCTIONS = {
    "api_read_ticket(text)": "tool_read_ticket",
    "api_lookup_account(text)": "tool_lookup_account",
    "api_request_moveout(text,date)": "tool_request_disconnection",
    "api_request_credit(text,numeric,text,integer)": "tool_issue_bill_credit",
    "api_set_temp_protection(text)": "tool_set_temp_protection",
}
LEASE_FUNCTIONS = {
    "open_lease(integer,text[],text)": {"dispatcher"},
    "revoke_lease(text)": {"dispatcher"},
    "lease_scope(text)": {"gateway", "dispatcher"},
}


@pytest.mark.parametrize("signature", list(API_FUNCTIONS) + list(LEASE_FUNCTIONS))
def test_new_functions_are_definer_with_fixed_search_path_and_no_public_execute(admin, signature):
    row = admin.execute(
        "SELECT p.prosecdef, p.proconfig, pg_get_userbyid(p.proowner) AS owner, "
        "has_function_privilege('public', p.oid, 'EXECUTE') AS public_execute, "
        "ARRAY(SELECT r.rolname FROM pg_roles r "
        "      WHERE r.rolname !~ '^pg_' AND r.rolname <> pg_get_userbyid(p.proowner) "
        "        AND NOT r.rolsuper AND has_function_privilege(r.oid, p.oid, 'EXECUTE') "
        "      ORDER BY r.rolname) AS callers "
        "FROM pg_proc p WHERE p.oid = %s::regprocedure",
        (signature,),
    ).fetchone()
    assert row["prosecdef"] is True
    assert row["proconfig"] == ["search_path=public, pg_temp"]
    assert row["public_execute"] is False
    if signature in API_FUNCTIONS:
        assert row["owner"] == "api_owner"
        assert row["callers"] == [API_FUNCTIONS[signature]]
    else:
        assert row["owner"] == "lease_owner"
        assert set(row["callers"]) == LEASE_FUNCTIONS[signature]


def test_old_ticket_id_function_is_gone(admin):
    # set_temp_protection(int) took a ticket id from the caller; api_set_temp_protection replaces it.
    assert admin.execute("SELECT to_regprocedure('set_temp_protection(integer)') AS f").fetchone()["f"] is None


def test_tool_roles_have_no_table_grants(admin):
    for view in ("table_privileges", "column_privileges"):
        rows = admin.execute(
            f"SELECT grantee, table_name, privilege_type FROM information_schema.{view} "
            "WHERE grantee = ANY(%s)",
            (TOOL_ROLES,),
        ).fetchall()
        assert rows == [], view
    sequences = admin.execute(
        "SELECT grantee, object_name FROM information_schema.usage_privileges "
        "WHERE grantee = ANY(%s) AND object_type = 'SEQUENCE'",
        (TOOL_ROLES,),
    ).fetchall()
    assert sequences == []


RLS_TABLES = ["tickets", "customers", "accounts", "supply_points", "action_requests", "leases"]


def test_rls_is_forced_on_the_customer_tables(admin):
    rows = admin.execute(
        "SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class "
        "WHERE relname = ANY(%s) AND relkind = 'r' ORDER BY relname",
        (RLS_TABLES,),
    ).fetchall()
    assert [(r["relname"], r["relrowsecurity"], r["relforcerowsecurity"]) for r in rows] == [
        (name, True, True) for name in sorted(RLS_TABLES)
    ]


@pytest.mark.parametrize("table", RLS_TABLES)
@pytest.mark.parametrize("role", TOOL_ROLES + ["executor"])
def test_rls_backstop_hides_rows_from_tool_roles(admin, table, role):
    open_lease(admin, 1, ["read_ticket"])
    admin.execute("INSERT INTO action_requests (kind, ticket_id, account_id, amount_eur) VALUES ('credit', 1, 1, 5)")
    assert admin.execute(f"SELECT count(*) AS n FROM {table}").fetchone()["n"] > 0
    # A grant added by mistake: the tool role still sees no row, because no policy names it.
    # The executor is the control: a role the policy names sees the rows.
    with admin.transaction():
        admin.execute(f"GRANT SELECT ON {table} TO {role}")
        admin.execute(f"SET LOCAL ROLE {role}")
        seen = admin.execute(f"SELECT count(*) AS n FROM {table}").fetchone()["n"]
        admin.execute("RESET ROLE")
        raise psycopg.Rollback
    if role == "executor":
        assert seen > 0
    else:
        assert seen == 0
        # The grant was rolled back.
        assert admin.execute(
            "SELECT has_table_privilege(%s, %s, 'SELECT') AS ok", (role, table)
        ).fetchone()["ok"] is False


VULNERABLE_SQL = (ROOT / "db" / "sql" / "90-vulnerable-demo.sql").read_text(encoding="utf-8")
ANY_FUNCTION = "api_lookup_account_any(text,integer)"


def test_vulnerable_function_absent_unless_demo(admin, settings):
    # The test database is always built without the demo file (db/init/init.sh); the stack database
    # has it only when DEMO_VULNERABLE=1.
    exists = "SELECT to_regprocedure(%s) IS NOT NULL AS ok"
    assert admin.execute(exists, (ANY_FUNCTION,)).fetchone()["ok"] is False
    with psycopg.connect(
        host=settings.db_host, port=settings.db_port, dbname="supplier", user="postgres",
        password=os.environ["POSTGRES_PASSWORD"], autocommit=True,
    ) as stack:
        present = stack.execute(exists, (ANY_FUNCTION,)).fetchone()[0]
    assert present is (os.environ.get("DEMO_VULNERABLE", "0") == "1")


def test_vulnerable_demo_function_leaks_only_to_lookup_and_only_with_a_lease(admin, as_role, demo_vulnerable):
    lease = open_lease(admin, 1, ["lookup_account"])
    conn = as_role("tool_lookup_account")
    row = conn.execute("SELECT name FROM api_lookup_account_any(%s, 1002)", (lease,)).fetchone()
    assert row == {"name": "Nikos Georgiou"}  # the hole the demo shows
    with pytest.raises(psycopg.errors.RaiseException, match="lease invalid"):
        conn.execute("SELECT * FROM api_lookup_account_any(%s, 1002)", ("0" * 64,))
    for role in [r for r in TOOL_ROLES if r != "tool_lookup_account"]:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            as_role(role).execute("SELECT * FROM api_lookup_account_any(%s, 1002)", (lease,))
    assert "api_lookup_account_any" in VULNERABLE_SQL
