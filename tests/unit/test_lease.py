"""Leases (db/sql/05-lease.sql) and the five lease-based tool functions.

A lease ties one agent run to one ticket and a list of tools. A tool role can reach the data only
through its one SECURITY DEFINER function, and that function answers only for a live lease that
lists the tool. The database keeps only the sha256 of a lease.
"""

import hashlib
import time

import psycopg
import pytest

from tests.conftest import TOOLS, open_lease

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
    "role", TOOL_ROLES + ["executor", "approver", "risk_engine", "gateway"]
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


@pytest.mark.parametrize(
    "level",
    [psycopg.IsolationLevel.REPEATABLE_READ, psycopg.IsolationLevel.SERIALIZABLE],
    ids=["repeatable_read", "serializable"],
)
def test_revoked_lease_is_refused_inside_an_old_snapshot(admin, as_role, level):
    # In REPEATABLE READ and SERIALIZABLE every statement reads the snapshot taken at the start of
    # the transaction, so a tool that took one while the lease was live would not see the revoke.
    # The lease check refuses any isolation level other than READ COMMITTED.
    lease = open_lease(admin, 1, ["lookup_account"])
    conn = as_role("tool_lookup_account")
    conn.autocommit = False
    conn.isolation_level = level
    try:
        conn.execute("SELECT 1")  # the snapshot is taken here, while the lease is live
        as_role("dispatcher").execute("SELECT revoke_lease(%s)", (lease,))
        with pytest.raises(psycopg.errors.RaiseException, match="lease invalid"):
            call_api(conn, "lookup_account", lease)
    finally:
        conn.rollback()


def test_lease_still_works_in_a_read_committed_transaction(admin, as_role):
    # The control for the test above: a transaction as such is fine, only an old snapshot is not.
    lease = open_lease(admin, 1, ["lookup_account"])
    conn = as_role("tool_lookup_account")
    conn.autocommit = False
    try:
        conn.execute("SELECT 1")
        assert call_api(conn, "lookup_account", lease)
        # An actual tool transaction holds a shared lease lock until commit, so
        # completion waits for its effects. Take the old snapshot control in a
        # fresh transaction, without an already-running tool call holding it.
        conn.commit()
        conn.execute("SELECT 1")
        as_role("dispatcher").execute("SELECT revoke_lease(%s)", (lease,))
        with pytest.raises(psycopg.errors.RaiseException, match="lease invalid"):
            call_api(conn, "lookup_account", lease)
    finally:
        conn.rollback()


@pytest.mark.parametrize("tool", TOOLS)
def test_lease_functions_refuse_a_caller_granted_another_tools_function(admin, tool):
    # A grant added by mistake: another tool role gets EXECUTE on this tool's function. The lease
    # lists every tool, so only the session_user check inside the function can refuse it.
    lease = open_lease(admin, 1, TOOLS)
    intruder = next(f"tool_{t}" for t in TOOLS if t != tool)
    signature = next(sig for sig, role in API_FUNCTIONS.items() if role == f"tool_{tool}")
    with admin.transaction():
        admin.execute(f"GRANT EXECUTE ON FUNCTION {signature} TO {intruder}")
        admin.execute(f"SET SESSION AUTHORIZATION {intruder}")
        with pytest.raises(psycopg.errors.RaiseException, match="lease invalid"):
            with admin.transaction():
                call_api(admin, tool, lease)
        # Control: the function's own role, in the same transaction, is served.
        admin.execute("RESET SESSION AUTHORIZATION")
        admin.execute(f"SET SESSION AUTHORIZATION tool_{tool}")
        assert call_api(admin, tool, lease)
        admin.execute("RESET SESSION AUTHORIZATION")
        raise psycopg.Rollback


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


def test_lease_check_helper_is_callable_by_no_login_role(admin):
    # lease_ticket_for_tool takes the tool name as an argument, so only the api_* functions
    # (running as api_owner, its owner) may call it.
    row = admin.execute(
        "SELECT p.prosecdef, pg_get_userbyid(p.proowner) AS owner, "
        "ARRAY(SELECT r.rolname FROM pg_roles r WHERE r.rolname !~ '^pg_' AND NOT r.rolsuper "
        "      AND r.rolname <> 'api_owner' AND has_function_privilege(r.oid, p.oid, 'EXECUTE')) AS callers "
        "FROM pg_proc p WHERE p.oid = 'lease_ticket_for_tool(text,text)'::regprocedure"
    ).fetchone()
    assert row == {"prosecdef": False, "owner": "api_owner", "callers": []}


def test_no_function_in_public_is_executable_by_public(admin):
    # PostgreSQL grants EXECUTE to PUBLIC on every new function unless told otherwise. Each file
    # revokes it, and 01-schema.sql changes the default, so a function added later starts closed.
    rows = admin.execute(
        "SELECT p.oid::regprocedure::text AS f FROM pg_proc p "
        "WHERE p.pronamespace = 'public'::regnamespace AND has_function_privilege('public', p.oid, 'EXECUTE') "
        "ORDER BY 1"
    ).fetchall()
    assert [r["f"] for r in rows] == []


def test_pgcrypto_is_in_its_own_schema_and_only_the_lease_owner_may_use_it(admin):
    # An extension's functions are executable by PUBLIC unless the schema revokes it. Put in
    # `public` they would be callable by every tool role (test_db_grants_match_the_manifest_of_each_login_role
    # would flag it). So they live in `crypto`, closed to PUBLIC, and the one role that needs a random number (lease_owner, for open_lease) is granted that one function.
    ext = admin.execute(
        "SELECT extnamespace::regnamespace::text AS schema FROM pg_extension WHERE extname = 'pgcrypto'"
    ).fetchone()
    assert ext == {"schema": "crypto"}
    in_public = admin.execute(
        "SELECT p.oid::regprocedure::text AS f FROM pg_proc p JOIN pg_depend d ON d.objid = p.oid "
        "JOIN pg_extension e ON e.oid = d.refobjid AND d.deptype = 'e' "
        "WHERE e.extname = 'pgcrypto' AND p.pronamespace = 'public'::regnamespace"
    ).fetchall()
    assert in_public == []
    rows = admin.execute(
        "SELECT r.rolname, p.oid::regprocedure::text AS f FROM pg_roles r "
        "JOIN pg_proc p ON p.pronamespace = 'crypto'::regnamespace "
        "WHERE NOT r.rolsuper AND r.rolname !~ '^pg_' AND has_function_privilege(r.oid, p.oid, 'EXECUTE') "
        "ORDER BY 1, 2"
    ).fetchall()
    assert [(r["rolname"], r["f"]) for r in rows] == [("lease_owner", "crypto.gen_random_bytes(integer)")]
    users = admin.execute(
        "SELECT rolname FROM pg_roles WHERE NOT rolsuper AND rolname !~ '^pg_' "
        "AND has_schema_privilege(oid, 'crypto', 'USAGE') ORDER BY 1"
    ).fetchall()
    assert [r["rolname"] for r in users] == ["lease_owner"]


def test_a_tool_role_cannot_call_pgcrypto(as_role):
    tool = as_role("tool_read_ticket")
    for call in ("SELECT crypto.digest('x', 'sha256')", "SELECT crypto.gen_random_bytes(8)"):
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            tool.execute(call)


def test_a_new_function_gets_no_public_execute_by_default(admin):
    # The default privilege from 01-schema.sql: a function created without any REVOKE.
    with admin.transaction():
        admin.execute("CREATE FUNCTION public.added_later() RETURNS int LANGUAGE sql AS 'SELECT 1'")
        public_execute = admin.execute(
            "SELECT has_function_privilege('public', 'public.added_later()', 'EXECUTE') AS ok"
        ).fetchone()["ok"]
        raise psycopg.Rollback
    assert public_execute is False


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


