"""Leases (db/sql/05-lease.sql) and the five lease-based tool functions.

A lease ties one agent run to one ticket and a list of tools. A tool role can reach the data only
through its one SECURITY DEFINER function, and that function answers only for a live lease that
lists the tool. The database keeps only the sha256 of a lease.
"""

import hashlib

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


def _expire(admin, lease):
    admin.execute(
        "UPDATE leases SET expires_at = now() - interval '1 second' WHERE token_hash = sha256(convert_to(%s, 'UTF8'))",
        (lease,),
    )


@pytest.mark.parametrize("state", ["live", "expired", "revoked", "unknown"])
def test_lease_functions_refuse_expired_revoked_unknown(admin, as_role, state):
    lease = open_lease(admin, 1, TOOLS)
    if state == "expired":
        _expire(admin, lease)
    elif state == "revoked":
        as_role("dispatcher").execute("SELECT revoke_lease(%s)", (lease,))
    elif state == "unknown":
        lease = hashlib.sha256(b"never issued").hexdigest()
    if state == "live":  # the control: the same call works on a live lease
        assert call_api(as_role("tool_read_ticket"), "read_ticket", lease)
        return
    for tool in TOOLS:
        with pytest.raises(psycopg.errors.RaiseException, match="lease invalid"):
            call_api(as_role(f"tool_{tool}"), tool, lease)
    # Nothing was written by a refused call.
    assert admin.execute("SELECT count(*) AS n FROM action_requests").fetchone()["n"] == 0
    assert admin.execute("SELECT count(*) AS n FROM flags WHERE supply_point_id = 'SP-1001'").fetchone()["n"] == 0


@pytest.mark.parametrize("tool", TOOLS)
def test_lease_function_refuses_tool_not_in_lease(admin, as_role, tool):
    others = [t for t in TOOLS if t != tool]
    lease = open_lease(admin, 1, others)
    with pytest.raises(psycopg.errors.RaiseException, match="lease invalid"):
        call_api(as_role(f"tool_{tool}"), tool, lease)
    # Control: a lease that lists the tool works for the same call.
    assert call_api(as_role(f"tool_{tool}"), tool, open_lease(admin, 1, [tool]))


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


def test_asi03_rls_hides_rows_from_tool_roles(admin):
    open_lease(admin, 1, ["read_ticket"])
    admin.execute("INSERT INTO action_requests (kind, ticket_id, account_id, amount_eur) VALUES ('credit', 1, 1, 5)")
    for table in RLS_TABLES:
        assert admin.execute(f"SELECT count(*) AS n FROM {table}").fetchone()["n"] > 0
        for role in TOOL_ROLES + ["executor"]:
            # A grant added by mistake: the tool role still sees no row, because no policy names it.
            # The executor is the control: a role the policy names sees the rows.
            with admin.transaction():
                admin.execute(f"GRANT SELECT ON {table} TO {role}")
                admin.execute(f"SET LOCAL ROLE {role}")
                seen = admin.execute(f"SELECT count(*) AS n FROM {table}").fetchone()["n"]
                admin.execute("RESET ROLE")
                raise psycopg.Rollback
            if role == "executor":
                assert seen > 0, table
            else:
                assert seen == 0, (table, role)
                # The grant was rolled back.
                assert admin.execute(
                    "SELECT has_table_privilege(%s, %s, 'SELECT') AS ok", (role, table)
                ).fetchone()["ok"] is False


# --- one effect request per lease, in the database ---------------------------------------
# A hijacked tool pod holds a valid lease for 15 minutes and could call its api_* function again
# and again. action_requests.lease_hash (set only by those functions) has a partial unique index,
# so the second request on a lease fails, whichever of the two effect tools asks.

EFFECT_TOOLS = ["issue_bill_credit", "request_disconnection"]
ONE_EFFECT_REFUSAL = "effect already requested"


def _requests(admin):
    return admin.execute("SELECT count(*) AS n FROM action_requests").fetchone()["n"]


@pytest.mark.parametrize("first", EFFECT_TOOLS)
@pytest.mark.parametrize("second", EFFECT_TOOLS)
def test_second_effect_request_on_one_lease_is_refused(admin, as_role, first, second):
    lease = open_lease(admin, 1, EFFECT_TOOLS)
    call_api(as_role(f"tool_{first}"), first, lease)
    with pytest.raises(psycopg.errors.RaiseException) as refused:
        call_api(as_role(f"tool_{second}"), second, lease)
    # A fixed text: no constraint name, no table, no lease.
    assert refused.value.diag.message_primary == ONE_EFFECT_REFUSAL
    assert lease not in str(refused.value)
    assert _requests(admin) == 1


def test_different_leases_each_file_one_request(admin, as_role):
    # Control: the index is per lease. Two runs on one ticket (the second after the first ended)
    # each file one request.
    for tool in EFFECT_TOOLS:
        call_api(as_role(f"tool_{tool}"), tool, open_lease(admin, 1, EFFECT_TOOLS))
    assert _requests(admin) == 2


def test_the_request_stores_the_hash_of_its_lease(admin, as_role):
    lease = open_lease(admin, 1, EFFECT_TOOLS)
    call_api(as_role("tool_issue_bill_credit"), "issue_bill_credit", lease)
    stored = admin.execute("SELECT lease_hash FROM action_requests").fetchone()["lease_hash"]
    assert bytes(stored) == hashlib.sha256(lease.encode()).digest()


def test_no_role_can_set_the_lease_hash_except_the_api_functions_owner(admin):
    roles = [r["rolname"] for r in admin.execute(
        "SELECT rolname FROM pg_roles WHERE rolname !~ '^pg_' AND NOT rolsuper").fetchall()]
    assert "tool_issue_bill_credit" in roles
    can = {
        r: [p for p in ("INSERT", "UPDATE") if admin.execute(
            "SELECT has_column_privilege(%s, 'action_requests', 'lease_hash', %s) AS ok", (r, p)
        ).fetchone()["ok"]]
        for r in roles
    }
    assert {r: p for r, p in can.items() if p} == {"api_owner": ["INSERT"]}


@pytest.mark.parametrize("tool", TOOLS)
def test_a_tool_role_cannot_write_the_hash_directly(admin, as_role, tool):
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        as_role(f"tool_{tool}").execute(
            "INSERT INTO action_requests (kind, ticket_id, account_id, move_out_date, lease_hash) "
            "VALUES ('move_out', 1, 1, now()::date + 3, sha256('x'::bytea))"
        )
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        as_role(f"tool_{tool}").execute("UPDATE action_requests SET lease_hash = NULL")
    assert _requests(admin) == 0
