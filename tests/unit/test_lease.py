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


