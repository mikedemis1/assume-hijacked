"""The protection flags: add only (db/sql/07-flags.sql).

A flag says "someone in this home depends on electricity" (life-support equipment). It is the one
thing that must never be lost: a home without a flag can be disconnected.

  tool role   ADD a flag for its ticket's home, through api_set_temp_protection (tests/test_lease.py)
  anyone else nothing, and nobody at all may change or delete one. No grant allows it, and a
              trigger refuses any UPDATE, DELETE or TRUNCATE even with a grant added by mistake or
              from the superuser. A flag is removed only by a database administrator by hand.
"""

import psycopg
import pytest

NOT_ALLOWED = (psycopg.errors.InsufficientPrivilege, psycopg.errors.RaiseException)

CHANGES = {
    "update source": "UPDATE flags SET source = 'x'",
    "move to another home": "UPDATE flags SET supply_point_id = 'SP-1002'",
    "delete": "DELETE FROM flags",
    "delete one home": "DELETE FROM flags WHERE supply_point_id = 'SP-1003'",
}


def flags(admin):
    return {r["supply_point_id"]: r["source"] for r in admin.execute("SELECT supply_point_id, source FROM flags")}


def all_roles(admin):
    rows = admin.execute("SELECT rolname FROM pg_roles WHERE NOT rolsuper AND rolname !~ '^pg_' ORDER BY rolname")
    return [r["rolname"] for r in rows]


@pytest.mark.parametrize("change", CHANGES)
def test_no_role_can_remove_or_change_a_flag(admin, change):
    # Every role the database has: the login roles (executor, approver, every tool role, ...) and
    # the owners (api_owner, ...). Each one is refused, by the missing grant.
    roles = all_roles(admin)
    assert {"executor", "approver", "api_owner", "tool_set_temp_protection"} <= set(roles)
    for role in roles:
        with admin.transaction(force_rollback=True):
            admin.execute(f"SET SESSION AUTHORIZATION {role}")
            with pytest.raises(NOT_ALLOWED):
                with admin.transaction():
                    admin.execute(CHANGES[change])
            admin.execute("RESET SESSION AUTHORIZATION")
    assert flags(admin) == {"SP-1003": "state_register"}


@pytest.mark.parametrize("change", CHANGES)
def test_even_the_superuser_cannot_delete_or_move_a_flag_directly(admin, change):
    # Moving a flag to another home is a removal for the first home; changing its source rewrites
    # where it came from. The trigger refuses all of it.
    with pytest.raises(psycopg.errors.RaiseException, match="flags"):
        admin.execute(CHANGES[change])
    assert flags(admin) == {"SP-1003": "state_register"}


@pytest.mark.parametrize("change", CHANGES)
def test_a_grant_added_by_mistake_still_cannot_change_a_flag(admin, change):
    # The trigger is the wall behind the grants: give the executor the privileges and it is
    # still refused. (The grant is rolled back with the transaction.)
    with admin.transaction(force_rollback=True):
        admin.execute("GRANT UPDATE, DELETE ON flags TO executor")
        admin.execute("SET SESSION AUTHORIZATION executor")
        with pytest.raises(psycopg.errors.RaiseException, match="flags"):
            with admin.transaction():
                admin.execute(CHANGES[change])
        admin.execute("RESET SESSION AUTHORIZATION")
    assert flags(admin) == {"SP-1003": "state_register"}


def test_nobody_holds_update_delete_or_truncate_on_flags(admin):
    rows = admin.execute(
        "SELECT rolname FROM pg_roles WHERE NOT rolsuper AND rolname !~ '^pg_' "
        "AND (has_table_privilege(oid, 'flags', 'DELETE') OR has_table_privilege(oid, 'flags', 'TRUNCATE') "
        "     OR has_any_column_privilege(oid, 'flags', 'UPDATE')) ORDER BY 1"
    ).fetchall()
    assert rows == []


def test_the_removal_machinery_is_gone(admin):
    names = admin.execute(
        "SELECT proname FROM pg_proc WHERE proname IN ('request_flag_removal', 'approve_flag_removal')"
    ).fetchall()
    tables = admin.execute(
        "SELECT relname FROM pg_class WHERE relkind = 'r' "
        "AND relname IN ('flag_removal_requests', 'flag_removal_approvals', 'register_sync', 'occupier_notices')"
    ).fetchall()
    roles = admin.execute("SELECT rolname FROM pg_roles WHERE rolname IN ('flags_remover', 'flags_admin')").fetchall()
    assert names == [] and tables == [] and roles == []


def test_flags_cannot_be_truncated_even_by_the_superuser(admin):
    with pytest.raises(psycopg.errors.RaiseException, match="truncate"):
        admin.execute("TRUNCATE flags CASCADE")
    assert flags(admin) == {"SP-1003": "state_register"}


def test_rls_is_forced_on_flags(admin):
    row = admin.execute(
        "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = 'flags' AND relkind = 'r'"
    ).fetchone()
    assert row == {"relrowsecurity": True, "relforcerowsecurity": True}
