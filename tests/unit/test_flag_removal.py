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
from app.tools.set_temp_protection import set_temp_protection
from tests.conftest import open_lease
from tests.unit.test_db_roles import TOOL_ROLES

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
def test_even_the_superuser_cannot_delete_or_move_a_flag_directly(admin, change):
    # Moving a flag to another home is a removal for the first home; changing its source rewrites
    # where it came from. The trigger refuses all of it.
    with pytest.raises(psycopg.errors.RaiseException, match="flags"):
        admin.execute(CHANGES[change])
    assert flags(admin) == {"SP-1003": "state_register"}


@pytest.mark.parametrize("change", CHANGES)
def test_asi02_no_role_can_remove_or_change_a_flag(admin, change):
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


def test_asi02_temp_protection_never_downgrades(as_role, admin):  # ③
    set_temp_protection(as_role("tool_set_temp_protection"), open_lease(admin, 3))
    row = admin.execute("SELECT source FROM flags WHERE supply_point_id = 'SP-1003'").fetchone()
    assert row == {"source": "state_register"}


@pytest.mark.parametrize("role", TOOL_ROLES)
def test_asi02_tools_cannot_change_flags_directly(as_role, role):  # ③
    conn = as_role(role)
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        conn.execute("DELETE FROM flags")
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        conn.execute("INSERT INTO flags (supply_point_id, source) VALUES ('SP-1001', 'x')")
