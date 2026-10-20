"""Case 5: a protection flag changed from YES to NO (ASI02).

Wall: flags can only be added; no role has the grant to change or remove one.
"""

import psycopg
import pytest

from app.tools.set_temp_protection import set_temp_protection
from tests.conftest import open_lease
from tests.unit.test_db_roles import TOOL_ROLES
from tests.unit.test_flag_removal import all_roles, CHANGES, flags, NOT_ALLOWED


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
