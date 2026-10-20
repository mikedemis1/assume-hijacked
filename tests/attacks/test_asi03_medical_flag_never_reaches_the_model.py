"""Case 2: a medical flag reaches the model (ASI03).

Walls: no tool returns a health field, and only the executor role can read the flags table.
"""

import psycopg
import pytest

from app.tools.lookup_account import lookup_account
from tests.conftest import open_lease
from tests.unit.test_agent import add_ticket, make_agent
from tests.unit.test_db_roles import _login_roles, TOOL_ROLES


def test_asi03_only_executor_reads_flags(admin, as_role):  # ②
    # Every login role in the database, so a role added later is checked without editing this test.
    roles = _login_roles(admin, exclude=("postgres", "executor"))
    assert set(TOOL_ROLES + ["approver"]) <= set(roles)
    for role in roles:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            as_role(role).execute("SELECT * FROM flags")


def test_asi03_no_tool_returns_health_fields(as_role, admin):  # ②
    result = lookup_account(as_role("tool_lookup_account"), open_lease(admin, 3))
    assert result["name"] == "Maria Ioannou"
    assert set(result) == {"name", "tariff", "status", "address"}


def test_asi03_reply_has_no_health_data(settings, admin, as_role):  # ②
    add_ticket(admin, 101, 1003, "CALL lookup_account {}\nSAY {last}")
    reply = make_agent(settings, as_role).handle_ticket(101)
    assert "Maria Ioannou" in reply
    for word in ("flag", "medical", "protect", "state_register", "register"):
        assert word not in reply.lower()
