import json

import pytest

from app.tools.issue_bill_credit import issue_bill_credit
from app.tools.read_ticket import read_ticket
from tests.conftest import open_lease
import logging
import psycopg
from app.tools.lookup_account import lookup_account

UNKNOWN_LEASE = "0" * 64


def test_read_ticket(as_role, admin):
    assert read_ticket(as_role("tool_read_ticket"), open_lease(admin, 1))["body"] == "What is my tariff?"


def security_events(caplog):
    return [json.loads(r.getMessage()) for r in caplog.records if r.name == "assume_hijacked.security"]


def test_credit_amount_must_be_positive(as_role, admin):
    with pytest.raises(ValueError):
        issue_bill_credit(as_role("tool_issue_bill_credit"), open_lease(admin, 1), -5, "duplicate_charge", 2)


def test_asi03_lookup_ignores_foreign_customer_id(as_role, admin, caplog):  # ①
    caplog.set_level(logging.INFO, logger="assume_hijacked.security")
    result = lookup_account(as_role("tool_lookup_account"), open_lease(admin, 1), customer_id=1002)
    assert result["name"] == "Eleni Papadopoulou"
    # Tool roles have no table grants (05-lease.sql), so the event goes to the security log, by
    # name only: never the value the model asked for.
    events = security_events(caplog)
    assert [(e["kind"], e["tool"], e["args"]) for e in events] == [("blocked", "lookup_account", ["customer_id"])]
    assert "1002" not in caplog.text


@pytest.mark.parametrize("amount", ["0", "-5", "NaN", "Infinity", "-Infinity"])
def test_asi02_database_refuses_a_zero_negative_or_nan_credit(admin, as_role, amount):
    lease = open_lease(admin, 1)
    with pytest.raises(psycopg.errors.RaiseException, match="positive finite number"):
        as_role("tool_issue_bill_credit").execute(
            "SELECT api_request_credit(%s, %s::numeric, 'duplicate_charge', 2)", (lease, amount)
        )
    assert admin.execute("SELECT count(*) AS n FROM action_requests").fetchone()["n"] == 0


def test_asi03_no_tool_returns_health_fields(as_role, admin):  # ②
    result = lookup_account(as_role("tool_lookup_account"), open_lease(admin, 3))
    assert result["name"] == "Maria Ioannou"
    assert set(result) == {"name", "tariff", "status", "address"}
