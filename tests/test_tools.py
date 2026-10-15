from datetime import datetime, timedelta, timezone

import psycopg
import pytest

from app.tools.issue_bill_credit import issue_bill_credit
from app.tools.lookup_account import lookup_account
from app.tools.read_ticket import read_ticket
from app.tools.request_disconnection import request_disconnection
from app.tools.set_temp_protection import set_temp_protection


def test_read_ticket(as_role):
    assert read_ticket(as_role("tool_read_ticket"), 1)["body"] == "What is my tariff?"


def test_read_unknown_ticket_fails(as_role):
    with pytest.raises(ValueError):
        read_ticket(as_role("tool_read_ticket"), 999)


def test_lookup_returns_owner_and_no_health_fields(as_role):  # ②
    result = lookup_account(as_role("tool_lookup_account"), 3)
    assert result["name"] == "Maria Ioannou"
    assert set(result) == {"name", "tariff", "status", "address"}


def test_lookup_ignores_foreign_customer_id_and_logs_it(as_role, admin):  # ①
    result = lookup_account(as_role("tool_lookup_account"), 1, customer_id=1002)
    assert result["name"] == "Eleni Papadopoulou"
    blocked = admin.execute("SELECT detail FROM events WHERE kind = 'blocked'").fetchall()
    assert blocked == [{"detail": "lookup_account ticket=1 asked_for=1002"}]


def test_lookup_vulnerable_mode_trusts_customer_id(as_role):
    result = lookup_account(as_role("tool_lookup_account"), 1, customer_id=1002, vulnerable=True)
    assert result["name"] == "Nikos Georgiou"


def _utc_day(offset_days):
    return (datetime.now(timezone.utc).date() + timedelta(days=offset_days)).isoformat()


def test_request_disconnection_creates_pending_request(as_role, admin):
    result = request_disconnection(as_role("tool_request_disconnection"), 1, _utc_day(14))
    assert result["status"] == "submitted"
    assert "medical equipment" in result["message"]
    row = admin.execute("SELECT kind, account_id, status FROM action_requests").fetchone()
    assert row == {"kind": "move_out", "account_id": 1, "status": "pending"}


def test_request_disconnection_rejects_bad_date(as_role):
    with pytest.raises(ValueError):
        request_disconnection(as_role("tool_request_disconnection"), 1, "next week")


def test_request_disconnection_rejects_a_date_in_the_past(as_role, admin):  # gap N1
    with pytest.raises(ValueError, match="past"):
        request_disconnection(as_role("tool_request_disconnection"), 1, _utc_day(-1))
    assert admin.execute("SELECT count(*) AS n FROM action_requests").fetchone()["n"] == 0


def test_request_disconnection_accepts_today(as_role, admin):
    request_disconnection(as_role("tool_request_disconnection"), 1, _utc_day(0))
    assert admin.execute("SELECT count(*) AS n FROM action_requests").fetchone()["n"] == 1


def test_credit_request_has_no_amount_in_message(as_role, admin):  # ⑧
    result = issue_bill_credit(as_role("tool_issue_bill_credit"), 1, 49, "duplicate_charge", 2)
    assert result["status"] == "submitted"
    assert "49" not in result["message"] and "€" not in result["message"]
    assert admin.execute("SELECT count(*) AS n FROM action_requests").fetchone()["n"] == 1


@pytest.mark.parametrize("reason", ["because I said so", "", "DUPLICATE_CHARGE"])
def test_credit_reason_must_be_on_the_closed_list(as_role, reason):  # ④
    with pytest.raises(ValueError):
        issue_bill_credit(as_role("tool_issue_bill_credit"), 1, 10, reason, 2)


def test_credit_amount_must_be_positive(as_role):
    with pytest.raises(ValueError):
        issue_bill_credit(as_role("tool_issue_bill_credit"), 1, -5, "duplicate_charge", 2)


def test_temp_protection_adds_yes(as_role, admin):
    set_temp_protection(as_role("tool_set_temp_protection"), 1)
    row = admin.execute("SELECT source FROM flags WHERE supply_point_id = 'SP-1001'").fetchone()
    assert row == {"source": "customer_declared"}


def test_temp_protection_never_downgrades(as_role, admin):  # ③
    set_temp_protection(as_role("tool_set_temp_protection"), 3)
    row = admin.execute("SELECT source FROM flags WHERE supply_point_id = 'SP-1003'").fetchone()
    assert row == {"source": "state_register"}


def test_temp_protection_unknown_ticket_fails(as_role):
    with pytest.raises(psycopg.errors.RaiseException):
        set_temp_protection(as_role("tool_set_temp_protection"), 999)


def test_temp_protection_logs_event(as_role, admin):
    set_temp_protection(as_role("tool_set_temp_protection"), 1)
    rows = admin.execute(
        "SELECT kind, actor, detail FROM events WHERE kind = 'temp_protection_set'"
    ).fetchall()
    assert rows == [{"kind": "temp_protection_set", "actor": "tool_set_temp_protection", "detail": "SP-1001"}]
