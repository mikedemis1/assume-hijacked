import json
import logging
from datetime import datetime, timedelta, timezone

import pytest

from app.tools.common import LeaseError
from app.tools.issue_bill_credit import issue_bill_credit
from app.tools.lookup_account import lookup_account
from app.tools.read_ticket import read_ticket
from app.tools.request_disconnection import request_disconnection
from app.tools.set_temp_protection import set_temp_protection
from tests.conftest import open_lease

UNKNOWN_LEASE = "0" * 64


def test_read_ticket(as_role, admin):
    assert read_ticket(as_role("tool_read_ticket"), open_lease(admin, 1))["body"] == "What is my tariff?"


def test_read_ticket_keeps_its_shape(as_role, admin):
    assert read_ticket(as_role("tool_read_ticket"), open_lease(admin, 2)) == {"ticket_id": 2, "body": "Hello"}


def test_read_unknown_ticket_fails(as_role):
    # No lease, no ticket: the tool cannot name a ticket of its own any more.
    with pytest.raises(LeaseError):
        read_ticket(as_role("tool_read_ticket"), UNKNOWN_LEASE)




def security_events(caplog):
    return [json.loads(r.getMessage()) for r in caplog.records if r.name == "assume_hijacked.security"]




def _utc_day(offset_days):
    return (datetime.now(timezone.utc).date() + timedelta(days=offset_days)).isoformat()


def test_request_disconnection_creates_pending_request(as_role, admin):
    result = request_disconnection(as_role("tool_request_disconnection"), open_lease(admin, 1), _utc_day(14))
    assert result["status"] == "submitted"
    assert "medical equipment" in result["message"]
    row = admin.execute("SELECT kind, ticket_id, account_id, status FROM action_requests").fetchone()
    assert row == {"kind": "move_out", "ticket_id": 1, "account_id": 1, "status": "pending"}


def test_request_disconnection_rejects_bad_date(as_role, admin):
    with pytest.raises(ValueError):
        request_disconnection(as_role("tool_request_disconnection"), open_lease(admin, 1), "next week")


def test_request_disconnection_rejects_a_date_in_the_past(as_role, admin):  # gap N1
    with pytest.raises(ValueError, match="past"):
        request_disconnection(as_role("tool_request_disconnection"), open_lease(admin, 1), _utc_day(-1))
    assert admin.execute("SELECT count(*) AS n FROM action_requests").fetchone()["n"] == 0


def test_request_disconnection_accepts_today(as_role, admin):
    request_disconnection(as_role("tool_request_disconnection"), open_lease(admin, 1), _utc_day(0))
    assert admin.execute("SELECT count(*) AS n FROM action_requests").fetchone()["n"] == 1


def test_request_disconnection_refuses_an_unknown_lease(as_role, admin):
    with pytest.raises(LeaseError):
        request_disconnection(as_role("tool_request_disconnection"), UNKNOWN_LEASE, _utc_day(14))
    assert admin.execute("SELECT count(*) AS n FROM action_requests").fetchone()["n"] == 0


def test_credit_request_has_no_amount_in_message(as_role, admin):  # ⑧
    result = issue_bill_credit(as_role("tool_issue_bill_credit"), open_lease(admin, 1), 49, "duplicate_charge", 2)
    assert result["status"] == "submitted"
    assert "49" not in result["message"] and "€" not in result["message"]
    row = admin.execute("SELECT kind, ticket_id, account_id, amount_eur FROM action_requests").fetchone()
    assert row == {"kind": "credit", "ticket_id": 1, "account_id": 1, "amount_eur": 49}


@pytest.mark.parametrize("reason", ["because I said so", "", "DUPLICATE_CHARGE"])
def test_credit_reason_must_be_on_the_closed_list(as_role, admin, reason):  # ④
    with pytest.raises(ValueError):
        issue_bill_credit(as_role("tool_issue_bill_credit"), open_lease(admin, 1), 10, reason, 2)


def test_credit_amount_must_be_positive(as_role, admin):
    with pytest.raises(ValueError):
        issue_bill_credit(as_role("tool_issue_bill_credit"), open_lease(admin, 1), -5, "duplicate_charge", 2)


def test_temp_protection_adds_yes(as_role, admin):
    set_temp_protection(as_role("tool_set_temp_protection"), open_lease(admin, 1))
    row = admin.execute("SELECT source FROM flags WHERE supply_point_id = 'SP-1001'").fetchone()
    assert row == {"source": "customer_declared"}




def test_temp_protection_unknown_ticket_fails(as_role, admin):
    with pytest.raises(LeaseError):
        set_temp_protection(as_role("tool_set_temp_protection"), UNKNOWN_LEASE)
    assert admin.execute("SELECT count(*) AS n FROM flags").fetchone()["n"] == 1  # only the seed's SP-1003


def test_temp_protection_logs_event(as_role, admin):
    set_temp_protection(as_role("tool_set_temp_protection"), open_lease(admin, 1))
    rows = admin.execute(
        "SELECT kind, actor, detail FROM events WHERE kind = 'temp_protection_set'"
    ).fetchall()
    assert rows == [{"kind": "temp_protection_set", "actor": "tool_set_temp_protection", "detail": "SP-1001"}]
