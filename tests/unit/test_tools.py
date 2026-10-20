import json

import pytest

from app.tools.issue_bill_credit import issue_bill_credit
from app.tools.read_ticket import read_ticket
from tests.conftest import open_lease

UNKNOWN_LEASE = "0" * 64


def test_read_ticket(as_role, admin):
    assert read_ticket(as_role("tool_read_ticket"), open_lease(admin, 1))["body"] == "What is my tariff?"


def security_events(caplog):
    return [json.loads(r.getMessage()) for r in caplog.records if r.name == "assume_hijacked.security"]


def test_credit_amount_must_be_positive(as_role, admin):
    with pytest.raises(ValueError):
        issue_bill_credit(as_role("tool_issue_bill_credit"), open_lease(admin, 1), -5, "duplicate_charge", 2)


