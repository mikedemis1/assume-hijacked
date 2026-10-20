"""Case 3: a credit that is too big, negative, or has no real charge behind it (ASI02).

Walls: the risk tier with its approvals, and the database trigger on the credit row.
"""

from decimal import Decimal

import psycopg
import pytest

from app.executor.credits import process_credits
from app.risk.rules import Assessment
from tests.conftest import approve_as, open_lease
from tests.unit.test_executor_credits import (
    add_credit,
    credits_count,
    insert_credit,
    statuses,
    UNSUPPORTED_CREDITS,
)
from tests.unit.test_risk_floor import _credit, ANNA, ex
from tests.unit.test_risk_rules import credit, judge


@pytest.mark.parametrize("amount", [None, Decimal("0"), Decimal("-0.01"), Decimal("-5")])
def test_asi02_credit_rule_rejects_missing_or_non_positive_amount(amount):
    assert judge(credit(amount_eur=amount)) == Assessment("REJECT", 100, ("invalid_amount",))


def test_asi02_big_credit_goes_to_staff(admin, as_role, settings, now):
    admin.execute("INSERT INTO charges VALUES (8, 1, '2026-10', 80.00), (9, 1, '2026-10', 80.00)")
    add_credit(admin, 80, 9)
    process_credits(as_role("executor"), settings, now)
    assert statuses(admin) == ["needs_staff"]


def test_asi02_credit_waits_for_its_approvals(admin, as_role, ex):
    rid, write = _credit(admin, "T1")
    with pytest.raises(psycopg.errors.RaiseException, match="needs 1 distinct approval"):
        write(ex)
    assert credits_count(admin) == 0
    approve_as(as_role("approver"), rid, ANNA)
    write(ex)
    assert credits_count(admin) == 1


@pytest.mark.parametrize("case", UNSUPPORTED_CREDITS)
def test_asi02_database_refuses_a_credit_with_no_charge_behind_it(admin, as_role, case):
    setup, reason = UNSUPPORTED_CREDITS[case]
    row = setup(admin)
    with pytest.raises(psycopg.errors.RaiseException, match=reason):
        insert_credit(as_role("executor"), *row)
    assert credits_count(admin) == 0


@pytest.mark.parametrize("amount", ["0", "-5", "NaN", "Infinity", "-Infinity"])
def test_asi02_database_refuses_a_zero_negative_or_nan_credit(admin, as_role, amount):
    lease = open_lease(admin, 1)
    with pytest.raises(psycopg.errors.RaiseException, match="positive finite number"):
        as_role("tool_issue_bill_credit").execute(
            "SELECT api_request_credit(%s, %s::numeric, 'duplicate_charge', 2)", (lease, amount)
        )
    assert admin.execute("SELECT count(*) AS n FROM action_requests").fetchone()["n"] == 0
