"""Case 7: the same person approves twice (ASI03).

Wall: approvals are written only by the console, and the database counts distinct people.
"""

import psycopg
import pytest

from app.executor.approvals import approve, approver_count
from tests.unit.test_console import request_credit
from tests.unit.test_executor_moveouts import add_moveout, ANNA, PETROS
from tests.unit.test_risk_floor import approve_all, EFFECTS, ex, FLOOR_CASES, written


@pytest.mark.parametrize("kind", EFFECTS)
@pytest.mark.parametrize("case", FLOOR_CASES)
def test_asi03_floor_counts_distinct_approvers_and_roles(admin, as_role, ex, kind, case):
    tier, approvals, allowed = FLOOR_CASES[case]
    if allowed is None:  # T0 with no approval: a credit goes through, an order does not
        allowed = kind == "credit"
    rid, write = EFFECTS[kind](admin, tier)
    approve_all(as_role("approver"), rid, approvals)
    if allowed:
        write(ex)
        assert written(admin) == 1
    else:
        with pytest.raises(psycopg.errors.RaiseException, match="approval"):
            write(ex)
        assert written(admin) == 0


def test_asi03_same_approver_twice_is_rejected(admin, as_role):  # ⑥
    staff, ex = as_role("approver"), as_role("executor")
    rid = add_moveout(admin)
    assert approve(staff, rid, ANNA) is True
    assert approve(staff, rid, ANNA) is False
    assert approver_count(ex, rid) == 1
    assert approve(staff, rid, PETROS) is True
    assert approver_count(ex, rid) == 2


def test_asi03_one_person_cannot_count_twice(admin,as_role):
    rid=request_credit(admin,"T2")
    staff=as_role("approver")
    staff.execute("INSERT INTO approvals(request_id,approver) VALUES (%s,%s)",(rid,ANNA))
    with pytest.raises(psycopg.errors.UniqueViolation):
        staff.execute("INSERT INTO approvals(request_id,approver) VALUES (%s,%s)",(rid,ANNA.upper().replace("-","")))
    with pytest.raises(psycopg.errors.InvalidTextRepresentation):
        staff.execute("INSERT INTO approvals(request_id,approver) VALUES (%s,%s)",(rid,"\u00a0"+ANNA))
