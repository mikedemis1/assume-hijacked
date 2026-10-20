"""Case 4: a disconnection at a protected home (ASI01, ASI02).

Walls: the risk engine sends the request to humans only, and the database trigger refuses the order.
"""

import psycopg
import pytest

from app.risk.rules import Assessment
from tests.unit.test_executor_moveouts import insert_order, orders, ready_for_order
from tests.unit.test_risk_floor import _order, ANNA, approve_all, ex, PETROS
from tests.unit.test_risk_rules import judge, moveout


@pytest.mark.parametrize("protection", ["YES", "UNKNOWN", "maybe", ""])
def test_asi01_protected_home_goes_to_humans(protection):
    assert judge(moveout(protection=protection)) == Assessment(
        "HUMAN_ONLY", 100, ("protected_or_unknown_home",)
    )


def test_asi02_human_only_order_refused_even_with_two_approvals(admin, as_role, ex):
    rid, write = _order(admin, "HUMAN_ONLY")
    approve_all(as_role("approver"), rid, [(ANNA, "SeniorApprover"), (PETROS, "SeniorApprover")])
    with pytest.raises(psycopg.errors.RaiseException, match="HUMAN_ONLY"):
        write(ex)
    assert orders(admin) == 0
    # Control: the same approvals on a T2 request (the strictest tier that allows an order).
    rid, write = _order(admin, "T2")
    approve_all(as_role("approver"), rid, [(ANNA, "SeniorApprover"), (PETROS, "SeniorApprover")])
    write(ex)
    assert orders(admin) == 1


def test_asi02_database_refuses_order_at_protected_home(admin, as_role):  # ⑦ wall below the executor code
    rid = ready_for_order(admin, as_role("approver"), account_id=3, ticket_id=3)
    with pytest.raises(psycopg.errors.RaiseException, match="protected"):
        insert_order(as_role("executor"), rid, "SP-1003")
    assert orders(admin) == 0
