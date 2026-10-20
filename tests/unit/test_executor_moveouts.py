import time
from datetime import datetime, timezone

import psycopg
import pytest

from app.executor.approvals import approve
from app.executor.moveouts import process_moveouts
from tests.conftest import assess

ANNA = "eeab6c5e-f5bc-5d16-af4b-813d9b88be01"
PETROS = "bbc480b8-6ddb-5ecf-8ce6-876023b4cbc3"

# The order trigger uses the database clock, so the tests never jump time with the executor's
# `now`. They back-date rows as admin instead (approvals), or pick the move-out date.


def utc_today():
    return datetime.now(timezone.utc).date()


def add_moveout(admin, account_id=1, ticket_id=1, move_out_date=None, tier="T1") -> int:
    """A pending move-out. The date defaults to today (UTC), so an order is allowed once the rest holds.
    It is assessed T1 by default (one approval, the rule these tests were written for), so they check
    the executor and check_disconnection_order, not the approval floor (tests/test_risk_floor.py)."""
    admin.execute(
        "INSERT INTO action_requests (kind, ticket_id, account_id, move_out_date) "
        "VALUES ('move_out', %s, %s, %s)",
        (ticket_id, account_id, move_out_date or utc_today()),
    )
    rid = admin.execute("SELECT max(id) AS id FROM action_requests").fetchone()["id"]
    if tier is not None:
        assess(admin, rid, tier)
    return rid


def status(admin, request_id):
    return admin.execute("SELECT status FROM action_requests WHERE id = %s", (request_id,)).fetchone()["status"]


def orders(admin):
    return admin.execute("SELECT count(*) AS n FROM disconnection_orders").fetchone()["n"]


def errors(admin):
    return [r["detail"] for r in admin.execute("SELECT detail FROM events WHERE kind = 'executor_error' ORDER BY id")]


def ready_for_order(admin, staff, account_id=1, ticket_id=1, move_out_date=None) -> int:
    """A move-out where every condition for an order holds: a T1 risk assessment, a staff approval
    after it, move-out date today. Tests break one condition at a time."""
    rid = add_moveout(admin, account_id, ticket_id, move_out_date)
    approve(staff, rid, ANNA)
    return rid


def test_order_written_after_one_approval_and_date_reached(admin, as_role, settings, now):
    ex, staff = as_role("executor"), as_role("approver")
    rid = add_moveout(admin)  # T1, move-out date today
    process_moveouts(ex, settings, now)
    # Waiting for the person: the executor's own check holds it, so the trigger never has to refuse.
    assert status(admin, rid) == "pending" and orders(admin) == 0 and errors(admin) == []
    approve(staff, rid, ANNA)
    process_moveouts(ex, settings, now)
    assert status(admin, rid) == "executed" and orders(admin) == 1 and errors(admin) == []


def test_order_refused_without_any_approval_even_at_t0_score(admin, as_role, settings, now):
    # T0 asks the floor for no approval; an order still always needs one person.
    ex = as_role("executor")
    rid = add_moveout(admin, tier="T0")
    with pytest.raises(psycopg.errors.RaiseException, match="no staff approval"):
        insert_order(ex, rid, "SP-1001")
    process_moveouts(ex, settings, now)  # the executor's own check holds it too
    assert status(admin, rid) == "pending" and orders(admin) == 0 and errors(admin) == []
    approve(as_role("approver"), rid, ANNA)  # control: the same request goes through with one
    process_moveouts(ex, settings, now)
    assert status(admin, rid) == "executed" and orders(admin) == 1 and errors(admin) == []


def insert_order(conn, request_id, supply_point_id):
    conn.execute(
        "INSERT INTO disconnection_orders (request_id, supply_point_id) VALUES (%s, %s)",
        (request_id, supply_point_id),
    )


def test_a_held_home_lock_fails_that_request_and_the_batch_goes_on(admin, as_role, settings, now):  # gap I9
    staff = as_role("approver")
    first = ready_for_order(admin, staff)  # SP-1001
    second = ready_for_order(admin, staff, account_id=2, ticket_id=2)  # SP-1002
    # Someone else holds SP-1001's lock and never lets go (admin here; a tool role can no longer).
    admin.execute("SELECT pg_advisory_lock(hashtext('SP-1001'))")
    try:
        started = time.monotonic()
        process_moveouts(as_role("executor"), settings, now)
        took = time.monotonic() - started
    finally:
        admin.execute("SELECT pg_advisory_unlock_all()")
    assert took < 10  # lock_timeout is 5 s for every executor session
    assert status(admin, first) == "pending" and status(admin, second) == "executed"
    assert errors(admin) == [f"move_out request={first}: LockNotAvailable"]


