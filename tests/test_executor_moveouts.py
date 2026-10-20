import time
from datetime import datetime, timedelta, timezone

import psycopg
import pytest

from app.executor.approvals import approve, approver_count
from app.executor.moveouts import process_moveouts
from app.tools.set_temp_protection import set_temp_protection
from tests.conftest import assess, open_lease

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


def back_date_approvals(admin, request_id, hours):
    admin.execute(
        "UPDATE approvals SET created_at = now() - make_interval(hours => %s) WHERE request_id = %s",
        (hours, request_id),
    )


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


def test_no_order_before_the_move_out_date(admin, as_role, settings, now):  # gap N1
    ex, staff = as_role("executor"), as_role("approver")
    rid = ready_for_order(admin, staff, move_out_date=utc_today() + timedelta(days=30))
    process_moveouts(ex, settings, now)
    # The executor waits by itself; the trigger would refuse too, but it is not needed here.
    assert status(admin, rid) == "pending" and orders(admin) == 0 and errors(admin) == []


def test_approval_given_before_the_assessment_does_not_count(admin, as_role, settings, now):  # gap N3
    ex, staff = as_role("executor"), as_role("approver")
    rid = add_moveout(admin, tier=None)
    approve(staff, rid, ANNA)  # the request has no tier yet
    assess(admin, rid, "T1")
    process_moveouts(ex, settings, now)
    assert status(admin, rid) == "pending" and orders(admin) == 0 and errors(admin) == []
    approve(staff, rid, PETROS)  # a fresh approval, after the assessment
    process_moveouts(ex, settings, now)
    assert status(admin, rid) == "executed" and orders(admin) == 1


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


def test_t2_needs_two_distinct_approvers(admin, as_role, settings, now):
    ex, staff = as_role("executor"), as_role("approver")
    rid = add_moveout(admin, tier="T2")
    approve(staff, rid, ANNA)
    process_moveouts(ex, settings, now)
    # Waiting for the second person, quietly: the trigger was never asked.
    assert status(admin, rid) == "pending" and orders(admin) == 0 and errors(admin) == []
    with pytest.raises(psycopg.errors.RaiseException, match="needs 2 distinct approvals"):
        insert_order(ex, rid, "SP-1001")
    assert approve(staff, rid, ANNA) is False  # the same person again is still one
    process_moveouts(ex, settings, now)
    assert status(admin, rid) == "pending" and orders(admin) == 0
    approve(staff, rid, PETROS)
    process_moveouts(ex, settings, now)
    assert status(admin, rid) == "executed" and orders(admin) == 1


def test_approver_cannot_choose_the_approval_time(admin, as_role):  # gap N3
    rid = add_moveout(admin)
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        as_role("approver").execute(
            "INSERT INTO approvals (request_id, approver, created_at) VALUES (%s, 'eeab6c5e-f5bc-5d16-af4b-813d9b88be01', now() + interval '1 year')",
            (rid,),
        )


def test_protected_home_goes_to_manual_only_and_never_gets_an_order(admin, as_role, settings, now):  # ⑦
    ex, staff = as_role("executor"), as_role("approver")
    rid = add_moveout(admin, account_id=3, ticket_id=3)
    process_moveouts(ex, settings, now)
    assert status(admin, rid) == "manual_only"
    approve(staff, rid, ANNA)
    approve(staff, rid, PETROS)
    process_moveouts(ex, settings, now)
    assert status(admin, rid) == "manual_only" and orders(admin) == 0
    # Whatever the executor's code does, the database refuses the row. Put the request back to
    # pending, so that only the flag is wrong: assessed, two approvals, date today.
    admin.execute("UPDATE action_requests SET status = 'pending' WHERE id = %s", (rid,))
    with pytest.raises(psycopg.errors.RaiseException, match="protected"):
        insert_order(ex, rid, "SP-1003")
    assert orders(admin) == 0


def test_order_refused_when_flag_added_after_assessment(admin, as_role, settings, now):
    ex, staff = as_role("executor"), as_role("approver")
    rid = ready_for_order(admin, staff)  # assessed T1, approved, date today, no flag yet
    set_temp_protection(as_role("tool_set_temp_protection"), open_lease(admin, 1))
    with pytest.raises(psycopg.errors.RaiseException, match="protected"):
        insert_order(ex, rid, "SP-1001")
    process_moveouts(ex, settings, now)
    assert status(admin, rid) == "manual_only" and orders(admin) == 0 and errors(admin) == []


def test_same_approver_twice_is_rejected(admin, as_role):  # ⑥
    staff, ex = as_role("approver"), as_role("executor")
    rid = add_moveout(admin)
    assert approve(staff, rid, ANNA) is True
    assert approve(staff, rid, ANNA) is False
    assert approver_count(ex, rid) == 1
    assert approve(staff, rid, PETROS) is True
    assert approver_count(ex, rid) == 2


def test_one_bad_request_does_not_block_the_batch(admin, as_role, settings, now):
    # The first request already has an order row (written behind the executor's back), so its own
    # order insert fails on the unique request id; the second one goes on.
    staff = as_role("approver")
    first, second = ready_for_order(admin, staff), ready_for_order(admin, staff, account_id=1, ticket_id=2)
    admin.execute(
        "INSERT INTO disconnection_orders (request_id, supply_point_id) VALUES (%s, 'SP-1001')", (first,)
    )
    process_moveouts(as_role("executor"), settings, now)
    assert status(admin, first) == "pending"
    assert status(admin, second) == "executed"
    assert errors(admin) == [f"move_out request={first}: UniqueViolation"]


def insert_order(conn, request_id, supply_point_id):
    conn.execute(
        "INSERT INTO disconnection_orders (request_id, supply_point_id) VALUES (%s, %s)",
        (request_id, supply_point_id),
    )


def test_database_accepts_order_when_the_whole_story_holds(admin, as_role):
    # Control for the refusals below: each of them breaks one condition of this setup.
    rid = ready_for_order(admin, as_role("approver"))
    insert_order(as_role("executor"), rid, "SP-1001")
    assert orders(admin) == 1


def test_database_refuses_order_at_protected_home(admin, as_role):  # ⑦ wall below the executor code
    rid = ready_for_order(admin, as_role("approver"), account_id=3, ticket_id=3)
    with pytest.raises(psycopg.errors.RaiseException, match="protected"):
        insert_order(as_role("executor"), rid, "SP-1003")
    assert orders(admin) == 0


def _credit_request_with_approval(admin, staff):
    # Everything else holds, move-out date included, so only the request kind is wrong.
    admin.execute(
        "INSERT INTO action_requests (kind, ticket_id, account_id, amount_eur, reason, evidence_ref, move_out_date) "
        "VALUES ('credit', 1, 1, 49, 'duplicate_charge', 2, %s)",
        (utc_today(),),
    )
    rid = admin.execute("SELECT max(id) AS id FROM action_requests").fetchone()["id"]
    assess(admin, rid, "T1")
    approve(staff, rid, ANNA)
    return rid, "SP-1001"


def _no_approval(admin, staff):
    return add_moveout(admin), "SP-1001"


def _approval_before_assessment(admin, staff):
    rid = add_moveout(admin, tier=None)
    approve(staff, rid, ANNA)
    assess(admin, rid, "T1")
    return rid, "SP-1001"


def _future_date(admin, staff):
    return ready_for_order(admin, staff, move_out_date=utc_today() + timedelta(days=1)), "SP-1001"


BROKEN_STORIES = {
    # Gap I2: the old trigger compared one string with the flags table and nothing else.
    "trailing space": lambda admin, staff: (ready_for_order(admin, staff, 3, 3), "SP-1003 "),
    "lower case": lambda admin, staff: (ready_for_order(admin, staff, 3, 3), "sp-1003"),
    "another home": lambda admin, staff: (ready_for_order(admin, staff, 3, 3), "SP-1002"),
    "credit request": _credit_request_with_approval,
    "unknown request": lambda admin, staff: (999, "SP-1001"),
    "no approval": _no_approval,
    "approval older than the assessment": _approval_before_assessment,
    "move-out date in the future": _future_date,
}


@pytest.mark.parametrize("story", BROKEN_STORIES)
def test_database_refuses_order_unless_the_whole_story_holds(admin, as_role, story):
    rid, home = BROKEN_STORIES[story](admin, as_role("approver"))
    with pytest.raises(psycopg.errors.RaiseException):
        insert_order(as_role("executor"), rid, home)
    assert orders(admin) == 0


@pytest.mark.parametrize("held", ["manual_only", "rejected", "executed", "refused"])
def test_database_refuses_order_unless_the_request_is_pending(admin, as_role, held):
    # Final review F3: every other condition holds, so only the request status is wrong.
    # manual_only is a human's job; rejected, refused and executed are finished.
    rid = ready_for_order(admin, as_role("approver"))
    admin.execute("UPDATE action_requests SET status = %s WHERE id = %s", (held, rid))
    with pytest.raises(psycopg.errors.RaiseException, match="not pending"):
        insert_order(as_role("executor"), rid, "SP-1001")
    assert orders(admin) == 0


def test_order_home_must_be_a_real_supply_point_even_without_the_trigger(admin):
    rid = add_moveout(admin)
    # Always rolled back, so the trigger is enabled again afterwards whatever happens inside.
    with admin.transaction(force_rollback=True):
        admin.execute("ALTER TABLE disconnection_orders DISABLE TRIGGER disconnection_orders_check")
        with pytest.raises(psycopg.errors.ForeignKeyViolation):
            with admin.transaction():
                insert_order(admin, rid, "SP-1001 ")


def test_executor_cannot_choose_the_time_of_an_order(admin, as_role):
    rid = add_moveout(admin)
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        as_role("executor").execute(
            "INSERT INTO disconnection_orders (request_id, supply_point_id, created_at) "
            "VALUES (%s, 'SP-1001', now() - interval '100 hours')",
            (rid,),
        )


def test_there_is_no_notice_table_or_register_for_the_executor_to_use(admin):
    rows = admin.execute(
        "SELECT relname FROM pg_class WHERE relkind = 'r' AND relname IN ('occupier_notices', 'register_sync')"
    ).fetchall()
    assert rows == []


def test_flag_waits_while_the_executor_holds_the_home(admin, as_role):
    ex, tool = as_role("executor"), as_role("tool_set_temp_protection")
    lease = open_lease(admin, 1)
    tool.execute("SET lock_timeout = '200ms'")
    with ex.transaction():
        ex.execute("SELECT pg_advisory_xact_lock(hashtext('SP-1001'))")
        with pytest.raises(psycopg.errors.LockNotAvailable):
            set_temp_protection(tool, lease)
    set_temp_protection(tool, lease)  # lock released at commit


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


def test_executor_takes_the_home_lock(admin, as_role, settings, now):  # gap I4
    # Ready for an order: if the request leaves 'pending' while someone else holds the home lock,
    # the executor went on without taking the lock itself.
    rid = ready_for_order(admin, as_role("approver"))
    ex = as_role("executor")
    ex.execute("SET lock_timeout = '300ms'")  # the role's 5 s keeps the test slow for no gain
    admin.execute("SELECT pg_advisory_lock(hashtext('SP-1001'))")
    try:
        started = time.monotonic()
        process_moveouts(ex, settings, now)
        took = time.monotonic() - started
    finally:
        admin.execute("SELECT pg_advisory_unlock_all()")
    assert took < 3
    assert status(admin, rid) == "pending" and orders(admin) == 0
    assert errors(admin) == [f"move_out request={rid}: LockNotAvailable"]
    process_moveouts(ex, settings, now)  # lock released: the same request now moves on
    assert status(admin, rid) == "executed"


def test_trigger_takes_the_home_lock(admin, as_role):  # gap I4
    rid = ready_for_order(admin, as_role("approver"))
    ex = as_role("executor")
    ex.execute("SET lock_timeout = '300ms'")
    admin.execute("SELECT pg_advisory_lock(hashtext('SP-1001'))")
    try:
        # Straight into the table: no executor code, so only the trigger can be waiting.
        with pytest.raises(psycopg.errors.LockNotAvailable):
            insert_order(ex, rid, "SP-1001")
    finally:
        admin.execute("SELECT pg_advisory_unlock_all()")
    assert orders(admin) == 0
    insert_order(ex, rid, "SP-1001")  # control: without the lock held the same insert works
    assert orders(admin) == 1


# --- risk tiers. HUMAN_ONLY ends at manual_only and REJECT at rejected, whatever the approvals.

def test_human_only_move_out_goes_to_manual_only_even_at_an_unprotected_home(admin, as_role, settings, now):
    rid = add_moveout(admin, tier="HUMAN_ONLY")  # SP-1001: the executor's own check would say NO
    process_moveouts(as_role("executor"), settings, now)
    assert status(admin, rid) == "manual_only" and orders(admin) == 0
    reason = admin.execute("SELECT decision_reason FROM action_requests WHERE id = %s", (rid,)).fetchone()
    assert reason["decision_reason"] == "risk: tier HUMAN_ONLY"


def test_rejected_move_out_is_rejected(admin, as_role, settings, now):
    rid = add_moveout(admin, tier="REJECT")
    process_moveouts(as_role("executor"), settings, now)
    assert status(admin, rid) == "rejected" and orders(admin) == 0


def test_executor_has_no_move_out_rate_limit(admin, as_role, settings, now):
    # The flood hold is gone: every ready request is looked at, and none is held.
    staff = as_role("approver")
    ids = [ready_for_order(admin, staff) for _ in range(25)]
    process_moveouts(as_role("executor"), settings, now)
    assert {status(admin, rid) for rid in ids} == {"executed"}
    assert admin.execute("SELECT count(*) AS n FROM events WHERE kind = 'ALERT'").fetchone()["n"] == 0
