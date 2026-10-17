import time
from datetime import datetime, timedelta, timezone

import psycopg
import pytest

from app.executor.approvals import approve, approver_count
from app.executor.moveouts import process_moveouts
from app.tools.set_temp_protection import set_temp_protection
from tests.conftest import assess, open_lease

# The order trigger uses the database clock, so the tests never jump time with the executor's
# `now`. They back-date rows as admin instead: notices, approvals, the register sync.


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


def synced_at(admin, when):
    """Pretend the state register last synced at `when`."""
    admin.execute("UPDATE register_sync SET last_success = %s", (when,))


def back_date_notice(admin, request_id, hours):
    admin.execute(
        "UPDATE occupier_notices SET sent_at = now() - make_interval(hours => %s) WHERE request_id = %s",
        (hours, request_id),
    )


def back_date_approvals(admin, request_id, hours):
    admin.execute(
        "UPDATE approvals SET created_at = now() - make_interval(hours => %s) WHERE request_id = %s",
        (hours, request_id),
    )


def ready_for_order(admin, staff, account_id=1, ticket_id=1, move_out_date=None) -> int:
    """A move-out where every condition for an order holds: a T1 risk assessment, notice sent
    73 hours ago, a staff approval after it, move-out date today. Tests break one condition at a time."""
    rid = add_moveout(admin, account_id, ticket_id, move_out_date)
    admin.execute(
        "INSERT INTO occupier_notices (request_id, supply_point_id, sent_at) "
        "SELECT %s, supply_point_id, now() - interval '73 hours' FROM accounts WHERE id = %s",
        (rid, account_id),
    )
    admin.execute("UPDATE action_requests SET status = 'notice_sent' WHERE id = %s", (rid,))
    approve(staff, rid, "staff.anna")
    return rid


def test_unprotected_needs_notice_wait_and_approval(admin, as_role, settings, now):
    ex, staff = as_role("executor"), as_role("approver")
    rid = add_moveout(admin)
    process_moveouts(ex, settings, now)
    assert status(admin, rid) == "notice_sent"
    approve(staff, rid, "staff.anna")
    process_moveouts(ex, settings, now)
    # Still waiting: the executor's own check holds it, so the trigger never has to refuse.
    assert status(admin, rid) == "notice_sent" and orders(admin) == 0 and errors(admin) == []
    back_date_notice(admin, rid, settings.occupier_wait_hours + 1)
    process_moveouts(ex, settings, now)
    assert status(admin, rid) == "executed" and orders(admin) == 1
    assert errors(admin) == []


def test_no_order_before_the_move_out_date(admin, as_role, settings, now):  # gap N1
    ex, staff = as_role("executor"), as_role("approver")
    rid = ready_for_order(admin, staff, move_out_date=utc_today() + timedelta(days=30))
    process_moveouts(ex, settings, now)
    # The executor waits by itself; the trigger would refuse too, but it is not needed here.
    assert status(admin, rid) == "notice_sent" and orders(admin) == 0 and errors(admin) == []


def test_approval_given_before_the_notice_does_not_count(admin, as_role, settings, now):  # gap N3
    ex, staff = as_role("executor"), as_role("approver")
    rid = ready_for_order(admin, staff)
    back_date_approvals(admin, rid, 80)  # the notice is 73 hours old
    process_moveouts(ex, settings, now)
    assert status(admin, rid) == "notice_sent" and orders(admin) == 0 and errors(admin) == []
    approve(staff, rid, "staff.petros")  # a fresh approval, after the notice
    process_moveouts(ex, settings, now)
    assert status(admin, rid) == "executed" and orders(admin) == 1


def notice_73_hours_ago(admin, rid, account_id=1):
    admin.execute(
        "INSERT INTO occupier_notices (request_id, supply_point_id, sent_at) "
        "SELECT %s, supply_point_id, now() - interval '73 hours' FROM accounts WHERE id = %s",
        (rid, account_id),
    )
    admin.execute("UPDATE action_requests SET status = 'notice_sent' WHERE id = %s", (rid,))


def test_no_order_without_approval(admin, as_role, settings, now):  # gap I4
    ex = as_role("executor")
    rid = add_moveout(admin)
    notice_73_hours_ago(admin, rid)  # notice, wait and move-out date are all fine; no staff approval
    process_moveouts(ex, settings, now)
    # No executor_error: the executor's own approver_count check held it, the trigger was never asked.
    assert status(admin, rid) == "notice_sent" and orders(admin) == 0 and errors(admin) == []
    approve(as_role("approver"), rid, "staff.anna")  # control: the same request goes through with one
    process_moveouts(ex, settings, now)
    assert status(admin, rid) == "executed" and orders(admin) == 1 and errors(admin) == []


def test_no_order_before_wait(admin, as_role, settings, now):  # gap I4
    ex = as_role("executor")
    rid = ready_for_order(admin, as_role("approver"))
    back_date_notice(admin, rid, settings.occupier_wait_hours - 1)  # 71 hours
    process_moveouts(ex, settings, now)
    # No executor_error: the executor's own `waited` check held it, the trigger was never asked.
    assert status(admin, rid) == "notice_sent" and orders(admin) == 0 and errors(admin) == []
    back_date_notice(admin, rid, settings.occupier_wait_hours + 1)  # control: 73 hours
    process_moveouts(ex, settings, now)
    assert status(admin, rid) == "executed" and orders(admin) == 1 and errors(admin) == []


def test_approver_cannot_choose_the_approval_time(admin, as_role):  # gap N3
    rid = add_moveout(admin)
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        as_role("approver").execute(
            "INSERT INTO approvals (request_id, approver, created_at) VALUES (%s, 'staff.anna', now() + interval '1 year')",
            (rid,),
        )


def test_protected_home_never_gets_order(admin, as_role, settings, now):  # ⑦
    ex, staff = as_role("executor"), as_role("approver")
    rid = add_moveout(admin, account_id=3, ticket_id=3)
    process_moveouts(ex, settings, now)
    assert status(admin, rid) == "manual_only"
    approve(staff, rid, "staff.anna")
    approve(staff, rid, "staff.petros")
    process_moveouts(ex, settings, now)
    assert status(admin, rid) == "manual_only" and orders(admin) == 0


def test_stale_register_means_protected(admin, as_role, settings, now):  # fail closed
    admin.execute("UPDATE register_sync SET last_success = now() - interval '48 hours'")
    rid = add_moveout(admin)
    process_moveouts(as_role("executor"), settings, now)
    assert status(admin, rid) == "manual_only"


def test_flag_raised_after_notice_stops_order(admin, as_role, settings, now):
    ex, staff = as_role("executor"), as_role("approver")
    rid = add_moveout(admin)
    process_moveouts(ex, settings, now)
    set_temp_protection(as_role("tool_set_temp_protection"), open_lease(admin, 1))
    back_date_notice(admin, rid, settings.occupier_wait_hours + 1)
    approve(staff, rid, "staff.anna")
    process_moveouts(ex, settings, now)
    assert status(admin, rid) == "manual_only" and orders(admin) == 0


def test_flood_is_rate_limited_and_alerts(admin, as_role, settings, now):  # ⑤
    for _ in range(50):
        add_moveout(admin)
    process_moveouts(as_role("executor"), settings, now)
    counts = {
        r["status"]: r["n"]
        for r in admin.execute("SELECT status, count(*) AS n FROM action_requests GROUP BY status")
    }
    assert counts == {"notice_sent": settings.moveout_max_per_hour, "held_rate_limit": 50 - settings.moveout_max_per_hour}
    alerts = admin.execute("SELECT count(*) AS n FROM events WHERE kind = 'ALERT'").fetchone()["n"]
    assert alerts == 1


def test_forged_alert_does_not_silence_the_flood_alert(admin, as_role, settings, now):
    # Tools cannot write events at all any more (05-lease.sql); the approver still can.
    as_role("approver").execute(
        "INSERT INTO events (kind, detail) VALUES ('ALERT', 'move-out rate limit reached')"
    )
    for _ in range(50):
        add_moveout(admin)
    process_moveouts(as_role("executor"), settings, now)
    rows = admin.execute(
        "SELECT actor FROM events WHERE kind = 'ALERT' AND detail = 'move-out rate limit reached' "
        "AND actor = 'executor'"
    ).fetchall()
    assert len(rows) == 1


def test_same_approver_twice_is_rejected(admin, as_role):  # ⑥
    staff, ex = as_role("approver"), as_role("executor")
    rid = add_moveout(admin)
    assert approve(staff, rid, "staff.anna") is True
    assert approve(staff, rid, "staff.anna") is False
    assert approver_count(ex, rid) == 1
    assert approve(staff, rid, "staff.petros") is True
    assert approver_count(ex, rid) == 2


def test_one_bad_request_does_not_block_the_batch(admin, as_role, settings, now):
    first, second = add_moveout(admin), add_moveout(admin, account_id=1, ticket_id=2)
    admin.execute(
        "INSERT INTO occupier_notices (request_id, supply_point_id, sent_at) VALUES (%s, 'SP-1001', %s)",
        (first, now),
    )
    process_moveouts(as_role("executor"), settings, now)
    assert status(admin, first) == "pending"
    assert status(admin, second) == "notice_sent"
    assert errors(admin) == [f"move_out request={first}: UniqueViolation"]


def test_rate_limit_counts_old_backlog(admin, as_role, settings, now):
    for _ in range(25):
        rid = add_moveout(admin)
        admin.execute("UPDATE action_requests SET created_at = now() - interval '3 hours' WHERE id = %s", (rid,))
    process_moveouts(as_role("executor"), settings, now)
    counts = {
        r["status"]: r["n"]
        for r in admin.execute("SELECT status, count(*) AS n FROM action_requests GROUP BY status")
    }
    assert counts == {"notice_sent": settings.moveout_max_per_hour, "held_rate_limit": 25 - settings.moveout_max_per_hour}


def test_protected_home_with_notice_and_two_approvals_still_gets_no_order(admin, as_role, settings, now):
    ex, staff = as_role("executor"), as_role("approver")
    rid = ready_for_order(admin, staff, account_id=3, ticket_id=3)
    approve(staff, rid, "staff.petros")
    process_moveouts(ex, settings, now)
    assert status(admin, rid) == "manual_only" and orders(admin) == 0


def test_stale_register_after_notice_stops_order(admin, as_role, settings, now):
    ex, staff = as_role("executor"), as_role("approver")
    rid = add_moveout(admin)
    process_moveouts(ex, settings, now)
    assert status(admin, rid) == "notice_sent"
    back_date_notice(admin, rid, settings.occupier_wait_hours + 1)
    approve(staff, rid, "staff.anna")
    synced_at(admin, now - timedelta(hours=48))
    process_moveouts(ex, settings, now)
    assert status(admin, rid) == "manual_only" and orders(admin) == 0


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


def test_database_refuses_order_when_register_is_stale(admin, as_role, now):
    rid = ready_for_order(admin, as_role("approver"))
    synced_at(admin, now - timedelta(hours=48))
    with pytest.raises(psycopg.errors.RaiseException, match="register"):
        insert_order(as_role("executor"), rid, "SP-1001")
    assert orders(admin) == 0


def _credit_request_with_notice_and_approval(admin, staff):
    # Everything else holds, move-out date included, so only the request kind is wrong.
    admin.execute(
        "INSERT INTO action_requests (kind, ticket_id, account_id, amount_eur, reason, evidence_ref, move_out_date) "
        "VALUES ('credit', 1, 1, 49, 'duplicate_charge', 2, %s)",
        (utc_today(),),
    )
    rid = admin.execute("SELECT max(id) AS id FROM action_requests").fetchone()["id"]
    assess(admin, rid, "T1")
    admin.execute(
        "INSERT INTO occupier_notices (request_id, supply_point_id, sent_at) "
        "VALUES (%s, 'SP-1001', now() - interval '73 hours')",
        (rid,),
    )
    approve(staff, rid, "staff.anna")
    return rid, "SP-1001"


def _no_notice(admin, staff):
    rid = add_moveout(admin)
    approve(staff, rid, "staff.anna")
    return rid, "SP-1001"


def _young_notice(admin, staff):
    rid = ready_for_order(admin, staff)
    back_date_notice(admin, rid, 71)
    return rid, "SP-1001"


def _approval_before_notice(admin, staff):
    rid = ready_for_order(admin, staff)
    back_date_approvals(admin, rid, 80)  # the notice is 73 hours old
    return rid, "SP-1001"


def _notice_to_another_home(admin, staff):
    # The occupier at SP-1002 was told; nobody at SP-1001 was.
    rid = ready_for_order(admin, staff)
    admin.execute("UPDATE occupier_notices SET supply_point_id = 'SP-1002' WHERE request_id = %s", (rid,))
    return rid, "SP-1001"


def _future_date(admin, staff):
    return ready_for_order(admin, staff, move_out_date=utc_today() + timedelta(days=1)), "SP-1001"


BROKEN_STORIES = {
    # Gap I2: the old trigger compared one string with the flags table and nothing else.
    "trailing space": lambda admin, staff: (ready_for_order(admin, staff, 3, 3), "SP-1003 "),
    "lower case": lambda admin, staff: (ready_for_order(admin, staff, 3, 3), "sp-1003"),
    "another home": lambda admin, staff: (ready_for_order(admin, staff, 3, 3), "SP-1002"),
    "credit request": _credit_request_with_notice_and_approval,
    "unknown request": lambda admin, staff: (999, "SP-1001"),
    "no notice": _no_notice,
    "notice under 72 hours": _young_notice,
    "notice to another home": _notice_to_another_home,
    "approval older than the notice": _approval_before_notice,
    "move-out date in the future": _future_date,
}


@pytest.mark.parametrize("story", BROKEN_STORIES)
def test_database_refuses_order_unless_the_whole_story_holds(admin, as_role, story):
    rid, home = BROKEN_STORIES[story](admin, as_role("approver"))
    with pytest.raises(psycopg.errors.RaiseException):
        insert_order(as_role("executor"), rid, home)
    assert orders(admin) == 0


@pytest.mark.parametrize("held", ["pending", "manual_only", "held_rate_limit", "executed"])
def test_database_refuses_order_unless_the_request_is_at_notice_sent(admin, as_role, held):
    # Final review F3: every other condition holds, so only the request status is wrong.
    # manual_only is a human's job; held_rate_limit waits for a human to release it.
    rid = ready_for_order(admin, as_role("approver"))
    admin.execute("UPDATE action_requests SET status = %s WHERE id = %s", (held, rid))
    with pytest.raises(psycopg.errors.RaiseException, match="notice_sent"):
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


def test_notice_home_must_be_a_real_supply_point(admin):
    rid = add_moveout(admin)
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        admin.execute(
            "INSERT INTO occupier_notices (request_id, supply_point_id) VALUES (%s, 'SP-1001 ')", (rid,)
        )


@pytest.mark.parametrize("table, column", [("occupier_notices", "sent_at"), ("disconnection_orders", "created_at")])
def test_executor_cannot_choose_the_time_of_a_notice_or_order(admin, as_role, table, column):
    # A back-dated notice would skip the 72-hour wait; the database sets these times itself.
    rid = add_moveout(admin)
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        as_role("executor").execute(
            f"INSERT INTO {table} (request_id, supply_point_id, {column}) "
            "VALUES (%s, 'SP-1001', now() - interval '100 hours')",
            (rid,),
        )


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
    first = add_moveout(admin)  # SP-1001
    second = add_moveout(admin, account_id=2, ticket_id=2)  # SP-1002
    # Someone else holds SP-1001's lock and never lets go (admin here; a tool role can no longer).
    admin.execute("SELECT pg_advisory_lock(hashtext('SP-1001'))")
    try:
        started = time.monotonic()
        process_moveouts(as_role("executor"), settings, now)
        took = time.monotonic() - started
    finally:
        admin.execute("SELECT pg_advisory_unlock_all()")
    assert took < 10  # lock_timeout is 5 s for every executor session
    assert status(admin, first) == "pending" and status(admin, second) == "notice_sent"
    assert errors(admin) == [f"move_out request={first}: LockNotAvailable"]


def test_executor_takes_the_home_lock(admin, as_role, settings, now):  # gap I4
    # A pending request needs no order, so the trigger's lock is not involved: if the request
    # leaves 'pending', the executor went on without taking the home lock itself.
    rid = add_moveout(admin)
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
    assert status(admin, rid) == "pending"
    assert admin.execute("SELECT count(*) AS n FROM occupier_notices").fetchone()["n"] == 0
    assert errors(admin) == [f"move_out request={rid}: LockNotAvailable"]
    process_moveouts(ex, settings, now)  # lock released: the same request now moves on
    assert status(admin, rid) == "notice_sent"


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


# --- risk tiers. A move-out's approvals count only after the occupier notice (the order rule), so
# the executor waits for the tier's approvals at the order step: T1 one person, T2 two, HOLD two
# SeniorApprovers. A HOLD also waits for two SeniorApprovers before its notice. HUMAN_ONLY ends at
# manual_only without a notice.

def test_t2_move_out_needs_two_approvals_after_the_notice(admin, as_role, settings, now):
    from tests.conftest import approve_as

    ex, staff = as_role("executor"), as_role("approver")
    rid = add_moveout(admin, tier="T2")
    notice_73_hours_ago(admin, rid)
    approve_as(staff, rid, "staff.anna")
    process_moveouts(ex, settings, now)
    # Waiting for the second person, quietly: the trigger was never asked.
    assert status(admin, rid) == "notice_sent" and orders(admin) == 0 and errors(admin) == []
    approve_as(staff, rid, "staff.petros")
    process_moveouts(ex, settings, now)
    assert status(admin, rid) == "executed" and orders(admin) == 1


def notices(admin):
    return admin.execute("SELECT count(*) AS n FROM occupier_notices").fetchone()["n"]


def test_hold_move_out_sends_no_notice_until_two_seniors_release_it(admin, as_role, settings, now):
    # A flood of move-outs (tier HOLD) may be fake requests: a notice would frighten real occupiers
    # for nothing. So two SeniorApprovers release a held request before its notice goes out.
    from tests.conftest import approve_as

    ex, staff = as_role("executor"), as_role("approver")
    rid = add_moveout(admin, tier="HOLD")
    control = add_moveout(admin, ticket_id=2)  # T1, same home: its notice goes out on the first run
    process_moveouts(ex, settings, now)
    assert status(admin, rid) == "pending" and status(admin, control) == "notice_sent"
    assert notices(admin) == 1 and errors(admin) == []
    approve_as(staff, rid, "senior.anna", "SeniorApprover")
    approve_as(staff, rid, "staff.petros", "Approver")  # not a senior: does not count
    process_moveouts(ex, settings, now)
    assert status(admin, rid) == "pending" and notices(admin) == 1 and errors(admin) == []
    approve_as(staff, rid, "senior.ioanna", "SeniorApprover")
    process_moveouts(ex, settings, now)
    assert status(admin, rid) == "notice_sent" and notices(admin) == 2 and errors(admin) == []


def test_released_hold_move_out_still_needs_two_seniors_after_the_notice(admin, as_role, settings, now):
    from tests.conftest import approve_as

    ex, staff = as_role("executor"), as_role("approver")
    rid = add_moveout(admin, tier="HOLD")
    approve_as(staff, rid, "senior.anna", "SeniorApprover")
    approve_as(staff, rid, "senior.ioanna", "SeniorApprover")
    process_moveouts(ex, settings, now)
    assert status(admin, rid) == "notice_sent"
    # 73 hours later. The release came before the notice, so it does not count for the order.
    back_date_approvals(admin, rid, 74)
    back_date_notice(admin, rid, 73)
    process_moveouts(ex, settings, now)
    assert status(admin, rid) == "notice_sent" and orders(admin) == 0 and errors(admin) == []
    approve_as(staff, rid, "senior.petros", "SeniorApprover")
    approve_as(staff, rid, "staff.eleni", "Approver")
    process_moveouts(ex, settings, now)
    assert status(admin, rid) == "notice_sent" and orders(admin) == 0 and errors(admin) == []
    approve_as(staff, rid, "senior.nikos", "SeniorApprover")
    process_moveouts(ex, settings, now)
    assert status(admin, rid) == "executed" and orders(admin) == 1


def insert_notice(conn, request_id, supply_point_id="SP-1001"):
    conn.execute(
        "INSERT INTO occupier_notices (request_id, supply_point_id) VALUES (%s, %s)", (request_id, supply_point_id)
    )


def test_database_refuses_notice_for_a_held_move_out_without_two_seniors(admin, as_role):
    # The same rule below the executor code: check_occupier_notice (db/sql/06-risk.sql).
    from tests.conftest import approve_as

    ex, staff = as_role("executor"), as_role("approver")
    rid = add_moveout(admin, tier="HOLD")
    with pytest.raises(psycopg.errors.RaiseException, match="SeniorApprover"):
        insert_notice(ex, rid)
    approve_as(staff, rid, "senior.anna", "SeniorApprover")
    approve_as(staff, rid, "staff.petros", "Approver")
    with pytest.raises(psycopg.errors.RaiseException, match="SeniorApprover"):
        insert_notice(ex, rid)
    assert notices(admin) == 0
    approve_as(staff, rid, "senior.ioanna", "SeniorApprover")
    insert_notice(ex, rid)  # released
    insert_notice(ex, add_moveout(admin, ticket_id=2))  # control: T1 needs no release
    assert notices(admin) == 2


def test_release_given_before_the_assessment_does_not_count(admin, as_role):
    from tests.conftest import approve_as

    ex, staff = as_role("executor"), as_role("approver")
    rid = add_moveout(admin, tier=None)
    approve_as(staff, rid, "senior.anna", "SeniorApprover")
    approve_as(staff, rid, "senior.ioanna", "SeniorApprover")
    assess(admin, rid, "HOLD")
    with pytest.raises(psycopg.errors.RaiseException, match="SeniorApprover"):
        insert_notice(ex, rid)


def released_hold_notice_73_hours_ago(admin, rid, account_id=1):
    """A HOLD move-out whose two seniors released it and whose notice went out 73 hours ago. The
    release approvals are moved before the notice, so they do not count for the order."""
    for who in ("senior.release.1", "senior.release.2"):
        admin.execute(
            "INSERT INTO approvals (request_id, approver, approver_role) VALUES (%s, %s, 'SeniorApprover')", (rid, who)
        )
    notice_73_hours_ago(admin, rid, account_id)
    back_date_approvals(admin, rid, 74)


def test_human_only_move_out_gets_no_notice_even_at_an_unprotected_home(admin, as_role, settings, now):
    rid = add_moveout(admin, tier="HUMAN_ONLY")  # SP-1001: the executor's own check would say NO
    process_moveouts(as_role("executor"), settings, now)
    assert status(admin, rid) == "manual_only"
    assert admin.execute("SELECT count(*) AS n FROM occupier_notices").fetchone()["n"] == 0
    reason = admin.execute("SELECT decision_reason FROM action_requests WHERE id = %s", (rid,)).fetchone()
    assert reason["decision_reason"] == "risk: tier HUMAN_ONLY"


def test_rejected_move_out_is_rejected(admin, as_role, settings, now):
    rid = add_moveout(admin, tier="REJECT")
    process_moveouts(as_role("executor"), settings, now)
    assert status(admin, rid) == "rejected" and orders(admin) == 0


# --- the outside world: the grid operator (DSO) gets each order, the SMS provider each notice ---

@pytest.fixture
def outside_world():
    from app.executor.outside import OutsideCalls
    from app.fakes import FAKES, start_fake

    dso = start_fake(FAKES["dso"], port=0, mode="compose", host="127.0.0.1")
    sms = start_fake(FAKES["sms"], port=0, mode="compose", host="127.0.0.1")
    outside = OutsideCalls(f"http://127.0.0.1:{dso.port}/orders", f"http://127.0.0.1:{sms.port}/messages")
    yield dso, sms, outside
    dso.shutdown()
    sms.shutdown()


def row_id(admin, table, rid):
    return admin.execute(f"SELECT id FROM {table} WHERE request_id = %s", (rid,)).fetchone()["id"]


def test_executor_calls_fake_dso_once_per_order(admin, as_role, settings, now, outside_world):
    dso, sms, outside = outside_world
    ex = as_role("executor")
    rid = add_moveout(admin)
    process_moveouts(ex, settings, now, outside=outside)
    assert status(admin, rid) == "notice_sent"
    notice = {"request_id": rid, "notice_id": row_id(admin, "occupier_notices", rid), "supply_point_id": "SP-1001"}
    assert [c["body"] for c in sms.calls()] == [notice] and dso.calls() == []
    back_date_notice(admin, rid, settings.occupier_wait_hours + 1)
    approve(as_role("approver"), rid, "staff.anna")
    for _ in range(3):  # the order run and two more: the call is made once, with the order
        process_moveouts(ex, settings, now, outside=outside)
    assert status(admin, rid) == "executed" and orders(admin) == 1
    order = {"request_id": rid, "order_id": row_id(admin, "disconnection_orders", rid), "supply_point_id": "SP-1001"}
    assert [c["body"] for c in dso.calls()] == [order]
    assert [c["body"] for c in sms.calls()] == [notice]
    assert errors(admin) == []


def test_no_outside_call_for_a_request_that_gets_no_effect(admin, as_role, settings, now, outside_world):
    dso, sms, outside = outside_world
    add_moveout(admin, account_id=3, ticket_id=3)  # protected home: manual_only
    add_moveout(admin, tier="HOLD")  # waits for its release
    add_moveout(admin, tier="HUMAN_ONLY")
    process_moveouts(as_role("executor"), settings, now, outside=outside)
    assert dso.calls() == [] and sms.calls() == []


def closed_port():
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def outside_failures(admin):
    return [r["detail"] for r in admin.execute("SELECT detail FROM events WHERE kind = 'outside_call_failed' ORDER BY id")]


def test_failed_dso_call_is_logged_counted_and_never_becomes_a_second_order(admin, as_role, settings, now):
    from app.common.ops import Metrics
    from app.executor.outside import OutsideCalls

    down = f"http://127.0.0.1:{closed_port()}"
    outside = OutsideCalls(f"{down}/orders", f"{down}/messages", timeout_s=2)
    metrics = Metrics()
    ex = as_role("executor")
    rid = ready_for_order(admin, as_role("approver"))
    process_moveouts(ex, settings, now, metrics, outside=outside)
    # The order stands (it is the database's record); the call failed and says so.
    assert status(admin, rid) == "executed" and orders(admin) == 1
    assert outside_failures(admin) == [f"dso move_out request={rid}: URLError"]
    lines = metrics.render().splitlines()
    assert 'executor_outside_calls_total{outcome="error",target="dso"} 1' in lines
    for _ in range(2):  # no retry, and no second order
        process_moveouts(ex, settings, now, metrics, outside=outside)
    assert orders(admin) == 1 and len(outside_failures(admin)) == 1
    assert 'executor_outside_calls_total{outcome="error",target="dso"} 1' in metrics.render().splitlines()
    assert errors(admin) == []


def test_failed_sms_call_leaves_the_notice_in_place(admin, as_role, settings, now):
    from app.common.ops import Metrics
    from app.executor.outside import OutsideCalls

    down = f"http://127.0.0.1:{closed_port()}"
    metrics = Metrics()
    rid = add_moveout(admin)
    outside = OutsideCalls(f"{down}/orders", f"{down}/messages", timeout_s=2)
    process_moveouts(as_role("executor"), settings, now, metrics, outside=outside)
    assert status(admin, rid) == "notice_sent" and notices(admin) == 1
    assert outside_failures(admin) == [f"sms move_out request={rid}: URLError"]
    assert 'executor_outside_calls_total{outcome="error",target="sms"} 1' in metrics.render().splitlines()


def test_successful_outside_calls_are_counted(admin, as_role, settings, now, outside_world):
    from app.common.ops import Metrics

    _, _, outside = outside_world
    metrics = Metrics()
    add_moveout(admin)
    process_moveouts(as_role("executor"), settings, now, metrics, outside=outside)
    assert 'executor_outside_calls_total{outcome="sent",target="sms"} 1' in metrics.render().splitlines()
    assert outside_failures(admin) == []


def test_a_refused_outside_call_counts_as_a_failure(admin, as_role, settings, now):
    # The fake refuses a call without its caller token (Kubernetes mode): logged, not retried.
    from app.executor.outside import OutsideCalls
    from app.fakes import FAKES, start_fake

    dso = start_fake(FAKES["dso"], port=0, mode="k8s", verifier=lambda token, audience: None, host="127.0.0.1")
    try:
        outside = OutsideCalls(f"http://127.0.0.1:{dso.port}/orders", "")
        rid = ready_for_order(admin, as_role("approver"))
        process_moveouts(as_role("executor"), settings, now, outside=outside)
    finally:
        dso.shutdown()
    assert status(admin, rid) == "executed"
    assert outside_failures(admin) == [f"dso move_out request={rid}: HTTPError"]


def test_without_a_url_the_call_is_skipped(admin, as_role, settings, now):
    from app.executor.outside import OutsideCalls

    rid = add_moveout(admin)
    process_moveouts(as_role("executor"), settings, now, outside=OutsideCalls("", ""))
    assert status(admin, rid) == "notice_sent" and outside_failures(admin) == []


def test_outside_calls_from_settings(settings):
    import dataclasses

    from app.executor.outside import outside_calls

    assert outside_calls(dataclasses.replace(settings, dso_url="", sms_url="")) is None
    built = outside_calls(
        dataclasses.replace(settings, dso_url="http://fake-dso:8091/orders", sms_url="http://fake-sms:8092/messages")
    )
    assert built.urls == {"dso": "http://fake-dso:8091/orders", "sms": "http://fake-sms:8092/messages"}
    assert built.audiences == {"dso": "fake-dso", "sms": "fake-sms"}


def test_outside_call_sends_the_caller_token_in_kubernetes_mode(tmp_path):
    from app.executor.outside import OutsideCalls

    sent = []
    (tmp_path / "fake-dso").mkdir()
    (tmp_path / "fake-dso" / "token").write_text("tok", encoding="utf-8")
    outside = OutsideCalls(
        "http://dso/orders", "", caller_auth="k8s", token_dir=tmp_path,
        post=lambda url, payload, headers, timeout_s: sent.append((url, headers)) or 202,
    )
    outside.send("dso", {"request_id": 1})
    assert sent == [("http://dso/orders", {"Authorization": "Bearer tok"})]


def test_a_failed_outside_call_is_attempted_exactly_once(admin, as_role, settings, now):
    # A retry is how one order becomes two at the grid operator: a call that timed out may still
    # have arrived. So one attempt, whatever happens, on this round and every later one.
    from app.executor.outside import OutsideCalls

    attempts = []

    def unreachable(url, payload, headers, timeout_s):
        attempts.append(payload["request_id"])
        raise TimeoutError("no answer")

    outside = OutsideCalls("http://dso/orders", "http://sms/messages", post=unreachable)
    ex = as_role("executor")
    rid = ready_for_order(admin, as_role("approver"))
    for _ in range(3):
        process_moveouts(ex, settings, now, outside=outside)
    assert attempts == [rid] and orders(admin) == 1
    assert outside_failures(admin) == [f"dso move_out request={rid}: TimeoutError"]
