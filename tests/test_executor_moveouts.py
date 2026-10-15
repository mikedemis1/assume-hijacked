import time
from datetime import datetime, timedelta, timezone

import psycopg
import pytest

from app.executor.approvals import approve, approver_count
from app.executor.moveouts import process_moveouts
from app.tools.set_temp_protection import set_temp_protection

# The order trigger uses the database clock, so the tests never jump time with the executor's
# `now`. They back-date rows as admin instead: notices, approvals, the register sync.


def utc_today():
    return datetime.now(timezone.utc).date()


def add_moveout(admin, account_id=1, ticket_id=1, move_out_date=None) -> int:
    """A pending move-out. The date defaults to today (UTC), so an order is allowed once the rest holds."""
    admin.execute(
        "INSERT INTO action_requests (kind, ticket_id, account_id, move_out_date) "
        "VALUES ('move_out', %s, %s, %s)",
        (ticket_id, account_id, move_out_date or utc_today()),
    )
    return admin.execute("SELECT max(id) AS id FROM action_requests").fetchone()["id"]


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
    """A move-out where every condition for an order holds: notice sent 73 hours ago,
    a staff approval after it, move-out date today. Tests break one condition at a time."""
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
    set_temp_protection(as_role("tool_set_temp_protection"), 1)
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
    as_role("tool_lookup_account").execute(
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


def test_flag_waits_while_the_executor_holds_the_home(as_role):
    ex, tool = as_role("executor"), as_role("tool_set_temp_protection")
    tool.execute("SET lock_timeout = '200ms'")
    with ex.transaction():
        ex.execute("SELECT pg_advisory_xact_lock(hashtext('SP-1001'))")
        with pytest.raises(psycopg.errors.LockNotAvailable):
            set_temp_protection(tool, 1)
    set_temp_protection(tool, 1)  # lock released at commit


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
