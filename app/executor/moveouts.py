"""Move-outs (decision 6): protected or unknown homes are never disconnected automatically."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import psycopg

from app.config import Settings
from app.executor.alerts import raise_alert_once
from app.executor.approvals import approver_count
from app.executor.protection import protection_status


def _decide(conn, request_id: int, status: str, reason: str, now: datetime) -> None:
    conn.execute(
        "UPDATE action_requests SET status = %s, decision_reason = %s, decided_at = %s WHERE id = %s",
        (status, reason, now, request_id),
    )


def _process_one(conn, settings: Settings, req, now: datetime, hour_ago: datetime) -> None:
    # Held until this request's transaction ends. set_temp_protection takes the same lock,
    # so a flag cannot land between the protection check and the order.
    conn.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (req["supply_point_id"],))
    protection = protection_status(
        conn, req["supply_point_id"], now, settings.register_max_age_hours
    )
    if req["status"] == "pending":
        # Requests decided in the last hour count, whatever their age.
        # held_rate_limit is terminal: a human releases held requests.
        accepted = conn.execute(
            "SELECT count(*) AS n FROM action_requests WHERE kind = 'move_out' "
            "AND decided_at >= %s AND status NOT IN ('pending', 'held_rate_limit')",
            (hour_ago,),
        ).fetchone()["n"]
        if accepted >= settings.moveout_max_per_hour:
            _decide(conn, req["id"], "held_rate_limit", "too many move-outs in one hour", now)
            raise_alert_once(conn, "move-out rate limit reached", hour_ago)
            return
        if protection != "NO":
            _decide(conn, req["id"], "manual_only", f"protection {protection}: human occupant check only", now)
            return
        # sent_at is the database's clock (column default); the executor cannot set it.
        conn.execute(
            "INSERT INTO occupier_notices (request_id, supply_point_id) VALUES (%s, %s)",
            (req["id"], req["supply_point_id"]),
        )
        _decide(conn, req["id"], "notice_sent", "notice sent to the occupier", now)
        return

    # notice_sent: check again, the home may have become protected meanwhile.
    if protection != "NO":
        _decide(conn, req["id"], "manual_only", f"protection {protection}: human occupant check only", now)
        return
    # The same conditions check_disconnection_order applies, so a normal run never hits the trigger.
    # Anything not met yet leaves the request at notice_sent for a later run.
    sent = conn.execute(
        "SELECT sent_at FROM occupier_notices WHERE request_id = %s", (req["id"],)
    ).fetchone()["sent_at"]
    waited = now - sent >= timedelta(hours=settings.occupier_wait_hours)
    day = req["move_out_date"]
    date_reached = day is not None and day <= now.astimezone(timezone.utc).date()
    if waited and date_reached and approver_count(conn, req["id"], after=sent) >= 1:
        # check_disconnection_order checks the whole story again, with the database clock.
        conn.execute(
            "INSERT INTO disconnection_orders (request_id, supply_point_id) VALUES (%s, %s)",
            (req["id"], req["supply_point_id"]),
        )
        _decide(conn, req["id"], "executed", "order sent to the grid operator", now)


def process_moveouts(conn: psycopg.Connection, settings: Settings, now: datetime) -> None:
    rows = conn.execute(
        "SELECT r.id, r.status, r.move_out_date, a.supply_point_id FROM action_requests r "
        "JOIN accounts a ON a.id = r.account_id "
        "WHERE r.kind = 'move_out' AND r.status IN ('pending', 'notice_sent') ORDER BY r.id"
    ).fetchall()
    hour_ago = now - timedelta(hours=1)
    for req in rows:
        try:
            # One transaction per request: the row written and the status change land together or not at all.
            with conn.transaction():
                _process_one(conn, settings, req, now, hour_ago)
        except Exception as exc:
            # One bad request must not stop the batch. Logged outside the failed transaction.
            conn.execute(
                "INSERT INTO events (kind, detail) VALUES ('executor_error', %s)",
                (f"move_out request={req['id']}: {type(exc).__name__}",),
            )
