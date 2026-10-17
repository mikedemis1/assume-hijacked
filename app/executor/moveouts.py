"""Move-outs (decision 6): protected or unknown homes are never disconnected automatically.

Only requests the risk engine assessed are taken (task A5). HUMAN_ONLY ends at manual_only and
REJECT at rejected, before any notice. T1, T2 and HOLD take the path below and wait, at the order
step, for the approvals their tier needs (T1 one, T2 two people, HOLD two SeniorApprovers). The
approvals count only once given after the occupier notice (the order rule) and after the
assessment, so that is where the executor waits: an approval before the notice would not count
for the order, and the same person cannot approve twice.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import psycopg

from app.common.ops import Metrics
from app.config import Settings
from app.executor.alerts import raise_alert_once
from app.executor.approvals import approvals_met
from app.executor.credits import risk_reason
from app.executor.metrics import count_request
from app.executor.protection import protection_status


def _decide(conn, request_id: int, status: str, reason: str, now: datetime) -> str:
    conn.execute(
        "UPDATE action_requests SET status = %s, decision_reason = %s, decided_at = %s WHERE id = %s",
        (status, reason, now, request_id),
    )
    return status


def _process_one(conn, settings: Settings, req, now: datetime, hour_ago: datetime) -> str | None:
    """The status the request moved to, or None when it stays where it is."""
    # Held until this request's transaction ends. set_temp_protection takes the same lock,
    # so a flag cannot land between the protection check and the order.
    conn.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (req["supply_point_id"],))
    protection = protection_status(
        conn, req["supply_point_id"], now, settings.register_max_age_hours
    )
    if req["status"] == "pending":
        if req["tier"] == "HUMAN_ONLY":
            return _decide(conn, req["id"], "manual_only", risk_reason(req), now)
        if req["tier"] == "REJECT":
            return _decide(conn, req["id"], "rejected", risk_reason(req), now)
        # Requests decided in the last hour count, whatever their age.
        # held_rate_limit is terminal: a human releases held requests.
        accepted = conn.execute(
            "SELECT count(*) AS n FROM action_requests WHERE kind = 'move_out' "
            "AND decided_at >= %s AND status NOT IN ('pending', 'held_rate_limit')",
            (hour_ago,),
        ).fetchone()["n"]
        if accepted >= settings.moveout_max_per_hour:
            decided = _decide(conn, req["id"], "held_rate_limit", "too many move-outs in one hour", now)
            raise_alert_once(conn, "move-out rate limit reached", hour_ago)
            return decided
        if protection != "NO":
            return _decide(conn, req["id"], "manual_only", f"protection {protection}: human occupant check only", now)
        # sent_at is the database's clock (column default); the executor cannot set it.
        conn.execute(
            "INSERT INTO occupier_notices (request_id, supply_point_id) VALUES (%s, %s)",
            (req["id"], req["supply_point_id"]),
        )
        return _decide(conn, req["id"], "notice_sent", "notice sent to the occupier", now)

    # notice_sent: check again, the home may have become protected meanwhile.
    if protection != "NO":
        return _decide(conn, req["id"], "manual_only", f"protection {protection}: human occupant check only", now)
    # The same conditions check_disconnection_order applies, so a normal run never hits the trigger.
    # Anything not met yet leaves the request at notice_sent for a later run.
    sent = conn.execute(
        "SELECT sent_at FROM occupier_notices WHERE request_id = %s", (req["id"],)
    ).fetchone()["sent_at"]
    waited = now - sent >= timedelta(hours=settings.occupier_wait_hours)
    day = req["move_out_date"]
    date_reached = day is not None and day <= now.astimezone(timezone.utc).date()
    # An order always needs at least one person (check_disconnection_order), whatever the tier.
    after = max(sent, req["assessed_at"])
    if waited and date_reached and approvals_met(conn, req["id"], req["tier"], after, minimum=1):
        # check_disconnection_order checks the whole story again, with the database clock.
        conn.execute(
            "INSERT INTO disconnection_orders (request_id, supply_point_id) VALUES (%s, %s)",
            (req["id"], req["supply_point_id"]),
        )
        return _decide(conn, req["id"], "executed", "order sent to the grid operator", now)
    return None


def process_moveouts(
    conn: psycopg.Connection, settings: Settings, now: datetime, metrics: Metrics | None = None
) -> None:
    # The join on risk_assessments is the rule: a request without an assessment is not looked at.
    rows = conn.execute(
        "SELECT r.id, r.status, r.move_out_date, a.supply_point_id, "
        "       k.tier, k.reasons AS risk_reasons, k.created_at AS assessed_at "
        "FROM action_requests r JOIN accounts a ON a.id = r.account_id "
        "JOIN risk_assessments k ON k.request_id = r.id "
        "WHERE r.kind = 'move_out' AND r.status IN ('pending', 'notice_sent') ORDER BY r.id"
    ).fetchall()
    hour_ago = now - timedelta(hours=1)
    for req in rows:
        try:
            # One transaction per request: the row written and the status change land together or not at all.
            with conn.transaction():
                status = _process_one(conn, settings, req, now, hour_ago)
            if status is not None:
                count_request(metrics, "move_out", status)
        except Exception as exc:
            count_request(metrics, "move_out", "error")
            # One bad request must not stop the batch. Logged outside the failed transaction.
            conn.execute(
                "INSERT INTO events (kind, detail) VALUES ('executor_error', %s)",
                (f"move_out request={req['id']}: {type(exc).__name__}",),
            )
