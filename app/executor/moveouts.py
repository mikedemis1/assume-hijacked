"""Move-outs (decision 6): a protected home is never disconnected automatically.

Only requests the risk engine assessed are taken. HUMAN_ONLY ends at manual_only and REJECT at
rejected. A home with a flag ends at manual_only too. T1 and T2 requests for an unprotected home
stay pending until the move-out date has come and the approvals their tier needs are in (T1 one,
T2 two people), at least one approval whatever the tier. Approvals count only once given after
the assessment, and the same person cannot approve twice. Then the order is written and the
request is executed: pending -> manual_only | rejected | executed.

The executor writes the order row and sends nothing outside.
"""

from __future__ import annotations

from datetime import datetime, timezone

import psycopg

from app.common.ops import Metrics
from app.config import Settings
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


def _decide_one(conn, req, now: datetime) -> str | None:
    """The status the request moved to, or None when it stays where it is."""
    # Held until this request's transaction ends. api_set_temp_protection takes the same lock,
    # so a flag cannot land between the protection check and the order.
    conn.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (req["supply_point_id"],))
    if req["tier"] == "HUMAN_ONLY":
        return _decide(conn, req["id"], "manual_only", risk_reason(req), now)
    if req["tier"] == "REJECT":
        return _decide(conn, req["id"], "rejected", risk_reason(req), now)
    if protection_status(conn, req["supply_point_id"]) != "NO":
        return _decide(conn, req["id"], "manual_only", "protected home: human occupant check only", now)
    # The same conditions check_disconnection_order applies, so a normal run never hits the trigger.
    # Anything not met yet leaves the request pending for a later run.
    day = req["move_out_date"]
    date_reached = day is not None and day <= now.astimezone(timezone.utc).date()
    # An order always needs at least one person (check_disconnection_order), whatever the tier.
    if date_reached and approvals_met(conn, req["id"], req["tier"], req["assessed_at"], minimum=1):
        # check_disconnection_order checks the whole story again, with the database clock.
        conn.execute(
            "INSERT INTO disconnection_orders (request_id, supply_point_id) VALUES (%s, %s)",
            (req["id"], req["supply_point_id"]),
        )
        return _decide(conn, req["id"], "executed", "order written", now)
    return None


def process_moveouts(
    conn: psycopg.Connection,
    settings: Settings,
    now: datetime,
    metrics: Metrics | None = None,
) -> None:
    # The join on risk_assessments is the rule: a request without an assessment is not looked at.
    rows = conn.execute(
        "SELECT r.id, r.status, r.move_out_date, a.supply_point_id, "
        "       k.tier, k.reasons AS risk_reasons, k.created_at AS assessed_at "
        "FROM action_requests r JOIN accounts a ON a.id = r.account_id "
        "JOIN risk_assessments k ON k.request_id = r.id "
        "WHERE r.kind = 'move_out' AND r.status = 'pending' ORDER BY r.id"
    ).fetchall()
    for req in rows:
        try:
            # One transaction per request: the row written and the status change land together or not at all.
            with conn.transaction():
                status = _decide_one(conn, req, now)
            if status is not None:
                count_request(metrics, "move_out", status)
        except Exception as exc:
            count_request(metrics, "move_out", "error")
            # One bad request must not stop the batch. Logged outside the failed transaction.
            conn.execute(
                "INSERT INTO events (kind, detail) VALUES ('executor_error', %s)",
                (f"move_out request={req['id']}: {type(exc).__name__}",),
            )
            continue
