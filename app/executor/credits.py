"""Bill credits (decision 4): evidence from the data, then three limits. The LLM never judges."""

from __future__ import annotations

from datetime import datetime, timedelta
from decimal import Decimal

import psycopg

from app.common.ops import Metrics
from app.config import Settings
from app.executor.alerts import raise_alert_once
from app.executor.metrics import count_request

AUTO_CHECKED_REASONS = {"duplicate_charge"}
REJECTED_ALERT_COUNT = 5  # refused credit requests for one account in one hour


def _sum_since(conn, since: datetime, account_id: int | None = None) -> Decimal:
    if account_id is None:
        row = conn.execute(
            "SELECT coalesce(sum(amount_eur), 0) AS s FROM credits WHERE created_at >= %s", (since,)
        ).fetchone()
    else:
        row = conn.execute(
            "SELECT coalesce(sum(amount_eur), 0) AS s FROM credits "
            "WHERE created_at >= %s AND account_id = %s",
            (since, account_id),
        ).fetchone()
    return Decimal(row["s"])


def decide_credit(conn: psycopg.Connection, req: dict, settings: Settings, now: datetime) -> tuple[str, str]:
    if req["amount_eur"] is None:
        return "rejected", "amount missing"
    if Decimal(req["amount_eur"]) <= 0:
        return "rejected", "amount must be positive"
    if req["reason"] not in AUTO_CHECKED_REASONS:
        return "needs_staff", "no automatic evidence check for this reason"
    evidence = conn.execute(
        "SELECT id, account_id, period, amount_eur FROM charges WHERE id = %s", (req["evidence_ref"],)
    ).fetchone()
    if evidence is None or evidence["account_id"] != req["account_id"]:
        return "needs_staff", "evidence not found for this account"
    earlier_twin = conn.execute(
        "SELECT 1 FROM charges WHERE account_id = %s AND period = %s AND amount_eur = %s AND id < %s",
        (evidence["account_id"], evidence["period"], evidence["amount_eur"], evidence["id"]),
    ).fetchone()
    if earlier_twin is None:
        return "needs_staff", "the charge is not a duplicate"
    amount = Decimal(req["amount_eur"])
    if amount > evidence["amount_eur"]:
        return "rejected", "amount is above the duplicate charge"
    if conn.execute("SELECT 1 FROM credits WHERE evidence_ref = %s", (evidence["id"],)).fetchone():
        return "rejected", "already credited"

    start_of_day = now.replace(hour=0, minute=0, second=0, microsecond=0)
    if _sum_since(conn, start_of_day) + amount > Decimal(str(settings.credit_day_global_max_eur)):
        raise_alert_once(conn, "daily global credit cap reached", start_of_day)
        return "held_global", "daily global cap"
    if amount > Decimal(str(settings.credit_auto_max_eur)):
        return "needs_staff", "above the automatic limit"
    start_of_month = start_of_day.replace(day=1)
    month_total = _sum_since(conn, start_of_month, req["account_id"])
    if month_total + amount > Decimal(str(settings.credit_month_max_eur)):
        return "needs_staff", "monthly limit for this account"
    return "approved", "duplicate charge confirmed"


def _process_one(conn: psycopg.Connection, settings: Settings, req: dict, now: datetime) -> str:
    status, why = decide_credit(conn, req, settings, now)
    if status == "approved":
        # created_at is the database clock; check_credit ties the row to this request.
        conn.execute(
            "INSERT INTO credits (request_id, account_id, amount_eur, evidence_ref) VALUES (%s, %s, %s, %s)",
            (req["id"], req["account_id"], req["amount_eur"], req["evidence_ref"]),
        )
        status = "executed"
    conn.execute(
        "UPDATE action_requests SET status = %s, decision_reason = %s, decided_at = %s WHERE id = %s",
        (status, why, now, req["id"]),
    )
    if status in ("rejected", "held_global"):
        _alert_on_repeated_refusals(conn, req["account_id"], now)
    return status


def _alert_on_repeated_refusals(conn: psycopg.Connection, account_id: int, now: datetime) -> None:
    """Each refusal is harmless; many for one account in an hour is a pattern someone should see."""
    hour_ago = now - timedelta(hours=1)
    refused = conn.execute(
        "SELECT count(*) AS n FROM action_requests WHERE kind = 'credit' AND account_id = %s "
        "AND status IN ('rejected', 'held_global') AND decided_at >= %s",
        (account_id, hour_ago),
    ).fetchone()["n"]
    if refused >= REJECTED_ALERT_COUNT:
        raise_alert_once(conn, f"repeated rejected credits account={account_id}", hour_ago)


def process_credits(
    conn: psycopg.Connection, settings: Settings, now: datetime, metrics: Metrics | None = None
) -> None:
    pending = conn.execute(
        "SELECT id, account_id, amount_eur, reason, evidence_ref FROM action_requests "
        "WHERE kind = 'credit' AND status = 'pending' ORDER BY id"
    ).fetchall()
    for req in pending:
        try:
            # One transaction per request: the credit and the status change land together or not at all.
            with conn.transaction():
                status = _process_one(conn, settings, req, now)
            count_request(metrics, "credit", status)
        except Exception as exc:
            count_request(metrics, "credit", "error")
            # One bad request must not stop the batch. Logged outside the failed transaction.
            conn.execute(
                "INSERT INTO events (kind, detail) VALUES ('executor_error', %s)",
                (f"credit request={req['id']}: {type(exc).__name__}",),
            )
