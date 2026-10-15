"""Credit request. Only records it; the executor checks evidence and limits (decision 4)."""

from __future__ import annotations

from decimal import Decimal

import psycopg

from app.tools.common import account_for_ticket

REASONS = ("duplicate_charge", "outage", "late_technician")
SUBMITTED = "Your request has been submitted and is being checked."


def issue_bill_credit(
    conn: psycopg.Connection,
    ticket_id: int,
    amount_eur: float,
    reason: str,
    evidence_ref: int,
) -> dict:
    if reason not in REASONS:
        raise ValueError(f"reason must be one of {REASONS}")
    amount = Decimal(str(amount_eur))
    if amount <= 0:
        raise ValueError("amount must be positive")
    account_id = account_for_ticket(conn, ticket_id)
    conn.execute(
        "INSERT INTO action_requests (kind, ticket_id, account_id, amount_eur, reason, evidence_ref) "
        "VALUES ('credit', %s, %s, %s, %s, %s)",
        (ticket_id, account_id, amount, reason, evidence_ref),
    )
    return {"status": "submitted", "message": SUBMITTED}
