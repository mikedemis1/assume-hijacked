"""Credit request. Only records it; the executor checks evidence and limits."""

from __future__ import annotations

from decimal import Decimal

import psycopg

from app.tools.common import call_api

# api_request_credit (db/sql/05-lease.sql) holds the same list.
REASONS = ("duplicate_charge", "outage", "late_technician")
SUBMITTED = "Your request has been submitted and is being checked."


def issue_bill_credit(
    conn: psycopg.Connection,
    lease: str,
    amount_eur: float,
    reason: str,
    evidence_ref: int,
) -> dict:
    if reason not in REASONS:
        raise ValueError(f"reason must be one of {REASONS}")
    amount = Decimal(str(amount_eur))
    if amount <= 0:
        raise ValueError("amount must be positive")
    # The account is the lease's ticket owner's, chosen inside the database function.
    call_api(conn, "SELECT api_request_credit(%s, %s, %s, %s)", (lease, amount, reason, evidence_ref))
    return {"status": "submitted", "message": SUBMITTED}
