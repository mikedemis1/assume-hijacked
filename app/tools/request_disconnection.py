"""Move-out request. Only records it; the executor decides (decision 6)."""

from __future__ import annotations

from datetime import date, datetime, timezone

import psycopg

from app.tools.common import account_for_ticket

SUBMITTED = (
    "Your request has been submitted and is being checked. "
    "Does anyone at the property use medical equipment that needs electricity? "
    "If so, please tell us and we will protect the supply."
)


def request_disconnection(conn: psycopg.Connection, ticket_id: int, move_out_date: str) -> dict:
    day = date.fromisoformat(move_out_date)
    # UTC, like the order trigger. Greece is ahead of UTC, so a customer's "today" always passes.
    if day < datetime.now(timezone.utc).date():
        raise ValueError("move-out date is in the past")
    account_id = account_for_ticket(conn, ticket_id)
    conn.execute(
        "INSERT INTO action_requests (kind, ticket_id, account_id, move_out_date) "
        "VALUES ('move_out', %s, %s, %s)",
        (ticket_id, account_id, day),
    )
    return {"status": "submitted", "message": SUBMITTED}
