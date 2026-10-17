"""Move-out request. Only records it; the executor decides (decision 6)."""

from __future__ import annotations

from datetime import date, datetime, timezone

import psycopg

from app.tools.common import call_api

SUBMITTED = (
    "Your request has been submitted and is being checked. "
    "Does anyone at the property use medical equipment that needs electricity? "
    "If so, please tell us and we will protect the supply."
)


def request_disconnection(conn: psycopg.Connection, lease: str, move_out_date: str) -> dict:
    day = date.fromisoformat(move_out_date)
    # UTC, like the order trigger. Greece is ahead of UTC, so a customer's "today" always passes.
    if day < datetime.now(timezone.utc).date():
        raise ValueError("move-out date is in the past")
    # The account is the lease's ticket owner's, chosen inside the database function.
    call_api(conn, "SELECT api_request_moveout(%s, %s)", (lease, day))
    return {"status": "submitted", "message": SUBMITTED}
