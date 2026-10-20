"""The ticket owner's account. Never returns health data (decision 2)."""

from __future__ import annotations

import psycopg

from app.common.events import security_event
from app.tools.common import call_api


def lookup_account(conn: psycopg.Connection, lease: str, customer_id: int | None = None) -> dict:
    if customer_id is not None:
        # The customer comes from the lease's ticket, never from the caller. Logged by name only:
        # the value is whatever the model wrote.
        security_event("blocked", tool="lookup_account", args=["customer_id"])
    cur = call_api(conn, "SELECT * FROM api_lookup_account(%s)", (lease,))
    row = cur.fetchone()
    if row is None:
        raise ValueError("no account for this customer")
    return dict(row)
