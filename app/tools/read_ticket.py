from __future__ import annotations

import psycopg

from app.tools.common import call_api


def read_ticket(conn: psycopg.Connection, lease: str) -> dict:
    row = call_api(conn, "SELECT id, body FROM api_read_ticket(%s)", (lease,)).fetchone()
    if row is None:
        raise ValueError("the lease's ticket was not found")
    return {"ticket_id": row["id"], "body": row["body"]}
