from __future__ import annotations

import psycopg


def read_ticket(conn: psycopg.Connection, ticket_id: int) -> dict:
    row = conn.execute("SELECT id, body FROM tickets WHERE id = %s", (ticket_id,)).fetchone()
    if row is None:
        raise ValueError(f"unknown ticket {ticket_id}")
    return {"ticket_id": row["id"], "body": row["body"]}
