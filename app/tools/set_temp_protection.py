"""Customer says someone at home needs powered medical equipment: protect at once (decision 3)."""

from __future__ import annotations

import psycopg


def set_temp_protection(conn: psycopg.Connection, ticket_id: int) -> dict:
    conn.execute("SELECT set_temp_protection(%s)", (ticket_id,))
    return {
        "status": "recorded",
        "message": "Thank you. We have noted this and a colleague will contact you.",
    }
