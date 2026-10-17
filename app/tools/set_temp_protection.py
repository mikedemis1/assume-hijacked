"""Customer says someone at home needs powered medical equipment: protect at once (decision 3)."""

from __future__ import annotations

import psycopg

from app.tools.common import call_api


def set_temp_protection(conn: psycopg.Connection, lease: str) -> dict:
    call_api(conn, "SELECT api_set_temp_protection(%s)", (lease,))
    return {
        "status": "recorded",
        "message": "Thank you. We have noted this and a colleague will contact you.",
    }
