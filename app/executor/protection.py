"""Is this home protected? Unknown counts as protected (fail closed, decision 3)."""

from __future__ import annotations

from datetime import datetime, timedelta

import psycopg


def protection_status(
    conn: psycopg.Connection, supply_point_id: str, now: datetime, max_age_hours: int
) -> str:
    if conn.execute("SELECT 1 FROM flags WHERE supply_point_id = %s", (supply_point_id,)).fetchone():
        return "YES"
    sync = conn.execute("SELECT last_success FROM register_sync WHERE id = 1").fetchone()
    if sync is None or now - sync["last_success"] > timedelta(hours=max_age_hours):
        return "UNKNOWN"
    return "NO"
