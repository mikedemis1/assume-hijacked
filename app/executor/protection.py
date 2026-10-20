"""Is this home protected? A flag row means YES, no row means NO (decision 3)."""

from __future__ import annotations

import psycopg


def protection_status(conn: psycopg.Connection, supply_point_id: str) -> str:
    if conn.execute("SELECT 1 FROM flags WHERE supply_point_id = %s", (supply_point_id,)).fetchone():
        return "YES"
    return "NO"
