from __future__ import annotations

from datetime import datetime

import psycopg


def raise_alert_once(conn: psycopg.Connection, key: str, since: datetime) -> None:
    """One ALERT event per key per window, so a flood gives one alert, not fifty.

    Only the executor's own alerts count: a tool that inserts a fake ALERT cannot silence a real one.
    """
    seen = conn.execute(
        "SELECT 1 FROM events WHERE kind = 'ALERT' AND actor = 'executor' "
        "AND detail = %s AND created_at >= %s",
        (key, since),
    ).fetchone()
    if seen is None:
        conn.execute("INSERT INTO events (kind, detail) VALUES ('ALERT', %s)", (key,))
