"""Executor process: the only component that turns requests into effects."""

from __future__ import annotations

import time
from datetime import datetime, timezone

from app import config, db
from app.common.ops import Heartbeat, Metrics, start_ops_server
from app.executor.credits import process_credits
from app.executor.moveouts import process_moveouts
from app.executor.outside import OutsideCalls, outside_calls

POLL_SECONDS = 5
OPS_PORT = 9000


def run_once(
    conn, settings, now: datetime, metrics: Metrics | None = None, outside: OutsideCalls | None = None
) -> None:
    process_credits(conn, settings, now, metrics)
    process_moveouts(conn, settings, now, metrics, outside)


def poll(
    conn, settings, now: datetime, metrics: Metrics, heartbeat: Heartbeat, outside: OutsideCalls | None = None
) -> None:
    """One trip round the loop. Both heartbeats are written only after the work finished, so a hung
    database call turns /healthz into 503 and leaves the database heartbeat (heartbeats table,
    db/sql/06-risk.sql) to age, instead of looking healthy."""
    run_once(conn, settings, now, metrics, outside)
    conn.execute("SELECT beat('executor')")
    metrics.set("executor_last_poll_timestamp_seconds", now.timestamp())
    heartbeat.beat()


def main() -> None:
    settings = config.load()
    metrics = Metrics()
    heartbeat = Heartbeat()
    start_ops_server(OPS_PORT, metrics, heartbeat)
    outside = outside_calls(settings)
    with db.connect(settings, "executor") as conn:
        while True:
            poll(conn, settings, datetime.now(timezone.utc), metrics, heartbeat, outside)
            time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
