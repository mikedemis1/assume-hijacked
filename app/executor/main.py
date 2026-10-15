"""Executor process: the only component that turns requests into effects."""

from __future__ import annotations

import time
from datetime import datetime, timezone

from app import config, db
from app.executor.credits import process_credits
from app.executor.moveouts import process_moveouts

POLL_SECONDS = 5


def run_once(conn, settings, now: datetime) -> None:
    process_credits(conn, settings, now)
    process_moveouts(conn, settings, now)


def main() -> None:
    settings = config.load()
    with db.connect(settings, "executor") as conn:
        while True:
            run_once(conn, settings, datetime.now(timezone.utc))
            time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
