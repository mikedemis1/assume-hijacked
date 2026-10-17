"""Register sync: reads the state register of homes with life-support equipment and adds their
protection flags. It only ever adds (db/sql/07-register.sql): a home the register stops listing
keeps its flag until two SeniorApprovers remove it. A hijacked or broken register, or this process,
can at worst add flags, which only sends more homes to a person.

Each round (every SYNC_SECONDS):
  1. GET the register's list (REGISTER_URL; the fake in this project, app/fakes).
  2. sync_add_flag for each listed home. A home this supplier does not serve is counted and skipped.
  3. sync_heartbeat: the register is fresh. Only after a complete read. If the register cannot be
     read or its answer is not a clean list, the round stops here: the register age keeps growing,
     and after 24 hours every unflagged home counts as UNKNOWN (fail closed).
  4. beat('register-sync') and the ops heartbeat, whatever the outcome: the process is alive.

Logs and metrics carry counts and error classes only, never a home id from the register.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable
from datetime import datetime, timezone

import psycopg

from app import config, db
from app.agent.events import security_event
from app.common import calls
from app.common.ops import Heartbeat, Metrics, start_ops_server

ROLE = "register_sync"
SOURCE = "state_register"
AUDIENCE = "fake-register"
SYNC_SECONDS = 30
OPS_PORT = 9000
TIMEOUT_S = 10.0
MAX_BODY_BYTES = 1024 * 1024
SUPPLY_POINT = re.compile(r"[A-Za-z0-9-]{1,32}")


class RegisterError(Exception):
    """The register's answer is not a clean list of supply point ids."""


def parse_register(raw: bytes) -> list[str]:
    try:
        answer = json.loads(raw)
    except ValueError as exc:
        raise RegisterError("not JSON") from exc
    listed = answer.get("protected") if isinstance(answer, dict) else None
    if not isinstance(listed, list):
        raise RegisterError("no list of protected homes")
    if not all(isinstance(sp, str) and SUPPLY_POINT.fullmatch(sp) for sp in listed):
        raise RegisterError("a listed home is not a supply point id")
    return listed


def fetch_register(url: str, headers: dict[str, str], timeout_s: float = TIMEOUT_S) -> list[str]:
    raw = calls.get_json(url, headers, timeout_s=timeout_s, max_bytes=MAX_BODY_BYTES)
    if len(raw) > MAX_BODY_BYTES:
        raise RegisterError("answer too big")
    return parse_register(raw)


def sync_once(conn: psycopg.Connection, homes: list[str], metrics: Metrics) -> None:
    """Add every listed home's flag, then mark the register fresh. A database error other than an
    unknown home propagates: no heartbeat for a sync that did not finish."""
    for sp in homes:
        try:
            with conn.transaction():
                conn.execute("SELECT sync_add_flag(%s, %s)", (sp, SOURCE))
        except psycopg.errors.NoDataFound:
            metrics.inc("register_sync_flags_total", {"outcome": "unknown_supply_point"})
            continue
        metrics.inc("register_sync_flags_total", {"outcome": "seen"})
    conn.execute("SELECT sync_heartbeat()")


def poll(
    conn: psycopg.Connection,
    fetch: Callable[[], list[str]],
    metrics: Metrics,
    heartbeat: Heartbeat,
    now: datetime | None = None,
) -> None:
    try:
        homes = fetch()
    except (RegisterError, OSError) as exc:  # OSError covers URLError, HTTPError and timeouts
        metrics.inc("register_sync_errors_total", {"stage": "fetch"})
        security_event("register_sync_failed", stage="fetch", error=type(exc).__name__)
    else:
        sync_once(conn, homes, metrics)
        metrics.set("register_sync_last_success_timestamp_seconds", (now or datetime.now(timezone.utc)).timestamp())
    conn.execute("SELECT beat('register-sync')")
    heartbeat.beat()


def main() -> None:
    settings = config.load()
    if not settings.register_url:
        raise SystemExit("REGISTER_URL is not set: register-sync has no register to read")
    metrics, heartbeat = Metrics(), Heartbeat()
    start_ops_server(OPS_PORT, metrics, heartbeat)

    def fetch() -> list[str]:
        return fetch_register(settings.register_url, calls.auth_headers(AUDIENCE, settings.caller_auth))

    with db.connect(settings, ROLE) as conn:
        while True:
            poll(conn, fetch, metrics, heartbeat)
            time.sleep(SYNC_SECONDS)


if __name__ == "__main__":
    main()
