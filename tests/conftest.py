from __future__ import annotations

import dataclasses
import os
import re
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path

import psycopg
import pytest
from psycopg.rows import dict_row

ROOT = Path(__file__).resolve().parent.parent


def _load_dotenv() -> None:
    env_file = ROOT / ".env"
    if not env_file.exists():
        return
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip())


_load_dotenv()

LOCAL_HOSTS = ("localhost", "127.0.0.1")
STACK_DB_NAME = "supplier"
# The suite truncates every table, so it gets its own database next to the stack's.
TEST_DB_NAME = os.environ.get("TEST_DB_NAME", "supplier_test")
# A container alias: one DNS label, no dots, not an IP address.
_SERVICE_ALIAS = re.compile(r"[a-z][a-z0-9-]{0,62}")


def db_host_allowed(host: str, env: Mapping[str, str]) -> bool:
    """Every test truncates all tables, so the suite only runs against a throwaway database.

    On a PC that is the local test database (localhost), started by `sh scripts/test-db.sh start`.
    In GitLab CI it is the job's own PostgreSQL service container, reached by its alias
    (.gitlab-ci.yml sets TEST_DB_SERVICE_HOST to it). The CI case needs all three: GITLAB_CI=true (set by the runner), DB_HOST equal to the
    TEST_DB_SERVICE_HOST named in the pipeline, and a bare alias. An IP address or a dotted name,
    which could point at a shared or production server, is refused even in CI. This stops
    accidents, not a determined admin (docs/pipeline.md).
    """
    if host in LOCAL_HOSTS:
        return True
    return (
        env.get("GITLAB_CI") == "true"
        and host == env.get("TEST_DB_SERVICE_HOST")
        and _SERVICE_ALIAS.fullmatch(host) is not None
    )


def pytest_configure():
    if TEST_DB_NAME == STACK_DB_NAME:
        pytest.exit(
            f"Refusing to run: TEST_DB_NAME={TEST_DB_NAME!r} is the stack database and the "
            "tests TRUNCATE every table. Use supplier_test (created by db/init/init.sh).",
            returncode=2,
        )
    # Every test truncates all tables: never let that reach a database that is not throwaway.
    host = os.environ.get("DB_HOST", "localhost")
    if not db_host_allowed(host, os.environ):
        pytest.exit(
            f"Refusing to run: the tests TRUNCATE every table and DB_HOST={host!r} is not "
            f"one of {LOCAL_HOSTS} (or, in GitLab CI only, the job's service alias in "
            "TEST_DB_SERVICE_HOST). Point DB_HOST at the local test database (sh scripts/test-db.sh start).",
            returncode=2,
        )

from app import config  # noqa: E402  (after .env is loaded)

SEED_SQL = (ROOT / "db" / "sql" / "04-seed.sql").read_text(encoding="utf-8")
ALL_TABLES = (
    "events, disconnection_orders, credits, approvals, risk_assessments, "
    "call_assessments, tool_calls, replies, agent_runs, agent_control, heartbeats, action_requests, "
    "leases, flags, charges, tickets, "
    "accounts, supply_points, customers"
)
# The tool names a lease can list (the leases.allowed_tools check in db/sql/05-lease.sql).
TOOLS = (
    "read_ticket",
    "lookup_account",
    "request_disconnection",
    "issue_bill_credit",
    "set_temp_protection",
)


@pytest.fixture
def settings() -> config.Settings:
    # DB_NAME may point at the stack database in .env; the tests never use it.
    return dataclasses.replace(config.load(), db_name=TEST_DB_NAME)


@pytest.fixture
def now() -> datetime:
    """The executor's `now`, taken when the test starts. Not at import time: a run that crosses
    midnight UTC would otherwise mix yesterday's `now` with today's dates."""
    return datetime.now(timezone.utc)


def admin_connect(settings) -> psycopg.Connection:
    """Superuser connection. Test setup only; no component uses it."""
    return psycopg.connect(
        host=settings.db_host,
        port=settings.db_port,
        dbname=settings.db_name,
        user="postgres",
        password=os.environ["POSTGRES_PASSWORD"],
        autocommit=True,
        row_factory=dict_row,
    )


@pytest.fixture
def admin(settings):
    conn = admin_connect(settings)
    yield conn
    conn.close()


def open_lease(admin, ticket: int, tools=TOOLS, bound_pod: str | None = None) -> str:
    """Open a lease as the dispatcher will. The superuser may call open_lease."""
    return admin.execute(
        "SELECT open_lease(%s, %s, %s) AS lease", (ticket, list(tools), bound_pod)
    ).fetchone()["lease"]


def assess(admin, request_id: int, tier: str, score: int = 0, reasons: tuple[str, ...] = ()) -> None:
    """The risk engine's verdict on one request (db/sql/06-risk.sql), written as the superuser.
    The risk service writes these in the stack; tests that need an effect to go through
    write one themselves, because the credit and order triggers refuse a request without one."""
    admin.execute(
        "INSERT INTO risk_assessments (request_id, tier, score, reasons, engine_version) "
        "VALUES (%s, %s, %s, %s, 'test')",
        (request_id, tier, score, list(reasons)),
    )


def approve_as(conn, request_id: int, approver: str, role: str = "Approver") -> None:
    """A staff approval with its role, as the console will write it."""
    conn.execute(
        "INSERT INTO approvals (request_id, approver, approver_role) VALUES (%s, %s, %s)",
        (request_id, approver, role),
    )


def reset_db(conn) -> None:
    # The flags table refuses TRUNCATE, even from the superuser (db/sql/07-flags.sql). The
    # reset turns triggers off for its own transaction only, which only a superuser can do.
    with conn.transaction():
        conn.execute("SET LOCAL session_replication_role = replica")
        conn.execute(f"TRUNCATE {ALL_TABLES} RESTART IDENTITY CASCADE")
    conn.execute(SEED_SQL)


@pytest.fixture(autouse=True)
def fresh_db(admin):
    reset_db(admin)


@pytest.fixture
def as_role(settings):
    from app import db

    opened = []

    def _connect(role: str):
        conn = db.connect(settings, role)
        opened.append(conn)
        return conn

    yield _connect
    for conn in opened:
        conn.close()
