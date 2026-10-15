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

    On a PC that is the local Compose database (localhost). In GitLab CI it is the job's own
    PostgreSQL service container, reached by its alias (.gitlab-ci.yml sets TEST_DB_SERVICE_HOST
    to it). The CI case needs all three: GITLAB_CI=true (set by the runner), DB_HOST equal to the
    TEST_DB_SERVICE_HOST named in the pipeline, and a bare alias. An IP address or a dotted name,
    which could point at a shared or production server, is refused even in CI. This stops
    accidents, not a determined admin (README, "CI pipeline").
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
            "TEST_DB_SERVICE_HOST). Point DB_HOST at the local Compose database.",
            returncode=2,
        )

from app import config  # noqa: E402  (after .env is loaded)

SEED_SQL = (ROOT / "db" / "sql" / "04-seed.sql").read_text(encoding="utf-8")
ALL_TABLES = (
    "events, disconnection_orders, occupier_notices, credits, approvals, action_requests, "
    "register_sync, flags, charges, tickets, accounts, supply_points, customers"
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


@pytest.fixture
def admin(settings):
    """Superuser connection. Test setup only; no component uses it."""
    conn = psycopg.connect(
        host=settings.db_host,
        port=settings.db_port,
        dbname=settings.db_name,
        user="postgres",
        password=os.environ["POSTGRES_PASSWORD"],
        autocommit=True,
        row_factory=dict_row,
    )
    yield conn
    conn.close()


def reset_db(conn) -> None:
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
