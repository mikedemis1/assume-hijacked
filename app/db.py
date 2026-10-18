"""One database connection per component role."""

from __future__ import annotations

import os

import psycopg
from psycopg.rows import dict_row

from app.config import Settings


def connect(
    settings: Settings,
    role: str,
    *,
    connect_timeout_s: int | None = None,
    statement_timeout_ms: int | None = None,
) -> psycopg.Connection:
    """One autocommit connection as `role`. A component on a request path (the tool gateway, the
    risk engine's /decide) passes both timeouts: a database that does not answer fails the request
    in a bounded time (the caller denies) instead of holding it."""
    var = f"DB_PASSWORD_{role.upper()}"
    password = os.environ.get(var, "")
    if not password:
        raise RuntimeError(f"{var} is not set for this component")
    return psycopg.connect(
        host=settings.db_host,
        port=settings.db_port,
        dbname=settings.db_name,
        user=role,
        password=password,
        autocommit=True,
        row_factory=dict_row,
        # Whole seconds (libpq); the statement timeout is a server setting, set for this session.
        **({"connect_timeout": connect_timeout_s} if connect_timeout_s else {}),
        **({"options": f"-c statement_timeout={int(statement_timeout_ms)}"} if statement_timeout_ms else {}),
    )
