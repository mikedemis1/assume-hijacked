"""One database connection per component role."""

from __future__ import annotations

import os

import psycopg
from psycopg.rows import dict_row

from app.config import Settings


def connect(settings: Settings, role: str) -> psycopg.Connection:
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
    )
