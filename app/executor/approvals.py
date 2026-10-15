from __future__ import annotations

from datetime import datetime

import psycopg


def approve(conn: psycopg.Connection, request_id: int, approver: str) -> bool:
    """Staff approval. The same person cannot approve the same request twice (decision 5)."""
    try:
        conn.execute(
            "INSERT INTO approvals (request_id, approver) VALUES (%s, %s)",
            (request_id, approver),
        )
    except psycopg.errors.UniqueViolation:
        return False
    return True


def approver_count(conn: psycopg.Connection, request_id: int, after: datetime | None = None) -> int:
    """Distinct approvers. With `after`, only approvals given after that time count: staff must
    approve once the occupier has been told, not before. created_at is set by the database."""
    row = conn.execute(
        "SELECT count(DISTINCT approver) AS n FROM approvals "
        "WHERE request_id = %s AND (%s::timestamptz IS NULL OR created_at > %s)",
        (request_id, after, after),
    ).fetchone()
    return row["n"]
