from __future__ import annotations

from datetime import datetime

import psycopg

# Tiers that wait for staff (required_approvals, db/sql/06-risk.sql): T1 one person, T2 two,
# HOLD two SeniorApprovers.
APPROVAL_TIERS = frozenset({"T1", "T2", "HOLD"})


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


def approvals_met(
    conn: psycopg.Connection, request_id: int, tier: str, after: datetime, minimum: int = 0
) -> bool:
    """Has the request the approvals its tier needs, given after `after` (the assessment, or the
    occupier notice if later)? The same count check_approval_floor makes in the database: one
    person counts once however they spell their id, and SeniorApprovers where the tier asks. The
    executor checks first so that a request still waiting stays quietly pending instead of being
    refused by the trigger on every poll. A tier no approval allows (HUMAN_ONLY, REJECT) is never
    met. `minimum` raises the number for effects that always need a person (an order)."""
    row = conn.execute(
        "SELECT q.n, (SELECT count(DISTINCT a.approver) FROM approvals a "
        "  WHERE a.request_id = %s AND a.created_at > %s "
        "    AND (NOT q.senior OR a.approver_role = 'SeniorApprover')) AS have "
        "FROM required_approvals(%s) q",
        (request_id, after, tier),
    ).fetchone()
    return row is not None and row["have"] >= max(row["n"], minimum)
