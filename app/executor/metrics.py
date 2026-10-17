"""What the executor counts. Names and categories only: kind and status, never ids or amounts."""

from __future__ import annotations

from app.common.ops import Metrics


def count_request(metrics: Metrics | None, kind: str, status: str) -> None:
    """One request decided (or failed: status "error"). metrics is None in the unit tests that
    do not look at it."""
    if metrics is not None:
        metrics.inc("executor_requests_total", {"kind": kind, "status": status})
