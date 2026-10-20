"""The demo's two database roles (db/sql/09-demo.sql), one short connection per call.

demo_portal: list the fictional customers, open a ticket for a customer, read the reply to that
customer's own ticket. demo_ops: read the audit tables for a handful of ticket numbers that the
caller (this service) took from the visitor's own session, never from the request.
"""

from __future__ import annotations

from app import config, db

CONNECT_TIMEOUT_S = 2
STATEMENT_TIMEOUT_MS = 3000


def _connect(role: str):
    return db.connect(config.load(), role, connect_timeout_s=CONNECT_TIMEOUT_S, statement_timeout_ms=STATEMENT_TIMEOUT_MS)


def customers() -> list[dict]:
    with _connect("demo_portal") as conn:
        return conn.execute("SELECT id, name FROM portal_customers()").fetchall()


def open_ticket(customer: int, text: str) -> int:
    with _connect("demo_portal") as conn:
        return conn.execute("SELECT portal_open_ticket(%s, %s) AS id", (customer, text)).fetchone()["id"]


def replies(customer: int, tickets: list[int]) -> dict[int, str]:
    """The stored reply of each of the customer's tickets that has one."""
    found = {}
    with _connect("demo_portal") as conn:
        for ticket in tickets:
            row = conn.execute("SELECT text FROM portal_reply(%s, %s)", (customer, ticket)).fetchone()
            if row is not None:
                found[ticket] = row["text"]
    return found


def kill_switch_on() -> bool:
    """Whether the agents are paused (the one flag of agent_control; demo_ops reads nothing else of it)."""
    with _connect("demo_ops") as conn:
        row = conn.execute("SELECT paused FROM agent_control").fetchone()
    return bool(row and row["paused"])


def audit(tickets: list[int]) -> dict[int, dict]:
    """For each ticket: its run, the gateway's calls, the risk engine's verdicts on them, the effect
    requests with their risk tier, approvals and outcome, the agent's own report of what it dropped
    (agent_events, names only), and when the reply was stored and of which kind."""
    if not tickets:
        return {}
    out = {t: {"run": None, "calls": [], "assessments": [], "requests": [], "events": [],
                     "reply_at": None, "reply_kind": None} for t in tickets}
    with _connect("demo_ops") as conn:
        runs = conn.execute(
            "SELECT ticket_id, lease_hash, status, created_at FROM agent_runs WHERE ticket_id = ANY(%s)", (tickets,)
        ).fetchall()
        ticket_of = {}
        for run in runs:
            out[run["ticket_id"]]["run"] = run
            if run["lease_hash"] is not None:
                ticket_of[bytes(run["lease_hash"])] = run["ticket_id"]
        hashes = list(ticket_of)
        if hashes:
            for call in conn.execute(
                "SELECT lease_hash, tool, arg_names, dropped_args, outcome, reason, created_at "
                "FROM tool_calls WHERE lease_hash = ANY(%s) ORDER BY id", (hashes,)
            ).fetchall():
                out[ticket_of[bytes(call["lease_hash"])]]["calls"].append(call)
            for verdict in conn.execute(
                "SELECT lease_hash, tool, decision, created_at FROM call_assessments "
                "WHERE lease_hash = ANY(%s) ORDER BY id", (hashes,)
            ).fetchall():
                out[ticket_of[bytes(verdict["lease_hash"])]]["assessments"].append(verdict)
        requests = conn.execute(
            "SELECT r.id, r.kind, r.ticket_id, r.amount_eur, r.status, r.decision_reason, r.created_at, "
            "k.tier, k.reasons, k.created_at AS assessed_at "
            "FROM action_requests r LEFT JOIN risk_assessments k ON k.request_id = r.id "
            "WHERE r.ticket_id = ANY(%s) ORDER BY r.id", (tickets,)
        ).fetchall()
        ids = [r["id"] for r in requests]
        paid = {r["request_id"] for r in conn.execute("SELECT request_id FROM credits WHERE request_id = ANY(%s)", (ids,)).fetchall()}
        ordered = {r["request_id"] for r in conn.execute(
            "SELECT request_id FROM disconnection_orders WHERE request_id = ANY(%s)", (ids,)).fetchall()}
        approvals: dict[int, list[str]] = {}
        for row in conn.execute(
            "SELECT request_id, approver_role FROM approvals WHERE request_id = ANY(%s) ORDER BY created_at", (ids,)
        ).fetchall():
            approvals.setdefault(row["request_id"], []).append(row["approver_role"])
        errors: dict[int, list[dict]] = {}
        seen: set[int] = set()
        for row in sorted(conn.execute("SELECT request_id, error, created_at FROM demo_request_errors(%s)", (ids,)).fetchall(),
                          key=lambda e: e["created_at"]):
            # The executor tries again on every round; show the first refusal of a request once.
            if row["request_id"] not in seen:
                seen.add(row["request_id"])
                errors.setdefault(row["request_id"], []).append(row)
        for r in requests:
            out[r["ticket_id"]]["requests"].append({
                "id": r["id"], "kind": r["kind"], "amount_eur": r["amount_eur"], "status": r["status"],
                "decision_reason": r["decision_reason"], "created_at": r["created_at"],
                "risk": None if r["tier"] is None else {"tier": r["tier"], "reasons": list(r["reasons"]),
                                                       "created_at": r["assessed_at"]},
                "approvals": approvals.get(r["id"], []), "credit_paid": r["id"] in paid,
                "order_written": r["id"] in ordered, "errors": errors.get(r["id"], []),
            })
        for row in conn.execute(
            "SELECT ticket_id, kind, tool, arg_names, reported_at FROM agent_events "
            "WHERE ticket_id = ANY(%s) ORDER BY id", (tickets,)
        ).fetchall():
            out[row["ticket_id"]]["events"].append(row)
        for row in conn.execute(
            "SELECT ticket_id, kind, created_at FROM replies WHERE ticket_id = ANY(%s)", (tickets,)
        ).fetchall():
            out[row["ticket_id"]]["reply_at"] = row["created_at"]
            out[row["ticket_id"]]["reply_kind"] = row["kind"]
    return out
