"""The ticket owner's account. Never returns health data (decision 2)."""

from __future__ import annotations

import psycopg


def lookup_account(
    conn: psycopg.Connection,
    ticket_id: int,
    customer_id: int | None = None,
    *,
    vulnerable: bool = False,
) -> dict:
    owner = conn.execute("SELECT customer_id FROM tickets WHERE id = %s", (ticket_id,)).fetchone()
    if owner is None:
        raise ValueError(f"unknown ticket {ticket_id}")
    target = owner["customer_id"]
    if customer_id is not None and customer_id != target:
        if vulnerable:
            target = customer_id
        else:
            conn.execute(
                "INSERT INTO events (kind, detail) VALUES ('blocked', %s)",
                (f"lookup_account ticket={ticket_id} asked_for={customer_id}",),
            )
    row = conn.execute(
        "SELECT c.name, a.tariff, a.status, s.address "
        "FROM accounts a "
        "JOIN customers c ON c.id = a.customer_id "
        "JOIN supply_points s ON s.id = a.supply_point_id "
        "WHERE a.customer_id = %s",
        (target,),
    ).fetchone()
    if row is None:
        raise ValueError("no account for this customer")
    return dict(row)
