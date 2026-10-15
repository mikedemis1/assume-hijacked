from __future__ import annotations

import psycopg


def account_for_ticket(conn: psycopg.Connection, ticket_id: int) -> int:
    """The account of the customer who opened the ticket. The ticket decides, not the LLM."""
    row = conn.execute(
        "SELECT a.id AS account_id FROM tickets t "
        "JOIN accounts a ON a.customer_id = t.customer_id WHERE t.id = %s",
        (ticket_id,),
    ).fetchone()
    if row is None:
        raise ValueError(f"unknown ticket {ticket_id}")
    return row["account_id"]
