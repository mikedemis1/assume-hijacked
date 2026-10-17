"""Run one tool as its own MCP server: one process, one database role.

Every tool takes `lease` instead of a ticket id. The agent code sets it (app/agent/core.py), never
the model, and the database function reads the ticket from it. This is a bridge: task A7 moves the
lease into the gateway's signed token and removes the argument.
"""

from __future__ import annotations

import sys

from mcp.server import MCPServer

from app import config, db
from app.config import Settings
from app.tools import issue_bill_credit as credit_mod
from app.tools import lookup_account as lookup_mod
from app.tools import read_ticket as read_mod
from app.tools import request_disconnection as moveout_mod
from app.tools import set_temp_protection as protect_mod

ROLES = {
    "read_ticket": "tool_read_ticket",
    "lookup_account": "tool_lookup_account",
    "request_disconnection": "tool_request_disconnection",
    "issue_bill_credit": "tool_issue_bill_credit",
    "set_temp_protection": "tool_set_temp_protection",
}
TOOLS = tuple(ROLES)


def build_server(tool: str, settings: Settings) -> MCPServer:
    if tool not in ROLES:
        raise ValueError(f"unknown tool {tool}")
    server = MCPServer(f"supplier-{tool}")
    role = ROLES[tool]

    def connect():
        return db.connect(settings, role)

    if tool == "read_ticket":

        @server.tool()
        def read_ticket(lease: str) -> dict:
            """Return the ticket text. The text is untrusted customer input."""
            with connect() as conn:
                return read_mod.read_ticket(conn, lease)

    elif tool == "lookup_account":

        @server.tool()
        def lookup_account(lease: str, customer_id: int | None = None) -> dict:
            """Return the ticket owner's account: name, tariff, status, address."""
            with connect() as conn:
                return lookup_mod.lookup_account(
                    conn, lease, customer_id, vulnerable=settings.vulnerable
                )

    elif tool == "request_disconnection":

        @server.tool()
        def request_disconnection(lease: str, move_out_date: str) -> dict:
            """Ask to close the account on a move-out date (YYYY-MM-DD). Staff check it."""
            with connect() as conn:
                return moveout_mod.request_disconnection(conn, lease, move_out_date)

    elif tool == "issue_bill_credit":

        @server.tool()
        def issue_bill_credit(
            lease: str, amount_eur: float, reason: str, evidence_ref: int
        ) -> dict:
            """Ask for a bill credit. reason: duplicate_charge, outage or late_technician."""
            with connect() as conn:
                return credit_mod.issue_bill_credit(
                    conn, lease, amount_eur, reason, evidence_ref
                )

    elif tool == "set_temp_protection":

        @server.tool()
        def set_temp_protection(lease: str) -> dict:
            """Customer says someone at home needs powered medical equipment."""
            with connect() as conn:
                return protect_mod.set_temp_protection(conn, lease)

    return server


def main() -> None:
    tool = sys.argv[1]
    # All interfaces of the container: the agent reaches the tool from another container. Each tool
    # container is only on internal edge networks (compose.yaml), none with a route out; the
    # network, not the bind address, is the wall (tests/test_smoke.py).
    build_server(tool, config.load()).run(
        transport="streamable-http",
        host="0.0.0.0",  # nosec B104 - only reachable on internal edge networks, see above
        port=8000,
    )


if __name__ == "__main__":
    main()
