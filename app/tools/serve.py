"""Run one tool as its own MCP server: one process, one database role.

A tool takes only the arguments the model may set. It never takes a lease or a ticket id: the
tool gateway signs a token for each call, the middleware (app/security/middleware.py) checks it
before anything else runs, and the lease inside it is what the tool hands to its database
function, which reads the ticket from the lease. A tool with no verified token has no lease.
"""

from __future__ import annotations

import os
import sys
import time
from collections.abc import Callable, Mapping

import uvicorn
from mcp.server import MCPServer
from mcp.server.mcpserver import Context

from app import config, db
from app.config import Settings
from app.security.middleware import LEASE_SCOPE_KEY, RequireToolToken
from app.security.tokens import JtiCache, load_public_key
from app.tools import issue_bill_credit as credit_mod
from app.tools import lookup_account as lookup_mod
from app.tools import read_ticket as read_mod
from app.tools import request_disconnection as moveout_mod
from app.tools import set_temp_protection as protect_mod
from app.tools.common import LEASE_INVALID, LeaseError

ROLES = {
    "read_ticket": "tool_read_ticket",
    "lookup_account": "tool_lookup_account",
    "request_disconnection": "tool_request_disconnection",
    "issue_bill_credit": "tool_issue_bill_credit",
    "set_temp_protection": "tool_set_temp_protection",
}
TOOLS = tuple(ROLES)
PORT = 8000


def lease_of(ctx: Context) -> str:
    """The lease from the verified token of this request. Without one (the server was reached
    some other way than through the token check) the call fails like an unknown lease."""
    request = ctx.request_context.request
    lease = request.scope.get(LEASE_SCOPE_KEY) if request is not None else None
    if not isinstance(lease, str) or not lease:
        raise LeaseError(LEASE_INVALID)
    return lease


def build_server(tool: str, settings: Settings, connect: Callable | None = None) -> MCPServer:
    """The MCP server of one tool. `connect` opens its database connection; tests pass a spy."""
    if tool not in ROLES:
        raise ValueError(f"unknown tool {tool}")
    server = MCPServer(f"supplier-{tool}")
    role = ROLES[tool]
    if connect is None:

        def connect():
            return db.connect(settings, role)

    if tool == "read_ticket":

        @server.tool()
        def read_ticket(ctx: Context) -> dict:
            """Return the ticket text. The text is untrusted customer input."""
            lease = lease_of(ctx)
            with connect() as conn:
                return read_mod.read_ticket(conn, lease)

    elif tool == "lookup_account" and settings.vulnerable:

        # The demo hole (docs/attacks.md, VULNERABLE switch): only this variant takes a customer id.
        @server.tool()
        def lookup_account(ctx: Context, customer_id: int | None = None) -> dict:
            """Return the ticket owner's account: name, tariff, status, address."""
            lease = lease_of(ctx)
            with connect() as conn:
                return lookup_mod.lookup_account(conn, lease, customer_id, vulnerable=True)

    elif tool == "lookup_account":

        # No customer argument at all: the account is the lease's ticket owner's.
        @server.tool()
        def lookup_account(ctx: Context) -> dict:  # noqa: F811 (the demo variant is the other branch)
            """Return the ticket owner's account: name, tariff, status, address."""
            lease = lease_of(ctx)
            with connect() as conn:
                return lookup_mod.lookup_account(conn, lease)

    elif tool == "request_disconnection":

        @server.tool()
        def request_disconnection(ctx: Context, move_out_date: str) -> dict:
            """Ask to close the account on a move-out date (YYYY-MM-DD). Staff check it."""
            lease = lease_of(ctx)
            with connect() as conn:
                return moveout_mod.request_disconnection(conn, lease, move_out_date)

    elif tool == "issue_bill_credit":

        @server.tool()
        def issue_bill_credit(ctx: Context, amount_eur: float, reason: str, evidence_ref: int) -> dict:
            """Ask for a bill credit. reason: duplicate_charge, outage or late_technician."""
            lease = lease_of(ctx)
            with connect() as conn:
                return credit_mod.issue_bill_credit(conn, lease, amount_eur, reason, evidence_ref)

    elif tool == "set_temp_protection":

        @server.tool()
        def set_temp_protection(ctx: Context) -> dict:
            """Customer says someone at home needs powered medical equipment."""
            lease = lease_of(ctx)
            with connect() as conn:
                return protect_mod.set_temp_protection(conn, lease)

    return server


def build_app(
    tool: str,
    settings: Settings,
    public_pem: bytes,
    *,
    connect: Callable | None = None,
    seen: JtiCache | None = None,
    clock: Callable[[], float] = time.time,
) -> RequireToolToken:
    """The ASGI app of one tool: the MCP server behind the token check.

    Stateless and plain JSON: every HTTP request stands alone (no session to hijack) and is checked
    on its own. The host is 0.0.0.0, which turns off the MCP library's check of the Host header
    (that check is for servers on localhost); the container network decides who can connect."""
    inner = build_server(tool, settings, connect).streamable_http_app(
        stateless_http=True, json_response=True, host="0.0.0.0"  # nosec B104 - only reachable on the internal edge networks
    )
    return RequireToolToken(inner, tool=tool, public_pem=public_pem, seen=seen, clock=clock)


def tool_name(argv: list[str], env: Mapping[str, str]) -> str:
    """The tool to serve: the argument (`python -m app.tools.serve <tool>`), checked against
    TOOL_NAME when the platform sets that too. The token's audience is this name."""
    named = argv[1] if len(argv) > 1 else ""
    from_env = env.get("TOOL_NAME", "")
    if named and from_env and named != from_env:
        raise SystemExit(f"the argument says {named} but TOOL_NAME says {from_env}")
    tool = named or from_env
    if tool not in ROLES:
        raise SystemExit(f"choose a tool: {', '.join(TOOLS)} (argument or TOOL_NAME)")
    return tool


def main() -> None:
    tool = tool_name(sys.argv, os.environ)
    key_file = os.environ.get("GATEWAY_PUBLIC_KEY_FILE", "")
    if not key_file:
        # No key, no way to tell a gateway call from any other: do not start.
        raise SystemExit("GATEWAY_PUBLIC_KEY_FILE is not set: a tool does not serve without the gateway's key")
    app = build_app(tool, config.load(), load_public_key(key_file))
    # All interfaces of the container: the gateway reaches the tool from another container. Each
    # tool container is only on internal edge networks (compose.yaml), none with a route out; the
    # network and the token, not the bind address, are the wall (tests/test_smoke.py).
    uvicorn.run(app, host="0.0.0.0", port=PORT, log_level="info")  # nosec B104 - only reachable on the internal edge networks


if __name__ == "__main__":
    main()
