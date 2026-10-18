"""What every tool shares: it reaches the database only through its one api_* function.

A tool never names a ticket. It passes the lease it was given, and the function reads the ticket
from the lease (db/sql/05-lease.sql). The lease comes from the signed token of the request
(app/tools/serve.py, app/security/middleware.py), never from a tool argument.
"""

from __future__ import annotations

import psycopg
from mcp.server.mcpserver.exceptions import ToolError

# The exact text every api_* function raises for an unknown, expired or revoked lease, or one that
# does not list the calling tool.
LEASE_INVALID = "lease invalid"


class LeaseError(ToolError):
    """The lease is unknown, expired, revoked or does not list this tool.

    A ToolError, so the MCP server passes the text "lease invalid" back to the caller; any other
    exception reaches it only as "Error executing tool <name>", with no detail."""


def call_api(conn: psycopg.Connection, query: str, params: tuple) -> psycopg.Cursor:
    """Run an api_* call. A refused lease becomes LeaseError("lease invalid") with no database
    detail (function names, lines), so the agent learns only that the lease was refused."""
    try:
        return conn.execute(query, params)
    except psycopg.errors.RaiseException as err:
        if err.diag.message_primary == LEASE_INVALID:
            raise LeaseError(LEASE_INVALID) from None
        raise
