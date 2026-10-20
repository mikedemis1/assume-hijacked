"""What every tool shares: it reaches the database only through its one api_* function.

A tool never names a ticket. It passes the lease it was given, and the function reads the ticket
from the lease (db/sql/05-lease.sql). The lease comes from the signed token of the request
(app/tools/serve.py, app/security/middleware.py), never from a tool argument.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

import psycopg
from mcp.server.mcpserver.exceptions import ToolError

# The exact text every api_* function raises for an unknown, expired or revoked lease, or one that
# does not list the calling tool.
LEASE_INVALID = "lease invalid"

# The exact text api_request_credit / api_request_moveout raise when the lease already filed an
# effect request (db/sql/01-schema.sql, one effect per lease). The tool turns it into a fixed
# ToolError; the gateway shows the agent only the category "denied".
EFFECT_ALREADY_REQUESTED = "effect already requested"


class LeaseError(ToolError):
    """The lease is unknown, expired, revoked or does not list this tool.

    A ToolError, so the MCP server passes the text "lease invalid" back to the caller; any other
    exception reaches it only as "Error executing tool <name>", with no detail."""


class EffectRefused(ToolError):
    """The lease has already filed its one effect request. Fixed text, no database detail, no
    lease: the agent only ever sees the category `denied` (app/common/toolerrors.py)."""


# What a tool says when it does not accept the arguments. Fixed text: the library otherwise shows
# nothing of a plain ValueError, and a message built from the arguments would repeat them.
INVALID_ARGUMENT = "invalid argument"


class ArgumentError(ToolError):
    """The arguments are not acceptable (a date that is not a date, a reason off the list, an
    amount that is not a positive number). The gateway turns the fixed text into the category
    `invalid_argument` for the agent."""


@contextmanager
def checked_arguments() -> Iterator[None]:
    """Turn the tool functions' own refusals (ValueError, and ArithmeticError from a Decimal that
    is not a number) into ArgumentError, whatever their text."""
    try:
        yield
    except (ValueError, ArithmeticError):
        raise ArgumentError(INVALID_ARGUMENT) from None


def call_api(conn: psycopg.Connection, query: str, params: tuple) -> psycopg.Cursor:
    """Run an api_* call. A refused lease becomes LeaseError("lease invalid") and a second effect
    request on a lease becomes EffectRefused, both with no database detail (function names,
    index names, lines), so the agent learns only that the call was refused."""
    try:
        return conn.execute(query, params)
    except psycopg.errors.RaiseException as err:
        if err.diag.message_primary == LEASE_INVALID:
            raise LeaseError(LEASE_INVALID) from None
        if err.diag.message_primary == EFFECT_ALREADY_REQUESTED:
            raise EffectRefused(EFFECT_ALREADY_REQUESTED) from None
        raise
