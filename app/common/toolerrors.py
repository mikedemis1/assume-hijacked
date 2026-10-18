"""What the agent is told when a tool call fails: `ERROR: <category>`, one of a fixed list.

The tool gateway writes these, the agent reads them. The category says what kind of failure it was
and nothing else: never the tool's own message (it can repeat the arguments, and the arguments can
hold health data or the lease), never a stack trace, never which wall said no.

    lease             the lease is unknown, expired, revoked or does not list this tool
    denied            a wall refused the call (the risk engine, a pause, the wrong pod, a tool
                      whose description changed). The agent is not told which.
    invalid_argument  the tool did not accept the arguments
    unavailable       the tool, or something the call needs, could not be reached
    tool_error        the tool failed for any other reason
"""

from __future__ import annotations

LEASE = "lease"
DENIED = "denied"
INVALID_ARGUMENT = "invalid_argument"
UNAVAILABLE = "unavailable"
TOOL_ERROR = "tool_error"
CATEGORIES = (LEASE, DENIED, INVALID_ARGUMENT, UNAVAILABLE, TOOL_ERROR)
PREFIX = "ERROR: "


def error_text(category: str) -> str:
    if category not in CATEGORIES:
        raise ValueError(f"unknown error category {category!r}")
    return PREFIX + category


def category_of(text: str) -> str | None:
    """The category if `text` is exactly an error text of ours, else None. Exact on purpose: an
    `ERROR: ...` with anything more after it is not ours and is not to be trusted."""
    if text.startswith(PREFIX) and text[len(PREFIX):] in CATEGORIES:
        return text[len(PREFIX):]
    return None
