"""The agent's report of its own drops, checked before it goes near the database.

The agent sends, with its reply, a list of {"kind", "tool", "args"}: the kind of drop, the tool the
model named and the names of the arguments it dropped. Names, never a value; but the model chooses
them, so an identifier of up to 64 characters can still spell short data. The list comes from a
process that may be taken over, so it is checked hard here and again by the database function
record_agent_events (db/sql/05-lease.sql); the limits are the same in both.

A list that breaks any rule is rejected whole: nothing of it is kept, whatever else in it was fine.
"""

from __future__ import annotations

import re

KINDS = ("dropped_argument", "unknown_tool")
# Why a list was refused, for the rejected counter: its shape, one of the count limits, or the database.
REASONS = ("shape", "limit", "db")
NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")
MAX_EVENTS = 32
MAX_NAMES = 16
EVENT_KEYS = {"kind", "tool", "args"}


def checked(value: object) -> list[dict] | None:
    """The list as it may be stored, or None if it breaks a rule. Rebuilt from its parts, so nothing
    the agent added is passed on."""
    return check(value)[0]


def check(value: object) -> tuple[list[dict] | None, str | None]:
    """Like `checked`, with the reason when the list is refused: "limit" (too many events or names)
    or "shape" (anything else)."""
    if not isinstance(value, list):
        return None, "shape"
    if len(value) > MAX_EVENTS:
        return None, "limit"
    clean = []
    for event in value:
        if not isinstance(event, dict) or set(event) != EVENT_KEYS:
            return None, "shape"
        kind, tool, args = event["kind"], event["tool"], event["args"]
        if kind not in KINDS or not _is_name(tool) or not isinstance(args, list):
            return None, "shape"
        if len(args) > MAX_NAMES:
            return None, "limit"
        if not all(_is_name(a) for a in args):
            return None, "shape"
        clean.append({"kind": kind, "tool": tool, "args": list(args)})
    return clean, None


def _is_name(value: object) -> bool:
    return isinstance(value, str) and NAME.fullmatch(value) is not None
