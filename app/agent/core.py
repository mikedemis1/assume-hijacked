"""The agent loop. Code, not the LLM, decides which ticket (and so which customer) a tool sees."""

from __future__ import annotations

import json
import re

from app.agent.events import security_event
from app.agent.guard import SAFE_REPLY, block_reason, numbers_in
from app.agent.llm import Reply
from app.agent.llm_client import LlmError
from app.common import toolerrors

MAX_STEPS = 10
# What the model sees when a tool call failed in a way the gateway did not name (see _scrub).
TOOL_ERROR = "ERROR: the tool could not complete this request"
GIVE_UP = "We could not complete your request automatically. A colleague will contact you."
# The longest reply the dispatcher takes (app/dispatcher/replies.py MAX_TEXT_CHARS); a test keeps the
# two equal. A longer or an empty text is not sent: GIVE_UP is.
MAX_REPLY_CHARS = 4000

# Arguments the LLM may set. The lease (which names the ticket) is always set by this code, and a
# ticket_id or lease from the model is dropped.
ALLOWED_ARGS = {
    "read_ticket": set(),
    "lookup_account": set(),
    "request_disconnection": {"move_out_date"},
    "issue_bill_credit": {"amount_eur", "reason", "evidence_ref"},
    "set_temp_protection": set(),
}

# Tool and argument names come from the model, so they can carry any text. Log one only when it
# looks like an identifier; anything else (a sentence, health data, a forged log line) is "<invalid>".
SAFE_NAME = re.compile(r"[A-Za-z0-9_]{1,64}")
NAMES_LIMIT = 20


def _name(value) -> str:
    return value if isinstance(value, str) and SAFE_NAME.fullmatch(value) else "<invalid>"


def _names(names) -> list[str]:
    return [_name(name) for name in list(names)[:NAMES_LIMIT]]


# What the agent reports to the dispatcher about its own drops (the dispatcher checks it again,
# app/dispatcher/events.py, and the limits are the same). Names only, never a value. A name that is
# not an identifier is sent as PLACEHOLDER so the list stays valid and the drop is still counted.
REPORT_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")
PLACEHOLDER = "invalid_name"
REPORT_EVENTS_LIMIT = 32
REPORT_NAMES_LIMIT = 16


def _report_name(value) -> str:
    return value if isinstance(value, str) and REPORT_NAME.fullmatch(value) else PLACEHOLDER


def event_list(drops) -> list[dict]:
    """The events to send, from (kind, tool, argument names) tuples, within the dispatcher's limits."""
    return [
        {"kind": kind, "tool": _report_name(tool), "args": [_report_name(n) for n in list(names)[:REPORT_NAMES_LIMIT]]}
        for kind, tool, names in list(drops)[:REPORT_EVENTS_LIMIT]
    ]


class Agent:
    def __init__(self, llm, gateway):
        self.llm = llm
        self.gateway = gateway
        self.events: list[dict] = []  # for the dispatcher, see event_list; set by handle_ticket

    def handle_ticket(self, ticket_id: int, lease: str) -> str:
        """The text to send as the reply to one ticket. `lease` is the lease the dispatcher handed
        out for this ticket; it goes to every tool and never into the transcript, so the model never
        sees it. `ticket_id` is for the security log only: the tools take the ticket from the lease.

        The text is the model's reply, the safe text when the reply guard blocks it, or the give-up
        text. It carries no notice: the dispatcher adds the credit notice and the medical question
        itself, from the gateway's record of calls (app/dispatcher/replies.py), after it has run the
        guard again.

        `events` holds, afterwards, the drops of this run to send with the reply."""
        drops: list[tuple[str, object, list]] = []
        try:
            return self._run(ticket_id, lease, drops)
        finally:
            self.events = event_list(drops)

    def _run(self, ticket_id: int, lease: str, drops: list) -> str:
        body = _ticket_body(_scrub(self.gateway.call("read_ticket", {"lease": lease}), lease))
        if body is None:
            security_event("ticket_unreadable", ticket_id=ticket_id)
            return GIVE_UP
        transcript: list[dict] = [{"role": "ticket", "text": body}]
        allowed_numbers: set[str] = set()  # numbers a tool returned in this conversation
        for _ in range(MAX_STEPS):
            try:
                action = self.llm.next_action(transcript)
            except LlmError as err:
                # The model could not answer (over its budget, unreachable, an answer that makes no
                # sense): no other step can work either, so the run ends with the give-up text.
                security_event("llm_refused", ticket_id=ticket_id, category=err.category)
                return GIVE_UP
            if isinstance(action, Reply):
                reason = block_reason(action.text, allowed_numbers)
                if reason:
                    security_event("reply_blocked", ticket_id=ticket_id, reason=reason)
                    return SAFE_REPLY
                return self._usable(action.text, ticket_id)
            args, dropped = self._safe_args(action.name, action.args, lease)
            if args is None:
                security_event("unknown_tool", ticket_id=ticket_id, name=_name(action.name))
                drops.append(("unknown_tool", action.name, []))
                result = f"ERROR: unknown tool {action.name}"
            else:
                if dropped:
                    drops.append(("dropped_argument", action.name, dropped))
                    security_event(
                        "dropped_argument", ticket_id=ticket_id, tool=action.name, args=_names(dropped)
                    )
                result = _scrub(self.gateway.call(action.name, args), lease)
                if result.startswith("ERROR:"):
                    category = toolerrors.category_of(result)
                    security_event("tool_error", ticket_id=ticket_id, tool=action.name, category=category or "other")
                    if category == toolerrors.LEASE:
                        # The lease is gone (ended, revoked, or it never covered this tool): no
                        # other call can work either, so the run ends here.
                        security_event("lease_refused", ticket_id=ticket_id, tool=action.name)
                        return GIVE_UP
                else:
                    # Not read_ticket: its result repeats the ticket text, which the customer wrote.
                    if action.name != "read_ticket":
                        allowed_numbers |= numbers_in(result)
            # What the model asked for, without the lease, so a model that reads the conversation
            # again sees its own calls. An unknown tool's arguments are not sent back.
            shown = {} if args is None else {key: value for key, value in args.items() if key != "lease"}
            transcript.append({"role": "tool", "name": action.name, "args": shown, "result": result})
        security_event("max_steps", ticket_id=ticket_id)
        return GIVE_UP

    @staticmethod
    def _usable(text: str, ticket_id: int) -> str:
        """The reply as it can be sent: the dispatcher takes 1 to MAX_REPLY_CHARS characters."""
        if not text.strip() or len(text) > MAX_REPLY_CHARS:
            security_event("reply_unusable", ticket_id=ticket_id)
            return GIVE_UP
        return text

    def _safe_args(self, name: str, args: dict, lease: str) -> tuple[dict | None, list[str]]:
        """The arguments to send, and the names of the ones the model sent that were dropped."""
        if name not in ALLOWED_ARGS:
            return None, []
        allowed = ALLOWED_ARGS[name]
        if not isinstance(args, dict):
            args = {}
        clean = {key: value for key, value in args.items() if key in allowed}
        dropped = [key for key in args if key not in allowed]
        clean["lease"] = lease
        return clean, dropped


def _scrub(result: str, lease: str) -> str:
    """What a tool answered, made safe for the transcript: the model must never see the lease.

    An error text can repeat the arguments that were sent (an MCP argument validation error shows
    them, shortened, so a plain search for the lease would miss part of it). So an error is reduced
    to one of the gateway's fixed categories (ERROR: lease, denied, invalid_argument, unavailable,
    tool_error; app/common/toolerrors.py), matched exactly, or else to a fixed text. Any other
    result has the lease removed."""
    if result.startswith("ERROR:"):
        category = toolerrors.category_of(result)
        return toolerrors.error_text(category) if category else TOOL_ERROR
    return result.replace(lease, "<lease>") if lease else result


def _ticket_body(raw: str) -> str | None:
    if raw.startswith("ERROR:"):
        return None
    try:
        body = json.loads(raw)["body"]
    except (ValueError, KeyError, TypeError, RecursionError):
        return None
    return body if isinstance(body, str) else None
