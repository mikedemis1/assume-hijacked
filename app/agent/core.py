"""The agent loop. Code, not the LLM, decides which ticket (and so which customer) a tool sees."""

from __future__ import annotations

import json
import re

from app.agent.events import security_event
from app.agent.guard import SAFE_REPLY, block_reason, numbers_in
from app.agent.llm import Reply

MAX_STEPS = 10
GIVE_UP = "We could not complete your request automatically. A colleague will contact you."

# Arguments the LLM may set. The lease (which names the ticket) is always set by this code, and a
# ticket_id or lease from the model is dropped (decision 1).
ALLOWED_ARGS = {
    "read_ticket": set(),
    "lookup_account": set(),
    "request_disconnection": {"move_out_date"},
    "issue_bill_credit": {"amount_eur", "reason", "evidence_ref"},
    "set_temp_protection": set(),
}
VULNERABLE_EXTRA = {"lookup_account": {"customer_id"}}

# Added by this code, not the model, after a move-out request went in (decision 6, gap I10).
# No digits and no money words, so it would pass the reply guard anyway.
MEDICAL_QUESTION = (
    "Does anyone at the property use medical equipment that needs electricity? "
    "If so, please tell us and we will protect the supply.\n"
    "Χρησιμοποιεί κάποιος στο ακίνητο ιατρικό εξοπλισμό που χρειάζεται ρεύμα; "
    "Αν ναι, πείτε μας και θα προστατεύσουμε την παροχή."
)
# Added by this code, not the model, whenever issue_bill_credit was called, whether the call worked
# or not: the model's reply may still suggest that money is coming. It names a credit, so the reply
# guard would block it; that is why it goes on after the guard.
CREDIT_NOTICE = (
    "No credit is confirmed until it has been checked.\n"
    "Καμία πίστωση δεν επιβεβαιώνεται πριν ελεγχθεί."
)
# Tool and argument names come from the model, so they can carry any text. Log one only when it
# looks like an identifier; anything else (a sentence, health data, a forged log line) is "<invalid>".
SAFE_NAME = re.compile(r"[A-Za-z0-9_]{1,64}")
NAMES_LIMIT = 20


def _name(value) -> str:
    return value if isinstance(value, str) and SAFE_NAME.fullmatch(value) else "<invalid>"


def _names(names) -> list[str]:
    return [_name(name) for name in list(names)[:NAMES_LIMIT]]


class Agent:
    def __init__(self, llm, gateway, *, vulnerable: bool = False):
        self.llm = llm
        self.gateway = gateway
        self.vulnerable = vulnerable

    def handle_ticket(self, ticket_id: int, lease: str) -> str:
        """Answer one ticket. `lease` is the lease opened for this ticket; it goes to every tool
        and never into the transcript, so the model never sees it. `ticket_id` is for the
        security log only: the tools take the ticket from the lease."""
        body = _ticket_body(self.gateway.call("read_ticket", {"lease": lease}))
        if body is None:
            security_event("ticket_unreadable", ticket_id=ticket_id)
            return GIVE_UP
        transcript: list[dict] = [{"role": "ticket", "text": body}]
        allowed_numbers: set[str] = set()  # numbers a tool returned in this conversation
        submitted = False  # a move-out request went in
        credit_asked = False  # issue_bill_credit was called, whatever it answered
        for _ in range(MAX_STEPS):
            action = self.llm.next_action(transcript)
            if isinstance(action, Reply):
                reason = block_reason(action.text, allowed_numbers)
                if reason:
                    security_event("reply_blocked", ticket_id=ticket_id, reason=reason)
                    return _finish(SAFE_REPLY, submitted, credit_asked)
                return _finish(action.text, submitted, credit_asked)
            args, dropped = self._safe_args(action.name, action.args, lease)
            if args is None:
                security_event("unknown_tool", ticket_id=ticket_id, name=_name(action.name))
                result = f"ERROR: unknown tool {action.name}"
            else:
                if dropped:
                    security_event(
                        "dropped_argument", ticket_id=ticket_id, tool=action.name, args=_names(dropped)
                    )
                if action.name == "issue_bill_credit":
                    credit_asked = True
                result = self.gateway.call(action.name, args)
                if result.startswith("ERROR:"):
                    security_event("tool_error", ticket_id=ticket_id, tool=action.name)
                else:
                    # Not read_ticket: its result repeats the ticket text, which the customer wrote.
                    if action.name != "read_ticket":
                        allowed_numbers |= numbers_in(result)
                    if action.name == "request_disconnection":
                        submitted = True
            transcript.append({"role": "tool", "name": action.name, "result": result})
        security_event("max_steps", ticket_id=ticket_id)
        return _finish(GIVE_UP, submitted, credit_asked)

    def _safe_args(self, name: str, args: dict, lease: str) -> tuple[dict | None, list[str]]:
        """The arguments to send, and the names of the ones the model sent that were dropped."""
        if name not in ALLOWED_ARGS:
            return None, []
        allowed = set(ALLOWED_ARGS[name])
        if self.vulnerable:
            allowed |= VULNERABLE_EXTRA.get(name, set())
        if not isinstance(args, dict):
            args = {}
        clean = {key: value for key, value in args.items() if key in allowed}
        dropped = [key for key in args if key not in allowed]
        clean["lease"] = lease
        return clean, dropped


def _ticket_body(raw: str) -> str | None:
    if raw.startswith("ERROR:"):
        return None
    try:
        body = json.loads(raw)["body"]
    except (ValueError, KeyError, TypeError, RecursionError):
        return None
    return body if isinstance(body, str) else None


def _finish(reply: str, submitted: bool, credit_asked: bool) -> str:
    """The model writes the reply; this code adds the credit notice and the medical question,
    after the guard."""
    parts = [reply]
    if credit_asked:
        parts.append(CREDIT_NOTICE)
    if submitted:
        parts.append(MEDICAL_QUESTION)
    return "\n\n".join(parts)
