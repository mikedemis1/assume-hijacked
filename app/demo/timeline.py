"""What the walls did for one ticket, as short plain-English lines.

The input is only what the database records (app/demo/database.py reads it as demo_ops): the
agent run, the tool gateway's record of every call (tool, argument names, dropped argument names,
outcome, reason), the risk engine's verdict on each call, the effect requests with their risk tier,
approvals and executor outcome, and the stored reply.

Two things are not in the database, and this module says so instead of guessing:

- The agent's own code drops arguments and refuses unknown tools before the gateway sees a call
  (app/agent/core.py), and only writes that to its log. With the scripted model the demo knows
  what the model was told, because it is in the customer's own message (CALL lines). When it has
  that plan it compares the plan with the gateway's record, and the lines that come from the
  comparison carry the source "from your message" so they are not mistaken for a record.
- Why the reply guard blocked a reply is only logged. What is recorded is the reply: the guard
  replaces a blocked reply with a fixed text, and this module recognises that text.

No ticket text goes into a line. Tool and argument names that come from the message are shown only
when they look like identifiers.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone

from app.agent.core import ALLOWED_ARGS
from app.agent.guard import SAFE_REPLY
from app.agent.llm import Reply, ToolCall
from app.agent.llm import parse_plan
from app.dispatcher.replies import CREDIT_NOTICE, MEDICAL_QUESTION

SAFE_NAME = re.compile(r"[A-Za-z0-9_]{1,64}")

TONES = ("neutral", "ok", "warn", "bad")

REASONS = {
    "unknown_tool": "no such tool",
    "lease": "no valid lease for this ticket",
    "tool_not_in_lease": "this tool is not allowed on this ticket",
    "pod_mismatch": "the caller is not the pod the lease was given to",
    "paused": "all agents are paused",
    "repeated_denials": "too many refused calls, agents paused",
    "call_budget": "call budget for this ticket used up",
    "one_effect_per_ticket": "one effect per ticket",
    "risk_unavailable": "risk engine unavailable",
    "risk_timeout": "risk engine did not answer in time",
    "risk_other": "refused by the risk engine",
    "descriptor_changed": "the tool's description changed since review",
    "db_unavailable": "database unavailable",
    "tool_unreachable": "tool unreachable",
    "invalid_argument": "the tool refused the arguments",
    "denied": "the tool refused it",
    "unavailable": "the tool was unavailable",
    "tool_error": "the tool failed",
}

RISK_RULES = {
    "above_auto_limit": "above the automatic limit",
    "above_200": "above 200 EUR",
    "no_auto_evidence": "no automatic evidence",
    "evidence_unconfirmed": "evidence not confirmed",
    "recent_refusals": "recent refused credits",
    "blocked_calls": "refused calls on this ticket",
    "invalid_amount": "invalid amount",
    "protected_or_unknown_home": "protected or unknown home",
}

TIERS = {
    "T0": ("ok", "can go ahead on its own"),
    "T1": ("warn", "needs 1 staff approval"),
    "T2": ("warn", "needs 2 staff approvals"),
    "HUMAN_ONLY": ("bad", "only a person may decide"),
    "REJECT": ("bad", "rejected"),
}

REQUEST_STATUS = {
    "executed": ("ok", "done"),
    "approved": ("ok", "approved"),
    "rejected": ("bad", "rejected"),
    "refused": ("bad", "refused by staff"),
    "manual_only": ("warn", "handed to a person"),
    "held_global": ("warn", "held by the daily cap"),
    "needs_staff": ("warn", "needs staff"),
}


@dataclass(frozen=True)
class Line:
    at: str  # ISO time, or "" when the line has no time of its own
    tone: str  # neutral | ok | warn | bad
    label: str  # a tool or a wall: "lookup_account", "risk engine"; "" for none
    text: str
    note: str = ""  # the source or a second fact, smaller

    def as_dict(self) -> dict[str, str]:
        return {"at": self.at, "tone": self.tone, "label": self.label, "text": self.text, "note": self.note}


def _iso(moment: datetime) -> str:
    """UTC with milliseconds, so times from the database and from this service sort as text."""
    return moment.astimezone(timezone.utc).isoformat(timespec="milliseconds")


def now_iso() -> str:
    return _iso(datetime.now(timezone.utc))


def _shown(name: object) -> str:
    return name if isinstance(name, str) and SAFE_NAME.fullmatch(name) else "<invalid>"


def _names(names: Iterable[object]) -> str:
    return ", ".join(_shown(n) for n in names)


def _plural(count: int, one: str, many: str) -> str:
    return one if count == 1 else many


def _reason(code: str) -> str:
    return REASONS.get(code, code.replace("_", " ") if SAFE_NAME.fullmatch(code or "") else "refused")


def reply_state(text: str | None) -> dict[str, object]:
    """What the stored reply shows: whether the reply guard replaced the agent's text, and which
    notices the dispatcher added."""
    if text is None:
        return {"stored": False, "blocked": False, "notices": []}
    notices = []
    if CREDIT_NOTICE in text:
        notices.append("credit notice")
    if MEDICAL_QUESTION in text:
        notices.append("medical-equipment question")
    return {"stored": True, "blocked": text.startswith(SAFE_REPLY), "notices": notices}


def _plan_calls(message: str) -> list[ToolCall]:
    """The tool calls the message orders. A message with no CALL line orders none: the scripted
    model's default plan is not something the visitor asked for."""
    if not re.search(r"^\s*CALL ", message, re.MULTILINE):
        return []
    return [step for step in parse_plan(message) if isinstance(step, ToolCall)]


def _call_lines(calls: list[dict], assessments: list[dict], plan: list[ToolCall] | None, finished: bool) -> list[Line]:
    """One line per call the gateway recorded, and, when a plan is known, the agent-side steps the
    gateway never saw. Each recorded call is matched with the next plan step that names the same tool."""
    unused = list(assessments)

    def verdict_of(call: dict) -> str:
        for k, a in enumerate(unused):
            if a["tool"] == call["tool"] and a["created_at"] <= call["created_at"]:
                del unused[k]
                return a["decision"]
        return ""

    steps = list(plan or [])
    lines: list[Line] = []
    position = 0  # first plan step that has not been matched yet
    for call in calls:
        tool = call["tool"]
        by_agent: list[str] = []
        # Plan steps skipped on the way (a tool the agent does not have) are shown before the call
        # they precede, so the timeline keeps the order of the message.
        hit = next((i for i in range(position, len(steps)) if steps[i].name == tool), None)
        if hit is not None:
            for step in steps[position:hit]:
                lines.append(_agent_refusal(step, call["created_at"]))
            asked = steps[hit].args if isinstance(steps[hit].args, dict) else {}
            if tool in ALLOWED_ARGS:
                by_agent = sorted(k for k in asked if k not in call["arg_names"] and k not in call["dropped_args"])
            position = hit + 1
        lines.append(_gateway_line(call, by_agent, verdict_of(call)))
    if finished:  # until the reply is stored the agent may simply not have got that far
        for step in steps[position:]:
            lines.append(_agent_refusal(step, None))
    return lines


def _agent_refusal(step: ToolCall, before) -> Line:
    at = _iso(before) if before is not None else ""
    if step.name in ALLOWED_ARGS:
        return Line(at, "neutral", _shown(step.name), "asked for, but the run ended before the call",
                    "from your message")
    return Line(at, "bad", _shown(step.name), "refused: the agent has no such tool", "by the agent (from your message)")


def _gateway_line(call: dict, by_agent: list[str], verdict: str) -> Line:
    """One line for a call the gateway recorded. `by_agent` are the argument names the agent's own
    code dropped before the call (known only by comparing with the message)."""
    at = _iso(call["created_at"])
    tool, outcome, reason = call["tool"], call["outcome"], call["reason"]
    if tool == "unknown":
        tool = "unknown tool"
    by_gateway = list(call["dropped_args"])
    dropped = by_agent + by_gateway
    facts = []
    if by_agent:
        facts.append("dropped by the agent, before the gateway (from your message)")
    if by_gateway:
        facts.append("dropped by the gateway")
    if verdict:
        facts.append(f"risk engine: {verdict}")
    drop_text = f"{_plural(len(dropped), 'argument', 'arguments')} {_names(dropped)} dropped"
    if outcome == "ok":
        if dropped:
            return Line(at, "warn", tool, drop_text, " · ".join([*facts, "call allowed"]))
        return Line(at, "neutral", tool, "allowed", " · ".join(facts))
    note = " · ".join(([drop_text] if dropped else []) + facts)
    if outcome == "tool_error":
        return Line(at, "warn", tool, f"allowed, then the tool failed: {_reason(reason)}", note)
    if outcome == "denied":
        return Line(at, "bad", tool, f"denied: {_reason(reason)}", note)
    return Line(at, "warn", tool, f"not completed: {_reason(reason or outcome)}", note)


def _request_lines(request: dict, filed_by_call_at=None) -> list[Line]:
    number = request["id"]
    kind = "credit" if request["kind"] == "credit" else "disconnection"
    amount = f", {request["amount_eur"]:.2f} EUR" if request["amount_eur"] is not None else ""
    filed_at = max(request["created_at"], filed_by_call_at) if filed_by_call_at else request["created_at"]
    lines = [Line(_iso(filed_at), "neutral", f"{kind} request #{number}", f"filed{amount}")]
    risk = request["risk"]
    if risk is not None:
        tone, meaning = TIERS.get(risk["tier"], ("warn", "unknown tier"))
        rules = ", ".join(RISK_RULES.get(r, r.replace("_", " ")) for r in risk["reasons"])
        lines.append(Line(_iso(risk["created_at"]), tone, "risk engine",
                          f"tier {_shown(risk['tier'])}: {meaning}", rules))
    status = request["status"]
    if status == "pending":
        if risk is not None and request["approvals"]:
            roles = ", ".join(request["approvals"])
            lines.append(Line("", "warn", f"{kind} request #{number}", f"waiting for approval, {len(request['approvals'])} given", roles))
        elif risk is not None:
            lines.append(Line("", "warn", f"{kind} request #{number}", "waiting for approval, none given yet", ""))
        else:
            lines.append(Line("", "neutral", f"{kind} request #{number}", "waiting for the risk engine", ""))
    else:
        tone, words = REQUEST_STATUS.get(status, ("neutral", status.replace("_", " ") if SAFE_NAME.fullmatch(status) else "closed"))
        why = request["decision_reason"] or ""
        done = request["credit_paid"] if request["kind"] == "credit" else request["order_written"]
        if status == "executed" and done:
            words = "credit paid" if request["kind"] == "credit" else "disconnection order written"
        lines.append(Line("", tone, f"{kind} request #{number}", words, why if SAFE_TEXT.fullmatch(why) else ""))
    for error in request["errors"]:
        lines.append(Line(_iso(error["created_at"]), "bad", "database",
                          f"refused the write: {_shown(error['error'])}", "a database rule stopped it"))
    return lines


SAFE_TEXT = re.compile(r"[A-Za-z0-9 _:,.\-]{0,160}")


def build(
    *,
    filed_at: str,
    message: str,
    run: dict | None,
    calls: list[dict],
    assessments: list[dict],
    requests: list[dict],
    reply_at,
    reply_text: str | None,
    scripted: bool,
) -> list[dict[str, str]]:
    """The timeline of one ticket, oldest first. `filed_at` and `message` are the demo's own
    record of what the customer sent; everything else is read from the database. Lines without a
    time of their own (an effect's current status) go after the line they follow. The first line is
    always "Ticket filed": this service and the database keep their own clocks."""
    lines: list[Line] = []
    if run is not None:
        if run["status"] == "failed":
            lines.append(Line(_iso(run["created_at"]), "bad", "agent", "run could not be started", "a person looks at the ticket"))
        else:
            lines.append(Line(_iso(run["created_at"]), "neutral", "agent", "run started"))
    lines += _call_lines(calls, assessments, _plan_calls(message) if scripted else None, reply_at is not None)
    # The gateway records a call after the tool has answered, and the request is filed during the
    # call, so the request is older than its call. Show it after the call that filed it.
    filed_by = {"credit": "issue_bill_credit", "move_out": "request_disconnection"}
    effect_calls = {tool: [c for c in calls if c["tool"] == tool and c["outcome"] == "ok"]
                    for tool in filed_by.values()}
    seen: dict[str, int] = {}
    for request in requests:
        tool = filed_by.get(request["kind"], "")
        number = seen[tool] = seen.get(tool, -1) + 1
        call = effect_calls.get(tool, [])[number:number + 1]
        lines += _request_lines(request, call[0]["created_at"] if call else None)
    state = reply_state(reply_text)
    if reply_at is not None:
        at = _iso(reply_at)
        if state["blocked"]:
            lines.append(Line(at, "bad", "reply guard", "reply blocked and replaced by a safe reply",
                              "the reason is not recorded in the database"))
        else:
            lines.append(Line(at, "ok", "reply", "stored and sent to the customer"))
        for notice in state["notices"]:
            lines.append(Line(at, "neutral", "dispatcher", f"added the {notice}"))
    elif run is not None and run["status"] != "failed":
        lines.append(Line("", "neutral", "agent", "working"))
    return [Line(filed_at, "neutral", "", "Ticket filed").as_dict(), *_in_order(lines)]


def _in_order(lines: list[Line]) -> list[dict[str, str]]:
    """Sort by time; a line without a time keeps its place after the line before it."""
    keyed: list[tuple[str, int, Line]] = []
    last = ""
    for number, line in enumerate(lines):
        last = line.at or last
        keyed.append((last, number, line))
    keyed.sort(key=lambda item: (item[0], item[1]))
    return [line.as_dict() for _, _, line in keyed]
