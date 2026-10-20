"""What the walls did for each message of the session: three plain lines and a badge per message.

Nothing is invented: every line is derived from the rows the database holds for the ticket
(app/demo/database.py reads them as demo_ops). Only fixed phrases are printed, never a name or a
word from a ticket, so a ticket cannot put text on the screen (ruling R14).

    The AI tried:        the attack's sentence (attacks.py), or "answer the question"
    Stopped by:          the strongest wall that acted, from the records
    The customer got:    from the stored reply and its kind

`node` says which part of the architecture strip lights up: agent, gateway, risk or dispatcher.
"""

from __future__ import annotations

from app.agent.guard import SAFE_REPLY
from app.demo import attacks, card

WAITING_TIERS = ("T1", "T2", "HUMAN_ONLY")
# Refusals that come from the risk engine; any other refused call is the tool gateway's.
RISK_REASONS = {"one_effect_per_ticket", "effect_already_requested", "call_budget", "repeated_denials",
                "risk_unavailable", "risk_timeout", "risk_other"}


def _waiting(data: dict) -> list[dict]:
    return [r for r in data["requests"] if r["status"] == "manual_only"
            or (r["status"] == "pending" and r["risk"] is not None and r["risk"]["tier"] in WAITING_TIERS)]


def _stop(node: str, wall: str, why: str) -> dict[str, str]:
    return {"node": node, "wall": wall, "why": why}


def _replaced(data: dict, reply: str | None) -> bool:
    """The reply guard replaced the model's reply (the dispatcher's kind, or the guard's fixed text)."""
    return data["reply_kind"] == "safe" or (reply or "").startswith(SAFE_REPLY)


def stopped_by(data: dict, reply: str | None) -> dict[str, str] | None:
    """The strongest wall that acted on this ticket, or None when nothing did."""
    calls, events, requests = data["calls"], data["events"], data["requests"]
    denied = [c["reason"] for c in calls if c["outcome"] == "denied"]
    waiting = _waiting(data)
    if waiting:
        what = "credits" if waiting[0]["kind"] == "credit" else "power cuts"
        extra = "; the extra requests were refused" if "one_effect_per_ticket" in denied else ""
        return _stop("risk", "Risk engine", f"{what} need a human{extra}")
    if any(r["status"] in ("rejected", "refused") or (r["risk"] and r["risk"]["tier"] == "REJECT") for r in requests):
        return _stop("risk", "Risk engine", "the request was rejected")
    if any(reason in RISK_REASONS for reason in denied):
        return _stop("risk", "Risk engine", "this action is not allowed")
    if denied:
        return _stop("gateway", "Tool gateway", "this tool is not allowed")
    if any(e["kind"] == "unknown_tool" for e in events):
        return _stop("agent", "Agent tool list", "the agent has no tool for that")
    if _replaced(data, reply):
        return _stop("dispatcher", "Reply guard", "the unsafe reply was replaced")
    dropped = [n for c in calls for n in c["dropped_args"]]
    dropped += [n for e in events if e["kind"] == "dropped_argument" for n in e["arg_names"]]
    if "customer_id" in dropped:
        return _stop("agent", "Login-bound ID", "the agent can only use the logged-in customer's ID")
    if dropped:
        return _stop("agent", "Argument filter", "arguments the tool does not take were dropped")
    return None


def _got(data: dict, reply: str | None, waiting: bool) -> str:
    if data["reply_at"] is None:
        return "no answer yet"
    if _replaced(data, reply):
        return "a safe reply"
    if waiting or data["reply_kind"] == "template":
        return "a reply saying a colleague will check"
    return "her own account" if card.account_card(reply) else "a plain answer"


def view(*, ticket_id: int, attack: attacks.Attack | None, simulated: bool, data: dict, reply: str | None) -> dict:
    stop = stopped_by(data, reply)
    waiting = bool(_waiting(data))
    if data["reply_at"] is None:
        badge = ("running", "Working")
    elif waiting:
        badge = ("waiting", "⏳ Waiting for a human")
    elif stop is None and attack is None:
        badge = ("normal", "✓ Normal answer")
    elif stop is not None:
        badge = ("contained", "✓ Attack contained" if attack else "✓ Contained")
    else:
        badge = ("open", "No wall acted, check the records")
    line = f"{stop['wall']} — {stop['why']}" if stop else "Nothing to stop"
    return {
        "id": ticket_id, "simulated": simulated, "attack": attack is not None,
        "tried": attack.tried if attack else "answer the question",
        "stopped": line, "got": _got(data, reply, waiting),
        "badge": {"kind": badge[0], "text": badge[1]},
        "nodes": ([stop["node"]] if stop else []) + (["staff"] if waiting else []),
    }


def summary(views: list[dict], paused: bool) -> dict:
    """Counters: attacks that were contained or wait for a human, messages that wait for one."""
    return {"blocked": sum(1 for v in views if v["attack"] and v["badge"]["kind"] in ("contained", "waiting")),
            "waiting": sum(1 for v in views if v["badge"]["kind"] == "waiting"),
            "killSwitch": "on" if paused else "off"}
