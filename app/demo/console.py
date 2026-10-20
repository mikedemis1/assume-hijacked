"""What the security console shows for the tickets of one presenter session, from the records.

Nothing here is invented: the flow nodes, the counters and the banner are derived from the same rows
as the live feed (app/demo/database.py reads them as demo_ops; app/demo/timeline.py words them).
Names that came from a ticket pass through app/demo/vocabulary.py first (ruling R14).

A node has a state:
  idle      nothing reached it
  passed    it let the work through unchanged (blue)
  changed   it altered or held something: an argument dropped, a fixed reply, a person is needed (amber)
  stopped   it refused (red)
  ok        it did its job and the outcome is fine (green)
"""

from __future__ import annotations

from app.demo import attacks, timeline, vocabulary

NODES = (("agent", "Agent"), ("gateway", "Gateway"), ("risk", "Risk engine"), ("tools", "Tools"),
         ("database", "Database"), ("reply", "Reply guard"))

WAITING_TIERS = ("T1", "T2", "HUMAN_ONLY")


def _node(key: str, state: str, note: str = "") -> dict[str, str]:
    return {"key": key, "label": dict(NODES)[key], "state": state, "note": note}


def _dropped_names(data: dict) -> list[str]:
    names: list[str] = []
    for call in data["calls"]:
        names += list(call["dropped_args"])
    names += [n for e in data["events"] if e["kind"] == "dropped_argument" for n in e["arg_names"]]
    return names


def flow(data: dict) -> list[dict[str, str]]:
    run, calls, events, requests = data["run"], data["calls"], data["events"], data["requests"]
    # agent
    if run is None:
        agent = _node("agent", "idle")
    elif run["status"] == "failed" or any(e["kind"] == "unknown_tool" for e in events):
        unknown = [e["tool"] for e in events if e["kind"] == "unknown_tool"]
        agent = _node("agent", "stopped", f"refused {vocabulary.tool(unknown[0])}" if unknown else "the run could not start")
    elif any(e["kind"] == "dropped_argument" for e in events):
        agent = _node("agent", "changed", "dropped " + vocabulary.args(
            n for e in events if e["kind"] == "dropped_argument" for n in e["arg_names"]))
    else:
        agent = _node("agent", "passed")
    # gateway
    denied = [c for c in calls if c["outcome"] == "denied"]
    gateway_dropped = [n for c in calls for n in c["dropped_args"]]
    if not calls:
        gateway = _node("gateway", "idle")
    elif denied:
        gateway = _node("gateway", "stopped", "denied: " + timeline.REASONS.get(denied[0]["reason"], "refused"))
    elif gateway_dropped:
        gateway = _node("gateway", "changed", "dropped " + vocabulary.args(gateway_dropped))
    else:
        gateway = _node("gateway", "passed")
    # risk engine: the verdict on each call, and the tier of each effect request
    verdicts = [a["decision"] for a in data["assessments"]]
    tiers = [r["risk"]["tier"] for r in requests if r["risk"] is not None]
    if "deny" in verdicts or "pause" in verdicts or "REJECT" in tiers:
        risk = _node("risk", "stopped", "refused")
    elif any(t in WAITING_TIERS for t in tiers):
        risk = _node("risk", "changed", "a person must decide")
    elif verdicts or tiers:
        risk = _node("risk", "ok", "allowed")
    else:
        risk = _node("risk", "idle")
    # tools: only calls that got past the gateway and the risk engine reach one
    reached = [c for c in calls if c["outcome"] in ("ok", "tool_error", "unavailable")]
    if any(c["outcome"] != "ok" for c in reached):
        tools = _node("tools", "stopped", "a tool failed")
    elif reached:
        tools = _node("tools", "ok")
    else:
        tools = _node("tools", "idle")
    # database
    failed = [r for r in requests if r["errors"]]
    waiting = [r for r in requests if r["status"] == "pending" and r["risk"] is not None and r["risk"]["tier"] in WAITING_TIERS]
    if failed:
        database = _node("database", "stopped", "a database rule refused the write")
    elif waiting or any(r["status"] == "manual_only" for r in requests):
        database = _node("database", "changed", "waiting for a person")
    elif reached or requests:
        database = _node("database", "ok")
    else:
        database = _node("database", "idle")
    # reply guard
    kind = data["reply_kind"]
    if data["reply_at"] is None:
        reply = _node("reply", "idle")
    elif kind == "safe":
        reply = _node("reply", "stopped", "blocked and replaced")
    elif kind == "template":
        reply = _node("reply", "changed", "a fixed reply, not the model's text")
    else:
        reply = _node("reply", "ok", "stored")
    return [agent, gateway, risk, tools, database, reply]


def banner(attack: attacks.Attack | None, nodes: list[dict], replied: bool) -> dict[str, str] | None:
    """Only a ticket that carried an armed attack gets one, and it says contained only when a wall acted."""
    if attack is None:
        return None
    if not replied:
        return {"kind": "running", "text": "The attack is running. The walls are at work."}
    if any(n["state"] in ("changed", "stopped") for n in nodes):
        return {"kind": "contained", "text": f"Attack contained · OWASP {attack.asi_text}"}
    return {"kind": "open", "text": "No wall acted on this attack. Look at the feed."}


def decisions(data: dict) -> int:
    """Denied calls, calls with a dropped argument, the agent's own drops and refusals, replies that
    were blocked or replaced, and effect requests that were rejected or refused."""
    n = sum(1 for c in data["calls"] if c["outcome"] == "denied" or c["dropped_args"])
    n += len(data["events"])
    n += 1 if data["reply_kind"] in ("safe", "template") else 0
    n += sum(1 for r in data["requests"]
             if r["status"] in ("rejected", "refused") or (r["risk"] is not None and r["risk"]["tier"] == "REJECT"))
    return n


def waiting_for_a_person(data: dict) -> int:
    return sum(1 for r in data["requests"]
               if r["status"] == "manual_only"
               or (r["status"] == "pending" and r["risk"] is not None and r["risk"]["tier"] in WAITING_TIERS))


def view(*, ticket_id: int, filed_at: str, body: str, attack: attacks.Attack | None, data: dict,
         reply: str | None, scripted: bool) -> dict:
    nodes = flow(data)
    replied = data["reply_at"] is not None
    lines = timeline.build(
        filed_at=filed_at, message=body, run=data["run"], calls=data["calls"], assessments=data["assessments"],
        requests=data["requests"], reply_at=data["reply_at"], reply_text=reply, scripted=scripted,
        events=data["events"], reply_kind=data["reply_kind"])
    return {
        "id": ticket_id, "filedAt": filed_at, "replied": replied,
        "attack": None if attack is None else {"id": attack.id, "label": attack.label, "asi": list(attack.asi)},
        "order": None if attack is None else list(attack.plan),
        "flow": nodes, "banner": banner(attack, nodes, replied), "feed": lines,
        "decisions": decisions(data), "waiting": waiting_for_a_person(data),
    }


def summary(views: list[dict], paused: bool) -> dict:
    return {"blocked": sum(v["decisions"] for v in views), "waiting": sum(v["waiting"] for v in views),
            "killSwitch": "on" if paused else "off"}
