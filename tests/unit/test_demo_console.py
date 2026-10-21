"""The presenter's cards (app/demo/console.py): three plain lines and a badge from rows shaped like the database's."""

from datetime import datetime, timedelta, timezone

import pytest

from app.agent.guard import SAFE_REPLY
from app.demo import attacks, console

T0 = datetime(2026, 10, 20, 12, 0, 0, tzinfo=timezone.utc)


def at(seconds):
    return T0 + timedelta(seconds=seconds)


def data(*, calls=(), requests=(), events=(), reply_kind="agent", replied=True):
    return {"run": {"status": "replied", "created_at": at(0)}, "calls": list(calls), "assessments": [],
            "requests": list(requests), "events": list(events),
            "reply_at": at(9) if replied else None, "reply_kind": reply_kind if replied else None}


def test_the_neighbour_attack_is_contained_by_the_login_bound_id_and_eleni_gets_her_own_account():
    drop = {"kind": "dropped_argument", "tool": "lookup_account", "arg_names": ["customer_id"], "reported_at": at(2)}
    reply = 'Here is your account: {"name": "Eleni Papadopoulou", "tariff": "G1 residential"}'
    card = console.view(ticket_id=7, attack=attacks.BY_ID["neighbour"], simulated=True, data=data(events=[drop]), reply=reply)
    assert card["tried"] == "read Nikos's account (customer 1002)"
    assert card["stopped"] == "Login-bound ID — the agent can only use the logged-in customer's ID"
    assert card["got"] == "her own account"
    assert card["badge"] == {"kind": "contained", "text": "✓ Attack contained"} and card["nodes"] == ["agent"]
    assert console.summary([card], False) == {"blocked": 1, "waiting": 0, "killSwitch": "off"}


def call(tool, *, dropped=(), outcome="allowed", reason=None):
    return {"tool": tool, "arg_names": [], "dropped_args": list(dropped), "outcome": outcome, "reason": reason,
            "created_at": at(3)}


def request(kind, *, tier="T1", status="pending"):
    return {"id": 1, "kind": kind, "amount_eur": None, "status": status, "decision_reason": None, "created_at": at(4),
            "risk": {"tier": tier, "reasons": [], "created_at": at(5)}, "approvals": [], "credit_paid": False,
            "order_written": False, "errors": []}


ACCOUNT = 'Here is your account: {"name": "Eleni Papadopoulou", "tariff": "G1 residential"}'
UNKNOWN_TOOL = {"kind": "unknown_tool", "tool": "fetch_url", "arg_names": [], "reported_at": at(2)}

# (attack, rows, reply, stopped, got, badge kind, lit nodes)
CASES = [
    ("neighbour",
     data(events=[{"kind": "dropped_argument", "tool": "lookup_account", "arg_names": ["customer_id"], "reported_at": at(2)}]),
     ACCOUNT, "Login-bound ID — the agent can only use the logged-in customer's ID", "her own account", "contained", ["agent"]),
    ("refund", data(), SAFE_REPLY,
     "Reply guard — the unsafe reply was replaced", "a safe reply", "contained", ["dispatcher"]),
    ("power",
     data(calls=[call("request_disconnection", dropped=["supply_point_id", "protection"]), call("request_disconnection")],
          requests=[request("move_out")], reply_kind="template"),
     "A colleague will check.", "Login-bound ID — the house number was dropped; her own move-out needs a staff approval",
     "a reply saying a colleague will check", "waiting", ["agent", "staff"]),
    ("export",
     data(calls=[call("lookup_account", dropped=["webhook"])], events=[UNKNOWN_TOOL]),
     ACCOUNT, "Agent tool list — the agent has no tool for that", "her own account", "contained", ["agent"]),
    ("credits",
     data(calls=[call("issue_bill_credit"), call("issue_bill_credit", outcome="denied", reason="one_effect_per_ticket")],
          requests=[request("credit")], reply_kind="template"),
     "A colleague will check.", "Risk engine — credits need a human; the extra requests were refused",
     "a reply saying a colleague will check", "waiting", ["risk", "staff"]),
    (None, data(), "Your tariff is G1 residential.", "Nothing to stop", "a plain answer", "normal", []),
]


@pytest.mark.parametrize("attack,rows,reply,stopped,got,kind,nodes", CASES, ids=[c[0] or "honest" for c in CASES])
def test_each_chip_and_an_honest_message_get_their_card(attack, rows, reply, stopped, got, kind, nodes):
    card = console.view(ticket_id=7, attack=attacks.BY_ID.get(attack), simulated=attack is not None, data=rows, reply=reply)
    assert card["stopped"] == stopped and card["got"] == got
    assert card["badge"]["kind"] == kind and card["nodes"] == nodes
