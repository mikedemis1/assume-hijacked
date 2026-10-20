"""The presenter's cards (app/demo/console.py): three plain lines and a badge from rows shaped like the database's."""

from datetime import datetime, timedelta, timezone

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
