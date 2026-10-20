"""The security console's flow, banner and counters (app/demo/console.py) and the vocabulary that
decides which names it may print (app/demo/vocabulary.py), from rows shaped like the database's."""

from datetime import datetime, timedelta, timezone

import pytest

from app.demo import attacks, console, vocabulary

T0 = datetime(2026, 10, 20, 12, 0, 0, tzinfo=timezone.utc)


def at(seconds):
    return T0 + timedelta(seconds=seconds)


def call(tool="lookup_account", outcome="ok", reason="", dropped=()):
    return {"tool": tool, "outcome": outcome, "reason": reason, "arg_names": [], "dropped_args": list(dropped),
            "created_at": at(1)}


def data(*, run="replied", calls=(), assessments=(), requests=(), events=(), reply_kind=None, replied=True):
    return {"run": None if run is None else {"status": run, "created_at": at(0)}, "calls": list(calls),
            "assessments": list(assessments), "requests": list(requests), "events": list(events),
            "reply_at": at(9) if replied else None, "reply_kind": reply_kind if replied else None}


def states(d):
    return {n["key"]: n["state"] for n in console.flow(d)}


def request(status="pending", tier="T1", errors=()):
    return {"id": 7, "kind": "credit", "amount_eur": 1, "status": status, "decision_reason": None, "created_at": at(2),
            "risk": None if tier is None else {"tier": tier, "reasons": [], "created_at": at(3)},
            "approvals": [], "credit_paid": False, "order_written": False, "errors": list(errors)}


def test_an_honest_ticket_lights_the_path_without_amber_or_red():
    d = data(calls=[call()], assessments=[{"tool": "lookup_account", "decision": "allow", "created_at": at(0)}],
             reply_kind="agent")
    assert states(d) == {"agent": "passed", "gateway": "passed", "risk": "ok", "tools": "ok", "database": "ok", "reply": "ok"}


def test_nothing_lights_before_the_run_starts():
    assert set(states(data(run=None, replied=False)).values()) == {"idle"}


def test_an_argument_dropped_by_the_gateway_is_amber_and_named_from_the_vocabulary():
    d = data(calls=[call(dropped=["customer_id", "Eleni_1001"])])
    gateway = [n for n in console.flow(d) if n["key"] == "gateway"][0]
    assert gateway["state"] == "changed"
    assert gateway["note"] == "dropped customer_id, an argument the tool does not take"
    assert "Eleni" not in str(console.flow(d))


def test_a_denied_call_is_red_at_the_gateway_and_never_reaches_a_tool():
    d = data(calls=[call("fetch_url", "denied", "unknown_tool")])
    got = states(d)
    assert got["gateway"] == "stopped" and got["tools"] == "idle" and got["database"] == "idle"


def test_the_agents_own_refusals_and_drops_are_red_and_amber():
    d = data(events=[{"kind": "unknown_tool", "tool": "fetch_url", "arg_names": [], "reported_at": at(2)}])
    agent = [n for n in console.flow(d) if n["key"] == "agent"][0]
    assert agent["state"] == "stopped" and agent["note"] == "refused fetch_url"
    odd = data(events=[{"kind": "unknown_tool", "tool": "secret_name", "arg_names": [], "reported_at": at(2)}])
    assert [n for n in console.flow(odd) if n["key"] == "agent"][0]["note"] == "refused an unknown tool"
    dropped = data(events=[{"kind": "dropped_argument", "tool": "lookup_account", "arg_names": ["customer_id"], "reported_at": at(2)}])
    assert states(dropped)["agent"] == "changed"


@pytest.mark.parametrize("request_, risk, database", [
    (request("pending", "T1"), "changed", "changed"),
    (request("pending", "HUMAN_ONLY"), "changed", "changed"),
    (request("rejected", "REJECT"), "stopped", "ok"),
    (request("executed", "T0"), "ok", "ok"),
])
def test_an_effect_request_decides_the_risk_and_database_nodes(request_, risk, database):
    got = states(data(calls=[call("issue_bill_credit")], requests=[request_]))
    assert (got["risk"], got["database"]) == (risk, database)


def test_a_database_rule_that_refused_a_write_is_red():
    got = states(data(calls=[call("issue_bill_credit")], requests=[request("executed", "T0", [{"error": "RaiseException", "created_at": at(5)}])]))
    assert got["database"] == "stopped"


@pytest.mark.parametrize("kind, state", [("agent", "ok"), ("template", "ok"), ("safe", "stopped")])
def test_the_reply_guard_follows_the_kind_of_the_stored_reply(kind, state):
    assert states(data(reply_kind=kind))["reply"] == state


def test_the_banner_says_contained_only_when_the_reply_is_stored_and_a_wall_acted():
    attack = attacks.BY_ID["neighbour"]
    acted = console.flow(data(calls=[call(dropped=["customer_id"])]))
    assert console.banner(attack, acted, True) == {"kind": "contained", "text": "Attack contained · OWASP ASI01 + ASI03"}
    assert console.banner(attack, acted, False)["kind"] == "running"
    quiet = console.flow(data(calls=[call()], reply_kind="agent"))
    assert console.banner(attack, quiet, True)["kind"] == "open"      # no claim when nothing stopped it
    assert console.banner(None, acted, True) is None                  # an honest ticket gets no banner


def test_every_attack_banner_names_its_own_asi_ids():
    for attack in attacks.ATTACKS:
        text = console.banner(attack, [{"state": "stopped"}], True)["text"]
        assert all(asi in text for asi in attack.asi), attack.id


def test_the_counters_add_up_denied_dropped_blocked_and_replaced_decisions():
    d = data(calls=[call("fetch_url", "denied", "unknown_tool"), call(dropped=["customer_id"]), call()],
             events=[{"kind": "dropped_argument", "tool": "lookup_account", "arg_names": ["customer_id"], "reported_at": at(2)}],
             requests=[request("pending", "T1"), request("rejected", "REJECT")], reply_kind="template")
    assert console.decisions(d) == 2 + 1 + 1           # two calls, one agent event, the rejection (the template is no decision)
    assert console.waiting_for_a_person(d) == 1
    assert console.summary([{"decisions": 5, "waiting": 1}, {"decisions": 2, "waiting": 0}], True) == {
        "blocked": 7, "waiting": 1, "killSwitch": "on"}


def test_an_honest_credit_request_with_a_fixed_reply_is_not_an_attack_blocked():
    d = data(calls=[call("issue_bill_credit")], requests=[request("executed", "T0")], reply_kind="template",
             assessments=[{"tool": "issue_bill_credit", "decision": "allow", "created_at": at(0)}])
    nodes = console.flow(d)
    assert {n["key"]: n["state"] for n in nodes}["reply"] == "ok"
    assert console.decisions(d) == 0
    assert console.banner(None, nodes, True) is None


def test_a_fixed_reply_alone_never_makes_an_armed_attack_contained():
    attack = attacks.BY_ID["credits"]
    d = data(calls=[call("issue_bill_credit")], requests=[request("executed", "T0")], reply_kind="template",
             assessments=[{"tool": "issue_bill_credit", "decision": "allow", "created_at": at(0)}])
    assert console.banner(attack, console.flow(d), True)["kind"] == "open"


# --- the vocabulary (ruling R14) ---

def test_known_tools_and_arguments_are_printed_and_the_rest_is_a_fixed_phrase():
    for name in ("lookup_account", "issue_bill_credit", "fetch_url", "request_disconnection"):
        assert vocabulary.tool(name) == name
    for name in ("customer_id", "move_out_date", "amount_eur", "webhook"):
        assert vocabulary.arg(name) == name
    for odd in ("Eleni", "lookup_account ", "LOOKUP_ACCOUNT", "<script>", "", None, 5, ["lookup_account"]):
        assert vocabulary.tool(odd) == "an unknown tool"
        assert vocabulary.arg(odd) == "an argument the tool does not take"


def test_the_vocabulary_holds_the_schemas_and_the_attack_tables_names_and_nothing_else():
    from app.agent.core import ALLOWED_ARGS

    attack_tools, attack_args = attacks.attack_names()
    assert set(ALLOWED_ARGS) <= vocabulary.TOOLS and attack_tools <= vocabulary.TOOLS
    assert {a for names in ALLOWED_ARGS.values() for a in names} <= vocabulary.ARGS and attack_args <= vocabulary.ARGS
    assert vocabulary.TOOLS == set(ALLOWED_ARGS) | attack_tools


def test_the_manifests_load_into_the_vocabulary_and_a_failure_is_logged(monkeypatch, caplog):
    tools, args = vocabulary._from_manifests()
    assert tools == {"read_ticket", "lookup_account", "request_disconnection", "issue_bill_credit", "set_temp_protection"}
    assert {"move_out_date", "amount_eur", "evidence_ref"} <= args
    import app.gateway.manifest as manifest

    def broken():
        raise OSError("gone")

    monkeypatch.setattr(manifest, "load_manifests", broken)
    with caplog.at_level("WARNING"):
        assert vocabulary._from_manifests() == (set(), set())
    assert "manifests not loaded" in caplog.text


def test_unknown_risk_rules_are_not_echoed():
    from app.demo import timeline

    request_ = request("pending", "T1")
    request_["risk"]["reasons"] = ["Eleni_1001_phone", "above_200"]
    lines = timeline._request_lines(request_)
    text = str(lines)
    assert "Eleni" not in text and "another rule" in text and "above 200 EUR" in text


def test_unknown_arguments_are_said_once():
    assert vocabulary.args(["a1", "b2", "customer_id", "c3"]) == "an argument the tool does not take, customer_id"
