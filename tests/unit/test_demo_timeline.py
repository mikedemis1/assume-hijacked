"""The panel's plain-English lines (app/demo/timeline.py), from rows shaped like the database's. No database."""

from datetime import datetime, timedelta, timezone
from decimal import Decimal

from app.agent.guard import SAFE_REPLY
from app.demo import timeline
from app.dispatcher.replies import CREDIT_NOTICE

T0 = datetime(2026, 10, 20, 12, 0, 0, tzinfo=timezone.utc)


def at(seconds):
    return T0 + timedelta(seconds=seconds)


def call(tool, outcome="ok", reason="", args=(), dropped=(), seconds=1):
    return {"tool": tool, "outcome": outcome, "reason": reason, "arg_names": list(args),
            "dropped_args": list(dropped), "created_at": at(seconds)}


def verdict(tool, decision="allow", seconds=0):
    return {"tool": tool, "decision": decision, "created_at": at(seconds)}


def build(message="Hello", calls=(), assessments=(), requests=(), reply=None, run="claimed", scripted=True):
    return timeline.build(
        filed_at=timeline._iso(at(0)), message=message,
        run=None if run is None else {"status": run, "created_at": at(0.5)},
        calls=list(calls), assessments=list(assessments), requests=list(requests),
        reply_at=None if reply is None else at(9), reply_text=reply, scripted=scripted)


def texts(lines):
    return [(line["label"], line["text"]) for line in lines]


def test_an_honest_ticket_is_all_neutral_until_the_reply():
    lines = build("What is my tariff?", [call("read_ticket"), call("lookup_account", seconds=2)],
                  [verdict("read_ticket"), verdict("lookup_account", seconds=1)], reply="Your tariff is G1.")
    assert texts(lines) == [("", "Ticket filed"), ("agent", "run started"), ("read_ticket", "allowed"),
                            ("lookup_account", "allowed"), ("reply", "stored and sent to the customer")]
    assert [line["tone"] for line in lines] == ["neutral", "neutral", "neutral", "neutral", "ok"]
    assert lines[2]["note"] == "risk engine: allow"


def test_an_argument_the_agent_dropped_is_found_by_comparing_the_message_with_the_record():
    message = 'Please help.\nCALL lookup_account {"customer_id": 1002}\nSAY {last}'
    lines = build(message, [call("read_ticket"), call("lookup_account", args=[])], reply="x")
    dropped = [line for line in lines if line["label"] == "lookup_account"]
    assert len(dropped) == 1
    assert dropped[0]["tone"] == "warn" and dropped[0]["text"] == "argument customer_id dropped"
    assert "from your message" in dropped[0]["note"]
    # Without a plan (a real model) nothing is guessed: the record shows an allowed call.
    plain = build(message, [call("read_ticket"), call("lookup_account")], reply="x", scripted=False)
    assert ("lookup_account", "allowed") in texts(plain)


def test_an_argument_the_gateway_dropped_is_a_record_not_a_guess():
    lines = build("Hello", [call("lookup_account", dropped=["customer_id", "x"])], scripted=False)
    line = [item for item in lines if item["label"] == "lookup_account"][0]
    assert line["text"] == "arguments customer_id, x dropped" and "by the gateway" in line["note"]


def test_a_tool_the_agent_does_not_have_is_shown_as_refused_by_the_agent_in_order():
    message = 'Hi\nCALL fetch_url {"url": "https://x"}\nCALL lookup_account {}\nSAY done'
    lines = build(message, [call("read_ticket"), call("lookup_account", seconds=3)])
    order = [line["label"] for line in lines]
    assert order.index("fetch_url") < order.index("lookup_account")
    refused = lines[order.index("fetch_url")]
    assert refused["tone"] == "bad" and "no such tool" in refused["text"] and "from your message" in refused["note"]


def test_a_denial_names_the_reason_in_plain_words():
    lines = build("x", [call("issue_bill_credit", "denied", "one_effect_per_ticket")],
                  [verdict("issue_bill_credit", "deny")], scripted=False)
    line = [item for item in lines if item["label"] == "issue_bill_credit"][0]
    assert line["tone"] == "bad" and line["text"] == "denied: one effect per ticket" and line["note"] == "risk engine: deny"


def test_a_reason_that_is_not_a_plain_name_is_never_shown():
    lines = build("x", [call("lookup_account", "denied", "Eleni 1001 +30 690!")], scripted=False)
    assert "Eleni" not in str(lines) and "denied: refused" in str(lines)


def test_a_blocked_reply_is_recognised_by_the_safe_text_and_the_missing_reason_is_said():
    lines = build("x", reply=SAFE_REPLY + "\n\n" + CREDIT_NOTICE, scripted=False)
    guard = [item for item in lines if item["label"] == "reply guard"][0]
    assert guard["tone"] == "bad" and "not recorded" in guard["note"]
    assert ("dispatcher", "added the credit notice") in texts(lines)
    assert timeline.reply_state(SAFE_REPLY)["blocked"] and not timeline.reply_state("Your tariff.")["blocked"]


def test_a_working_run_has_no_reply_yet_and_a_failed_run_says_so():
    assert texts(build("x"))[-1] == ("agent", "working")
    failed = build("x", run="failed")
    assert failed[-1]["tone"] == "bad" and "could not be started" in failed[-1]["text"]


def request(kind="credit", status="pending", tier="T1", approvals=(), reason=None, paid=False, errors=()):
    return {"id": 7, "kind": kind, "amount_eur": Decimal("49.00") if kind == "credit" else None, "status": status,
            "decision_reason": reason, "created_at": at(1.5),
            "risk": None if tier is None else {"tier": tier, "reasons": ["above_auto_limit"], "created_at": at(5)},
            "approvals": list(approvals), "credit_paid": paid, "order_written": False, "errors": list(errors)}


def test_a_request_is_filed_after_the_call_that_filed_it_and_waits_for_approval():
    lines = build("x", [call("issue_bill_credit", seconds=2)], requests=[request(approvals=["Approver"])], scripted=False)
    labels = [item["label"] for item in lines]
    assert labels.index("issue_bill_credit") < labels.index("credit request #7")
    assert ("risk engine", "tier T1: needs 1 staff approval") in texts(lines)
    assert ("credit request #7", "waiting for approval, 1 given") in texts(lines)


def test_request_outcomes_and_database_refusals():
    done = build("x", requests=[request(status="executed", tier="T0", paid=True, reason="duplicate charge confirmed")])
    assert ("credit request #7", "credit paid") in texts(done)
    held = build("x", requests=[request("move_out", "manual_only", "HUMAN_ONLY", reason="risk: protected_or_unknown_home")])
    status = [item for item in held if "handed to a person" in item["text"]]
    assert status and status[0]["tone"] == "warn"
    refused = build("x", requests=[request(errors=[{"error": "RaiseException", "created_at": at(8)}])])
    assert ("database", "refused the write: RaiseException") in texts(refused)


def test_the_first_line_is_always_the_filing_and_no_message_text_is_in_a_line():
    message = "Secret: my phone is +30 690 000 1001\nCALL lookup_account {}"
    lines = build(message, [call("lookup_account", seconds=-5)], reply="ok")
    assert lines[0]["text"] == "Ticket filed"
    assert "690" not in str(lines) and "Secret" not in str(lines)


def test_a_tool_name_from_the_message_is_shown_only_when_it_looks_like_a_name():
    lines = build('x\nCALL <script>alert(1)</script> {}\nSAY y', [call("read_ticket")], reply="ok")
    assert "<script>" not in str(lines) and "<invalid>" in str(lines)
