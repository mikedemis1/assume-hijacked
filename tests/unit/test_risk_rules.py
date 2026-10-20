"""The risk rules are pure: no database, no clock. Every test builds facts and reads the verdict."""

from __future__ import annotations

import itertools
from decimal import Decimal

import pytest

from app.risk.rules import Assessment, CallFacts, EffectFacts, assess_call, assess_effect

AUTO = Decimal("50")  # auto_max_eur


def credit(**over) -> EffectFacts:
    """A clean credit: small, duplicate charge, evidence confirmed, nothing recent. Scores 0."""
    base = dict(
        kind="credit",
        amount_eur=Decimal("10"),
        reason="duplicate_charge",
        protection="NO",
        evidence_confirmed=True,
        refused_credits_last_hour=0,
        blocked_calls_on_ticket=0,
    )
    base.update(over)
    return EffectFacts(**base)


def moveout(**over) -> EffectFacts:
    """A clean move-out: the home is not protected, no blocked calls."""
    base = dict(
        kind="move_out",
        amount_eur=None,
        reason=None,
        protection="NO",
        evidence_confirmed=False,
        refused_credits_last_hour=0,
        blocked_calls_on_ticket=0,
    )
    base.update(over)
    return EffectFacts(**base)


def judge(f: EffectFacts, auto: Decimal = AUTO) -> Assessment:
    return assess_effect(f, auto)


# --- credit score items -------------------------------------------------------------------------


def test_credit_score_tiers_at_the_reachable_scores():
    assert judge(credit()).tier == "T0"  # 0
    assert judge(credit(blocked_calls_on_ticket=1)).tier == "T1"  # 30
    assert judge(credit(evidence_confirmed=False)).tier == "T1"  # 40
    r = judge(credit(evidence_confirmed=False, blocked_calls_on_ticket=1))  # 40 + 30 = 70
    assert (r.score, r.tier) == (70, "T2")
    r = judge(credit(evidence_confirmed=False, reason="goodwill"))  # 80
    assert (r.score, r.tier) == (80, "T2")


# --- property: a hard rule always wins ----------------------------------------------------------

AMOUNTS = [None, Decimal("-1"), Decimal("0"), Decimal("0.01"), Decimal("50"), Decimal("201")]
REASONS = [None, "duplicate_charge", "goodwill"]
PROTECTIONS = ["YES", "NO"]
BOOLS = [True, False]
COUNTS = [0, 1, 2, 3, 10]


def all_facts():
    for kind, amount, reason, prot, ev, refused, blocked in itertools.product(
        ["credit", "move_out"], AMOUNTS, REASONS, PROTECTIONS, BOOLS, COUNTS, COUNTS
    ):
        yield EffectFacts(kind, amount, reason, prot, ev, refused, blocked)


def test_hard_rule_always_wins():
    seen = {"REJECT": 0, "HUMAN_ONLY": 0, "other": 0}
    for f in all_facts():
        r = judge(f)
        if f.kind == "credit" and (f.amount_eur is None or f.amount_eur <= 0):
            expected = "REJECT"
        elif f.kind == "move_out" and f.protection != "NO":
            expected = "HUMAN_ONLY"
        else:
            expected = None
        if expected:
            assert r.tier == expected, f
            assert len(r.reasons) == 1, f
            seen[expected] += 1
        else:
            assert r.tier in ("T0", "T1", "T2"), f
            seen["other"] += 1
    assert all(seen.values()), seen


# --- calls --------------------------------------------------------------------------------------


def call(**over) -> CallFacts:
    base = dict(
        tool="read_ticket",
        lease_live=True,
        tool_in_lease=True,
        paused=False,
        calls_on_lease=0,
        effect_calls_on_lease=0,
        denied_on_lease=0,
    )
    base.update(over)
    return CallFacts(**base)


@pytest.mark.parametrize("tool", ["request_disconnection", "issue_bill_credit"])
def test_second_effect_call_is_denied(tool):
    assert assess_call(call(tool=tool, effect_calls_on_lease=0)) == ("allow", ())
    assert assess_call(call(tool=tool, effect_calls_on_lease=1)) == ("deny", ("one_effect_per_ticket",))
    assert assess_call(call(tool=tool, effect_calls_on_lease=2)) == ("deny", ("one_effect_per_ticket",))


@pytest.mark.parametrize("protection", ["YES", "UNKNOWN", "maybe", ""])
def test_asi01_protected_home_goes_to_humans(protection):
    assert judge(moveout(protection=protection)) == Assessment(
        "HUMAN_ONLY", 100, ("protected_or_unknown_home",)
    )


@pytest.mark.parametrize("amount", [None, Decimal("0"), Decimal("-0.01"), Decimal("-5")])
def test_asi02_credit_rule_rejects_missing_or_non_positive_amount(amount):
    assert judge(credit(amount_eur=amount)) == Assessment("REJECT", 100, ("invalid_amount",))


@pytest.mark.parametrize("denied,verdict", [(0, "allow"), (2, "allow"), (3, "pause"), (4, "pause")])
def test_asi10_three_denials_pause_in_the_rules(denied, verdict):
    got = assess_call(call(denied_on_lease=denied))
    assert got == (verdict, ("repeated_denials",) if verdict == "pause" else ())
