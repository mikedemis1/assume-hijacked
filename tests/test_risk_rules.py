"""The risk rules are pure: no database, no clock. Every test builds facts and reads the verdict."""

from __future__ import annotations

import itertools
from decimal import Decimal

import pytest

from app.risk import rules
from app.risk.rules import (
    ENGINE_VERSION,
    Assessment,
    CallFacts,
    EffectFacts,
    assess_call,
    assess_effect,
)

LIMIT = 3  # moveout_limit
AUTO = Decimal("50")  # auto_max_eur


def credit(**over) -> EffectFacts:
    """A clean credit: small, duplicate charge, evidence confirmed, nothing recent. Scores 0."""
    base = dict(
        kind="credit",
        amount_eur=Decimal("10"),
        reason="duplicate_charge",
        protection="NO",
        evidence_confirmed=True,
        moveouts_last_hour=0,
        refused_credits_last_hour=0,
        blocked_calls_on_ticket=0,
    )
    base.update(over)
    return EffectFacts(**base)


def moveout(**over) -> EffectFacts:
    """A clean move-out: the home is not protected, no flood, no blocked calls."""
    base = dict(
        kind="move_out",
        amount_eur=None,
        reason=None,
        protection="NO",
        evidence_confirmed=False,
        moveouts_last_hour=0,
        refused_credits_last_hour=0,
        blocked_calls_on_ticket=0,
    )
    base.update(over)
    return EffectFacts(**base)


def judge(f: EffectFacts, limit: int = LIMIT, auto: Decimal = AUTO) -> Assessment:
    return assess_effect(f, limit, auto)


def test_engine_version():
    assert ENGINE_VERSION == "rules-1"


def test_facts_and_assessment_are_frozen():
    with pytest.raises(AttributeError):
        credit().amount_eur = Decimal("1")  # type: ignore[misc]
    with pytest.raises(AttributeError):
        Assessment("T0", 0, ()).tier = "T1"  # type: ignore[misc]
    with pytest.raises(AttributeError):
        CallFacts("x", True, True, False, 0, 0, 0).tool = "y"  # type: ignore[misc]


# --- hard rules ---------------------------------------------------------------------------------


@pytest.mark.parametrize("amount", [None, Decimal("0"), Decimal("-0.01"), Decimal("-5")])
def test_credit_with_no_or_non_positive_amount_is_rejected(amount):
    assert judge(credit(amount_eur=amount)) == Assessment("REJECT", 100, ("invalid_amount",))


def test_smallest_positive_credit_is_not_rejected():
    assert judge(credit(amount_eur=Decimal("0.01"))).tier == "T0"


@pytest.mark.parametrize("protection", ["YES", "UNKNOWN", "maybe", ""])
def test_moveout_with_protection_not_no_goes_to_humans(protection):
    assert judge(moveout(protection=protection)) == Assessment(
        "HUMAN_ONLY", 100, ("protected_or_unknown_home",)
    )


def test_moveout_flood_is_held_at_the_limit_not_below_it():
    assert judge(moveout(moveouts_last_hour=LIMIT - 1)).tier == "T1"
    assert judge(moveout(moveouts_last_hour=LIMIT)) == Assessment("HOLD", 100, ("flood",))
    assert judge(moveout(moveouts_last_hour=LIMIT + 5)).tier == "HOLD"


def test_flood_uses_the_limit_it_is_given():
    assert judge(moveout(moveouts_last_hour=1), limit=1).tier == "HOLD"
    assert judge(moveout(moveouts_last_hour=1), limit=2).tier == "T1"


def test_protection_rule_comes_before_flood():
    f = moveout(protection="YES", moveouts_last_hour=99)
    assert judge(f) == Assessment("HUMAN_ONLY", 100, ("protected_or_unknown_home",))


def test_hard_rules_apply_only_to_their_own_kind():
    # A credit ignores the move-out rules, a move-out ignores the credit rule.
    assert judge(credit(protection="YES", moveouts_last_hour=99)).tier == "T0"
    assert judge(moveout(amount_eur=None)).tier == "T1"
    assert judge(moveout(amount_eur=Decimal("-1"))).tier == "T1"


def test_unknown_kind_is_a_programming_error():
    with pytest.raises(ValueError, match=r"^unknown effect kind: 'refund'$"):
        judge(credit(kind="refund"))
    with pytest.raises(ValueError, match=r"^unknown effect kind: ''$"):
        judge(credit(kind=""))


# --- credit score items -------------------------------------------------------------------------


def test_clean_credit_scores_zero_tier_t0():
    assert judge(credit()) == Assessment("T0", 0, ())


def test_above_auto_limit_boundary():
    assert judge(credit(amount_eur=AUTO)).score == 0
    r = judge(credit(amount_eur=AUTO + Decimal("0.01")))
    assert (r.score, r.tier, r.reasons) == (40, "T1", ("above_auto_limit",))


def test_auto_limit_comes_from_the_argument():
    f = credit(amount_eur=Decimal("20"))
    assert assess_effect(f, LIMIT, Decimal("19.99")).reasons == ("above_auto_limit",)
    assert assess_effect(f, LIMIT, Decimal("20")).reasons == ()


def test_above_200_boundary_and_both_amount_items_stack():
    r = judge(credit(amount_eur=Decimal("200")))
    assert r.reasons == ("above_auto_limit",)  # 200 is above 50 but not above 200
    r = judge(credit(amount_eur=Decimal("200.01")))
    assert (r.score, r.tier, r.reasons) == (80, "T2", ("above_auto_limit", "above_200"))


def test_above_200_alone_when_auto_limit_is_higher():
    r = assess_effect(credit(amount_eur=Decimal("250")), LIMIT, Decimal("500"))
    assert r.reasons == ("above_200",)
    assert r.score == 40


def test_amount_is_decimal_exact():
    # 200.00 and 200 are the same amount; 50.00 is not above a limit of 50.
    assert judge(credit(amount_eur=Decimal("200.00"))).reasons == ("above_auto_limit",)
    assert judge(credit(amount_eur=Decimal("50.00"))).score == 0


@pytest.mark.parametrize("reason", ["goodwill", "other", "", None])
def test_reason_other_than_duplicate_charge_has_no_auto_evidence(reason):
    r = judge(credit(reason=reason))
    assert (r.score, r.tier, r.reasons) == (40, "T1", ("no_auto_evidence",))


def test_unconfirmed_evidence():
    r = judge(credit(evidence_confirmed=False))
    assert (r.score, r.tier, r.reasons) == (40, "T1", ("evidence_unconfirmed",))


@pytest.mark.parametrize("refused,expected", [(0, 0), (1, 0), (2, 40), (3, 40)])
def test_recent_refusals_boundary(refused, expected):
    r = judge(credit(refused_credits_last_hour=refused))
    assert r.score == expected
    assert ("recent_refusals" in r.reasons) is (expected == 40)


def test_blocked_calls_boundary_on_credit():
    assert judge(credit(blocked_calls_on_ticket=0)).score == 0
    r = judge(credit(blocked_calls_on_ticket=1))
    assert (r.score, r.tier, r.reasons) == (30, "T1", ("blocked_calls",))
    assert judge(credit(blocked_calls_on_ticket=7)).score == 30  # counted once, not per call


def test_credit_score_tiers_at_the_reachable_scores():
    assert judge(credit()).tier == "T0"  # 0
    assert judge(credit(blocked_calls_on_ticket=1)).tier == "T1"  # 30
    assert judge(credit(evidence_confirmed=False)).tier == "T1"  # 40
    r = judge(credit(evidence_confirmed=False, blocked_calls_on_ticket=1))  # 40 + 30 = 70
    assert (r.score, r.tier) == (70, "T2")
    r = judge(credit(evidence_confirmed=False, reason="goodwill"))  # 80
    assert (r.score, r.tier) == (80, "T2")


def test_the_tier_threshold_is_70_not_69():
    # The weights never give 69, so test the threshold itself through the tier helpers.
    assert rules._credit_tier(0) == "T0"
    assert rules._credit_tier(1) == "T1"
    assert rules._credit_tier(69) == "T1"
    assert rules._credit_tier(70) == "T2"
    assert rules._moveout_tier(0) == "T1"
    assert rules._moveout_tier(69) == "T1"
    assert rules._moveout_tier(70) == "T2"


def test_credit_reasons_are_in_the_order_the_rules_fire():
    f = credit(
        amount_eur=Decimal("300"),
        reason="goodwill",
        evidence_confirmed=False,
        refused_credits_last_hour=2,
        blocked_calls_on_ticket=1,
    )
    r = judge(f)
    assert r.reasons == (
        "above_auto_limit",
        "above_200",
        "no_auto_evidence",
        "evidence_unconfirmed",
        "recent_refusals",
        "blocked_calls",
    )
    assert r.score == 40 * 5 + 30
    assert r.tier == "T2"


def test_reasons_is_a_tuple():
    assert isinstance(judge(credit(evidence_confirmed=False)).reasons, tuple)
    assert isinstance(judge(credit()).reasons, tuple)


# --- move-out score and tier --------------------------------------------------------------------


def test_clean_moveout_is_t1_with_score_zero():
    assert judge(moveout()) == Assessment("T1", 0, ())


def test_credit_only_score_items_do_not_apply_to_moveouts():
    f = moveout(
        amount_eur=Decimal("999"), reason="goodwill", evidence_confirmed=False, refused_credits_last_hour=9
    )
    assert judge(f) == Assessment("T1", 0, ())


def test_blocked_calls_apply_to_moveouts_too():
    r = judge(moveout(blocked_calls_on_ticket=1))
    assert (r.score, r.tier, r.reasons) == (30, "T1", ("blocked_calls",))


def test_moveout_stays_t1_with_the_reachable_scores():
    # The only move-out item is 30 points, so T2 cannot be reached with these weights.
    for blocked in (0, 1, 5):
        assert judge(moveout(blocked_calls_on_ticket=blocked)).tier == "T1"


# --- property: a hard rule always wins ----------------------------------------------------------

AMOUNTS = [None, Decimal("-1"), Decimal("0"), Decimal("0.01"), Decimal("50"), Decimal("201")]
REASONS = [None, "duplicate_charge", "goodwill"]
PROTECTIONS = ["YES", "NO", "UNKNOWN"]
BOOLS = [True, False]
COUNTS = [0, 1, 2, 3, 10]


def all_facts():
    for kind, amount, reason, prot, ev, mo, refused, blocked in itertools.product(
        ["credit", "move_out"], AMOUNTS, REASONS, PROTECTIONS, BOOLS, COUNTS, COUNTS, COUNTS
    ):
        yield EffectFacts(kind, amount, reason, prot, ev, mo, refused, blocked)


def test_hard_rule_always_wins():
    seen = {"REJECT": 0, "HUMAN_ONLY": 0, "HOLD": 0, "other": 0}
    for f in all_facts():
        r = judge(f)
        if f.kind == "credit" and (f.amount_eur is None or f.amount_eur <= 0):
            expected = "REJECT"
        elif f.kind == "move_out" and f.protection != "NO":
            expected = "HUMAN_ONLY"
        elif f.kind == "move_out" and f.moveouts_last_hour >= LIMIT:
            expected = "HOLD"
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


def test_every_verdict_is_consistent_with_its_score():
    for f in all_facts():
        r = judge(f)
        if r.tier in ("REJECT", "HUMAN_ONLY", "HOLD"):
            continue
        assert r.score == sum(rules._WEIGHTS[x] for x in r.reasons), f
        if f.kind == "credit":
            want = "T0" if r.score == 0 else "T1" if r.score < 70 else "T2"
        else:
            want = "T1" if r.score < 70 else "T2"
        assert r.tier == want, f


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


def test_call_allowed_when_nothing_is_wrong():
    assert assess_call(call()) == ("allow", ())


def test_paused_denies():
    assert assess_call(call(paused=True)) == ("deny", ("paused",))


def test_dead_lease_denies():
    assert assess_call(call(lease_live=False)) == ("deny", ("lease",))


def test_tool_not_in_lease_denies():
    assert assess_call(call(tool_in_lease=False)) == ("deny", ("tool_not_in_lease",))


@pytest.mark.parametrize("denied,verdict", [(0, "allow"), (2, "allow"), (3, "pause"), (4, "pause")])
def test_repeated_denials_pause_from_three(denied, verdict):
    got = assess_call(call(denied_on_lease=denied))
    assert got == (verdict, ("repeated_denials",) if verdict == "pause" else ())


@pytest.mark.parametrize("calls,verdict", [(0, "allow"), (7, "allow"), (8, "deny"), (9, "deny")])
def test_call_budget_denies_from_eight(calls, verdict):
    got = assess_call(call(calls_on_lease=calls))
    assert got == (verdict, ("call_budget",) if verdict == "deny" else ())


@pytest.mark.parametrize("tool", ["request_disconnection", "issue_bill_credit"])
def test_second_effect_call_is_denied(tool):
    assert assess_call(call(tool=tool, effect_calls_on_lease=0)) == ("allow", ())
    assert assess_call(call(tool=tool, effect_calls_on_lease=1)) == ("deny", ("one_effect_per_ticket",))
    assert assess_call(call(tool=tool, effect_calls_on_lease=2)) == ("deny", ("one_effect_per_ticket",))


@pytest.mark.parametrize(
    "tool", ["read_ticket", "lookup_account", "set_temp_protection", "tool_issue_bill_credit", ""]
)
def test_effect_limit_applies_only_to_the_two_effect_tools(tool):
    assert assess_call(call(tool=tool, effect_calls_on_lease=5)) == ("allow", ())


def test_call_rules_are_checked_in_the_listed_order():
    facts = dict(
        tool="issue_bill_credit",
        paused=True,
        lease_live=False,
        tool_in_lease=False,
        denied_on_lease=3,
        calls_on_lease=8,
        effect_calls_on_lease=1,
    )
    order = [
        ("paused", False, "deny", "paused"),
        ("lease_live", True, "deny", "lease"),
        ("tool_in_lease", True, "deny", "tool_not_in_lease"),
        ("denied_on_lease", 0, "pause", "repeated_denials"),
        ("calls_on_lease", 0, "deny", "call_budget"),
        ("effect_calls_on_lease", 0, "deny", "one_effect_per_ticket"),
    ]
    for field, cured, decision, reason in order:
        assert assess_call(CallFacts(**facts)) == (decision, (reason,)), field
        facts[field] = cured  # cure the rule that just fired; the next one in the list must fire
    assert assess_call(CallFacts(**facts)) == ("allow", ())


def test_call_property_allow_only_when_no_rule_fires():
    for tool, live, in_lease, paused, calls, effects, denied in itertools.product(
        ["read_ticket", "issue_bill_credit", "request_disconnection"],
        BOOLS,
        BOOLS,
        BOOLS,
        [0, 7, 8],
        [0, 1],
        [0, 2, 3],
    ):
        f = CallFacts(tool, live, in_lease, paused, calls, effects, denied)
        decision, reasons = assess_call(f)
        clean = (
            live
            and in_lease
            and not paused
            and denied < 3
            and calls < 8
            and not (tool != "read_ticket" and effects >= 1)
        )
        assert (decision == "allow") is clean, f
        assert (reasons == ()) is clean, f
        assert decision in ("allow", "deny", "pause")
