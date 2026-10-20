"""The risk rules: pure functions, no database, no I/O, no clock.

The risk engine gathers the facts (from the database) and these functions judge them. Keeping
the judgement pure means every rule has a table-driven test and a mutation proof.

Effects (assess_effect). Hard rules run first, in order; the first hit wins and nothing is
scored. A hard-rule verdict carries score 100 (the top of the scale) so an audit row never reads
as a low-risk 0. Otherwise the score items are added up and the score picks the tier.

    rule / score item              applies to   points  reason
    -----------------------------  -----------  ------  --------------------
    amount missing or <= 0         credit       hard    invalid_amount (REJECT)
    protection is not NO           move_out     hard    protected_or_unknown_home (HUMAN_ONLY)
    amount > auto_max_eur          credit       +40     above_auto_limit
    amount > 200                   credit       +40     above_200
    reason != duplicate_charge     credit       +40     no_auto_evidence
    evidence not confirmed         credit       +40     evidence_unconfirmed
    refused_credits_last_hour >= 2 credit       +40     recent_refusals
    blocked_calls_on_ticket >= 1   both         +30     blocked_calls

    tier: credit 0 -> T0, 1..69 -> T1, 70+ -> T2;  move_out 0..69 -> T1, 70+ -> T2.

A kind other than credit or move_out is a programming error and raises ValueError.
Reasons are a tuple, in the order the rules fired.

Calls (assess_call). Checked in order, first hit wins: paused, lease not live, tool not in the
lease, three denials on the lease (pause the agents), call budget, second effect call.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal

ENGINE_VERSION = "rules-1"

HARD_RULE_SCORE = 100
HUMAN_TIER_SCORE = 70  # score at which a credit or move-out goes to T2
HARD_AMOUNT_EUR = Decimal("200")
REFUSED_CREDITS_LIMIT = 2
DENIED_CALLS_LIMIT = 3
CALL_BUDGET = 8
EFFECT_TOOLS = frozenset({"request_disconnection", "issue_bill_credit"})

_WEIGHTS = {
    "above_auto_limit": 40,
    "above_200": 40,
    "no_auto_evidence": 40,
    "evidence_unconfirmed": 40,
    "recent_refusals": 40,
    "blocked_calls": 30,
}


@dataclass(frozen=True)
class EffectFacts:
    kind: str  # credit | move_out
    amount_eur: Decimal | None
    reason: str | None
    protection: str  # YES | NO
    evidence_confirmed: bool
    refused_credits_last_hour: int
    blocked_calls_on_ticket: int


@dataclass(frozen=True)
class Assessment:
    tier: str
    score: int
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class CallFacts:
    tool: str
    lease_live: bool
    tool_in_lease: bool
    paused: bool
    calls_on_lease: int
    effect_calls_on_lease: int
    denied_on_lease: int


def _hard(tier: str, reason: str) -> Assessment:
    return Assessment(tier, HARD_RULE_SCORE, (reason,))


def _credit_tier(score: int) -> str:
    if score == 0:
        return "T0"
    if score < HUMAN_TIER_SCORE:
        return "T1"
    return "T2"


def _moveout_tier(score: int) -> str:
    if score < HUMAN_TIER_SCORE:
        return "T1"
    return "T2"


def _credit_reasons(f: EffectFacts, amount: Decimal, auto_max_eur: Decimal) -> list[str]:
    reasons = []
    if amount > auto_max_eur:
        reasons.append("above_auto_limit")
    if amount > HARD_AMOUNT_EUR:
        reasons.append("above_200")
    if f.reason != "duplicate_charge":
        reasons.append("no_auto_evidence")
    if not f.evidence_confirmed:
        reasons.append("evidence_unconfirmed")
    if f.refused_credits_last_hour >= REFUSED_CREDITS_LIMIT:
        reasons.append("recent_refusals")
    return reasons


def assess_effect(f: EffectFacts, auto_max_eur: Decimal) -> Assessment:
    if f.kind == "credit":
        if f.amount_eur is None or f.amount_eur <= 0:
            return _hard("REJECT", "invalid_amount")
        reasons = _credit_reasons(f, f.amount_eur, auto_max_eur)
        tier_for = _credit_tier
    elif f.kind == "move_out":
        if f.protection != "NO":
            return _hard("HUMAN_ONLY", "protected_or_unknown_home")
        reasons = []
        tier_for = _moveout_tier
    else:
        raise ValueError(f"unknown effect kind: {f.kind!r}")
    if f.blocked_calls_on_ticket >= 1:
        reasons.append("blocked_calls")
    score = sum(_WEIGHTS[r] for r in reasons)
    return Assessment(tier_for(score), score, tuple(reasons))


def assess_call(f: CallFacts) -> tuple[str, tuple[str, ...]]:
    if f.paused:
        return "deny", ("paused",)
    if not f.lease_live:
        return "deny", ("lease",)
    if not f.tool_in_lease:
        return "deny", ("tool_not_in_lease",)
    if f.denied_on_lease >= DENIED_CALLS_LIMIT:
        return "pause", ("repeated_denials",)
    if f.calls_on_lease >= CALL_BUDGET:
        return "deny", ("call_budget",)
    if f.tool in EFFECT_TOOLS and f.effect_calls_on_lease >= 1:
        return "deny", ("one_effect_per_ticket",)
    return "allow", ()
