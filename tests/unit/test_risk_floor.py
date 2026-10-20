"""The approval floor: risk assessments, approver roles and the effect triggers (db/sql/06-risk.sql,
check_credit and check_disconnection_order in db/sql/01-schema.sql).

A credit or a disconnection order is written only when its request has a risk assessment, the
assessment's tier allows the effect at all (required_approvals has a row for it), and enough
distinct staff approved it. The database checks this
on the row itself, so a hijacked executor or console cannot skip the humans: the executor can
write rows, but not assessments; the console can write approvals (through approve_request, for known staff only: tests/unit/
test_staff.py), but cannot make one person count twice.
"""

import psycopg
import pytest

from tests.conftest import BOB_DEV, approve_as, assess
from tests.unit.test_executor_credits import add_credit, credits_count, insert_credit
from tests.unit.test_executor_moveouts import add_moveout, insert_order, orders

TIERS = ["T0", "T1", "T2", "HUMAN_ONLY", "REJECT"]
ANNA, PETROS = "eeab6c5e-f5bc-5d16-af4b-813d9b88be01", "bbc480b8-6ddb-5ecf-8ce6-876023b4cbc3"


def _login_roles(admin, *, exclude=()):
    rows = admin.execute("SELECT rolname FROM pg_roles WHERE rolcanlogin ORDER BY rolname").fetchall()
    return [r["rolname"] for r in rows if r["rolname"] not in ("postgres", *exclude)]


# --- one effect of each kind, ready but for the floor ---
# Everything else the triggers check holds: a credit backed by duplicate charge 2, an order for an
# unprotected home with a move-out date of today. Only the assessment and the approvals decide.

def _credit(admin, tier):
    rid = add_credit(admin, 49, 2, tier=tier)
    return rid, lambda conn: insert_credit(conn, rid, 1, 49)


def _order(admin, tier):
    rid = add_moveout(admin, tier=tier)
    return rid, lambda conn: insert_order(conn, rid, "SP-1001")


EFFECTS = {"credit": _credit, "move_out": _order}


@pytest.fixture
def ex(as_role):
    """One executor connection per test: the role has CONNECTION LIMIT 3 and the stack's executor
    holds one of them."""
    return as_role("executor")


def written(admin):
    return credits_count(admin) + orders(admin)


def approve_all(staff, rid, approvals):
    """Each approver in turn. A duplicate is refused by the primary key; the floor must not count
    it either way, so the refusal is ignored here and the floor test checks the result."""
    for who in approvals:
        try:
            approve_as(staff, rid, who)
        except psycopg.errors.UniqueViolation:
            pass


# --- the floor ---


def test_order_refused_without_assessment(admin, as_role, ex):
    rid, write = _order(admin, tier=None)
    approve_as(as_role("approver"), rid, ANNA)  # an approval, but before any assessment
    with pytest.raises(psycopg.errors.RaiseException, match="no risk assessment"):
        write(ex)
    assert orders(admin) == 0
    assess(admin, rid, "T1")
    # The approval was given before the assessment, so it does not count.
    with pytest.raises(psycopg.errors.RaiseException, match="needs 1 distinct approval"):
        write(ex)
    approve_as(as_role("approver"), rid, PETROS)  # control: an approval after the assessment
    write(ex)
    assert orders(admin) == 1


FLOOR_CASES = {
    # case: (tier, approvers, allowed)
    "T2, one person": ("T2", [ANNA], False),
    "T2, the same person twice": ("T2", [ANNA, ANNA], False),
    "T2, the same person in alternative UUID spelling": ("T2", [ANNA, "EEAB6C5EF5BC5D16AF4B813D9B88BE01"], False),
    "T2, two people": ("T2", [ANNA, PETROS], True),
    "T0, no approval (credit only; an order always needs one)": ("T0", [], None),
}


def test_required_approvals_per_tier(admin):
    expected = {"T0": 0, "T1": 1, "T2": 2}
    for tier in TIERS + ["HOLD", "t1", "T3", "", None]:
        rows = admin.execute("SELECT n FROM required_approvals(%s)", (tier,)).fetchall()
        want = [{"n": expected[tier]}] if tier in expected else []
        assert rows == want, tier


def test_tier_hold_is_refused_by_the_database(admin):
    # HOLD (the move-out flood hold) is gone from the closed list of tiers.
    rid = add_credit(admin, 49, 2, tier=None)
    with pytest.raises(psycopg.errors.CheckViolation):
        admin.execute(
            "INSERT INTO risk_assessments (request_id, tier, score, reasons, engine_version) "
            "VALUES (%s, 'HOLD', 100, '{flood}', 'rules-1')",
            (rid,),
        )


def test_assessment_tier_is_on_the_closed_list(admin):
    rid = add_credit(admin, 49, 2, tier=None)
    for bad in ("T3", "t0", "", "ALLOW", "HOLD"):
        with pytest.raises(psycopg.errors.CheckViolation):
            assess(admin, rid, bad)
    for tier in TIERS:  # control: every tier the rules can return (app/risk/rules.py)
        other = add_credit(admin, 49, 2, tier=None)
        assess(admin, other, tier)


def test_asi02_human_only_order_refused_even_with_two_approvals(admin, as_role, ex):
    rid, write = _order(admin, "HUMAN_ONLY")
    approve_all(as_role("approver"), rid, [ANNA, PETROS])
    with pytest.raises(psycopg.errors.RaiseException, match="HUMAN_ONLY"):
        write(ex)
    assert orders(admin) == 0
    # Control: the same approvals on a T2 request (the strictest tier that allows an order).
    rid, write = _order(admin, "T2")
    approve_all(as_role("approver"), rid, [ANNA, PETROS])
    write(ex)
    assert orders(admin) == 1


def test_asi02_credit_waits_for_its_approvals(admin, as_role, ex):
    rid, write = _credit(admin, "T1")
    with pytest.raises(psycopg.errors.RaiseException, match="needs 1 distinct approval"):
        write(ex)
    assert credits_count(admin) == 0
    approve_as(as_role("approver"), rid, ANNA)
    write(ex)
    assert credits_count(admin) == 1


@pytest.mark.parametrize("kind", EFFECTS)
@pytest.mark.parametrize("case", FLOOR_CASES)
def test_asi03_floor_counts_distinct_approvers_and_roles(admin, as_role, ex, kind, case):
    tier, approvals, allowed = FLOOR_CASES[case]
    if allowed is None:  # T0 with no approval: a credit goes through, an order does not
        allowed = kind == "credit"
    rid, write = EFFECTS[kind](admin, tier)
    approve_all(as_role("approver"), rid, approvals)
    if allowed:
        write(ex)
        assert written(admin) == 1
    else:
        with pytest.raises(psycopg.errors.RaiseException, match="approval"):
            write(ex)
        assert written(admin) == 0


# --- who may write and read assessments ---

def _assessment_insert(table, rid, extra=None):
    """The INSERT the risk engine makes into `table`, plus one (column, value) when given."""
    if table == "risk_assessments":
        columns, values = ["request_id", "tier", "score", "reasons", "engine_version"], [rid, "T0", 0, [], "rules-1"]
    else:
        columns, values = ["lease_hash", "tool", "decision", "reasons"], [bytes(32), "read_ticket", "allow", []]
    if extra:
        columns, values = columns + [extra[0]], values + [extra[1]]
    return f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({', '.join(['%s'] * len(values))})", values


ASSESSMENT_TABLES = ["risk_assessments", "call_assessments"]


@pytest.mark.parametrize("table", ASSESSMENT_TABLES)
def test_only_risk_engine_inserts_assessments(admin, as_role, table):
    rid = add_credit(admin, 49, 2, tier=None)
    statement, values = _assessment_insert(table, rid)
    allowed = []
    for role in _login_roles(admin, exclude=("risk_engine",)):
        try:
            as_role(role).execute(statement, values)
        except psycopg.errors.InsufficientPrivilege:
            continue
        allowed.append(role)
    assert allowed == []
    assert admin.execute(f"SELECT count(*) AS n FROM {table}").fetchone()["n"] == 0
    # Control: the risk engine can, and the database records who and when.
    as_role("risk_engine").execute(statement, values)
    row = admin.execute(f"SELECT actor, created_at > now() - interval '1 minute' AS fresh FROM {table}").fetchone()
    assert row == {"actor": "risk_engine", "fresh": True}


# --- agent_control: the stop switch ---

def control(admin):
    return admin.execute("SELECT paused, reason FROM agent_control").fetchall()


def test_asi10_risk_engine_pauses_and_approver_resumes(admin, as_role):
    as_role("risk_engine").execute("SELECT pause_agents('repeated_denials')")
    assert control(admin) == [{"paused": True, "reason": "repeated_denials"}]
    as_role("approver").execute("SELECT resume_agents(%s::uuid)", (BOB_DEV,))
    assert control(admin) == [{"paused": False, "reason": ""}]
    events = admin.execute("SELECT kind, actor, detail FROM events ORDER BY id").fetchall()
    assert events == [
        {"kind": "agents_paused", "actor": "risk_engine", "detail": "repeated_denials"},
        {"kind": "agents_resumed", "actor": "approver", "detail": BOB_DEV},
    ]
