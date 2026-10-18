"""The approval floor: risk assessments, approver roles and the effect triggers (db/sql/06-risk.sql,
check_credit and check_disconnection_order in db/sql/01-schema.sql).

A credit or a disconnection order is written only when its request has a risk assessment, the
assessment's tier allows the effect at all (required_approvals has a row for it), and enough
distinct staff approved it, SeniorApprovers where the tier asks for them. The database checks this
on the row itself, so a hijacked executor or console cannot skip the humans: the executor can
write rows, but not assessments; the console can write approvals, but cannot make one person count
twice.
"""

import psycopg
import pytest

from app.executor.credits import process_credits
from tests.conftest import approve_as, assess, open_lease
from tests.test_executor_credits import add_credit, credits_count, insert_credit
from tests.test_executor_moveouts import (
    add_moveout,
    insert_order,
    notice_73_hours_ago,
    orders,
    released_hold_notice_73_hours_ago,
)

TIERS = ["T0", "T1", "T2", "HUMAN_ONLY", "HOLD", "REJECT"]
ANNA, PETROS = "eeab6c5e-f5bc-5d16-af4b-813d9b88be01", "bbc480b8-6ddb-5ecf-8ce6-876023b4cbc3"


def _login_roles(admin, *, exclude=()):
    rows = admin.execute("SELECT rolname FROM pg_roles WHERE rolcanlogin ORDER BY rolname").fetchall()
    return [r["rolname"] for r in rows if r["rolname"] not in ("postgres", *exclude)]


# --- one effect of each kind, ready but for the floor ---
# Everything else the triggers check holds: a credit backed by duplicate charge 2, an order with a
# 73-hour-old notice to the right home and a move-out date of today. Only the assessment and the
# approvals decide.

def _credit(admin, tier):
    rid = add_credit(admin, 49, 2, tier=tier)
    return rid, lambda conn: insert_credit(conn, rid, 1, 49)


def _order(admin, tier):
    rid = add_moveout(admin, tier=tier)
    if tier == "HOLD":  # a held move-out gets its notice only once two seniors released it
        released_hold_notice_73_hours_ago(admin, rid)
    else:
        notice_73_hours_ago(admin, rid)
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
    """Each (approver, role) in turn. A duplicate is refused by the primary key; the floor must
    not count it either way, so the refusal is ignored here and the floor test checks the result."""
    for who, role in approvals:
        try:
            approve_as(staff, rid, who, role)
        except psycopg.errors.UniqueViolation:
            pass


# --- the floor ---

def test_credit_refused_without_assessment(admin, as_role, ex, settings, now):
    rid, write = _credit(admin, tier=None)
    with pytest.raises(psycopg.errors.RaiseException, match="no risk assessment"):
        write(ex)
    # The executor leaves an unassessed request alone (task A5), so the trigger is not even asked.
    process_credits(ex, settings, now)
    assert credits_count(admin) == 0
    status = admin.execute("SELECT status FROM action_requests WHERE id = %s", (rid,)).fetchone()["status"]
    assert status == "pending"
    assert admin.execute("SELECT count(*) AS n FROM events WHERE kind = 'executor_error'").fetchone()["n"] == 0
    # Control: the same request, once assessed T0, is credited.
    assess(admin, rid, "T0")
    write(ex)
    assert credits_count(admin) == 1


def test_order_refused_without_assessment(admin, as_role, ex):
    rid, write = _order(admin, tier=None)
    approve_as(as_role("approver"), rid, ANNA)  # the approval after the notice the order always needs
    with pytest.raises(psycopg.errors.RaiseException, match="no risk assessment"):
        write(ex)
    assert orders(admin) == 0
    assess(admin, rid, "T1")
    # The approval was given before the assessment, so it does not count (ruling a, A5).
    with pytest.raises(psycopg.errors.RaiseException, match="needs 1 distinct approval"):
        write(ex)
    approve_as(as_role("approver"), rid, PETROS)  # control: an approval after the assessment
    write(ex)
    assert orders(admin) == 1


def test_t1_credit_needs_one_approval(admin, as_role, ex):
    rid, write = _credit(admin, "T1")
    with pytest.raises(psycopg.errors.RaiseException, match="needs 1 distinct approval"):
        write(ex)
    assert credits_count(admin) == 0
    approve_as(as_role("approver"), rid, ANNA)
    write(ex)
    assert credits_count(admin) == 1


FLOOR_CASES = {
    # case: (tier, approvals, allowed)
    "T2, one person": ("T2", [(ANNA, "Approver")], False),
    "T2, the same person twice": ("T2", [(ANNA, "Approver"), (ANNA, "Approver")], False),
    "T2, the same person as Approver and as SeniorApprover": (
        "T2", [(ANNA, "Approver"), (ANNA, "SeniorApprover")], False),
    "T2, the same person in alternative UUID spelling": ("T2", [(ANNA, "Approver"), ("EEAB6C5EF5BC5D16AF4B813D9B88BE01", "Approver")], False),
    "T2, two people": ("T2", [(ANNA, "Approver"), (PETROS, "Approver")], True),
    "HOLD, two Approvers": ("HOLD", [(ANNA, "Approver"), (PETROS, "Approver")], False),
    "HOLD, a SeniorApprover and an Approver": ("HOLD", [(ANNA, "SeniorApprover"), (PETROS, "Approver")], False),
    "HOLD, one SeniorApprover twice": ("HOLD", [(ANNA, "SeniorApprover"), ("EEAB6C5EF5BC5D16AF4B813D9B88BE01", "SeniorApprover")], False),
    "HOLD, two SeniorApprovers": ("HOLD", [(ANNA, "SeniorApprover"), (PETROS, "SeniorApprover")], True),
    "T0, no approval (credit only; an order always needs one)": ("T0", [], None),
}


@pytest.mark.parametrize("kind", EFFECTS)
@pytest.mark.parametrize("case", FLOOR_CASES)
def test_floor_counts_distinct_approvers_and_roles(admin, as_role, ex, kind, case):
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


def test_order_approvals_count_only_after_the_notice(admin, as_role, ex):
    # The existing order rule, now for every approval the tier needs: T2 with two people, but
    # one of them approved before the occupier was told.
    rid, write = _order(admin, "T2")
    staff = as_role("approver")
    approve_as(staff, rid, ANNA)
    admin.execute(
        "UPDATE approvals SET created_at = now() - interval '80 hours' WHERE request_id = %s", (rid,)
    )
    approve_as(staff, rid, PETROS)
    with pytest.raises(psycopg.errors.RaiseException, match="needs 2 distinct approvals"):
        write(ex)
    assert orders(admin) == 0
    approve_as(staff, rid, "0adc7093-4b20-5a09-b9ef-682eef8811b2")  # control: a second approval after the notice
    write(ex)
    assert orders(admin) == 1


@pytest.mark.parametrize("kind", EFFECTS)
def test_approvals_count_only_after_the_assessment(admin, as_role, ex, kind):
    # An approval given before the request had a tier was given without knowing the risk. A console
    # that let staff approve early (or a hijacked one that approves everything in advance) must not
    # pre-pay the floor.
    rid, write = EFFECTS[kind](admin, None)
    staff = as_role("approver")
    approve_as(staff, rid, ANNA)
    approve_as(staff, rid, PETROS)
    assess(admin, rid, "T2")
    with pytest.raises(psycopg.errors.RaiseException, match="needs 2 distinct approvals"):
        write(ex)
    assert written(admin) == 0
    approve_as(staff, rid, "0adc7093-4b20-5a09-b9ef-682eef8811b2")
    with pytest.raises(psycopg.errors.RaiseException, match="has 1"):
        write(ex)
    approve_as(staff, rid, "aacecd35-e508-5dbb-814a-62b0b6762230")  # control: two people after the assessment
    write(ex)
    assert written(admin) == 1


EFFECT_UPDATES = {
    # An UPDATE never runs the insert-time checks, so it could move an approved effect to another
    # request, account, amount or home. Nobody has an UPDATE grant; the trigger is the wall behind it.
    "credits": ["UPDATE credits SET amount_eur = 500", "UPDATE credits SET request_id = request_id"],
    "disconnection_orders": ["UPDATE disconnection_orders SET supply_point_id = 'SP-1003'",
                             "UPDATE disconnection_orders SET request_id = request_id"],
}


def _one_effect_each(admin, as_role, ex):
    rid, write = _credit(admin, "T0")
    write(ex)
    rid, write = _order(admin, "T1")
    approve_as(as_role("approver"), rid, ANNA)
    write(ex)
    assert written(admin) == 2


@pytest.mark.parametrize("table", EFFECT_UPDATES)
def test_effect_rows_cannot_be_updated(admin, as_role, ex, table):
    _one_effect_each(admin, as_role, ex)
    allowed = []
    for role in _login_roles(admin):
        conn = ex if role == "executor" else as_role(role)  # executor: CONNECTION LIMIT 3
        for statement in EFFECT_UPDATES[table]:
            try:
                conn.execute(statement)
            except psycopg.errors.InsufficientPrivilege:
                continue
            allowed.append(f"{role}: {statement}")
    assert allowed == []
    for statement in EFFECT_UPDATES[table]:
        # A grant added by mistake, and the superuser: still refused.
        with admin.transaction(force_rollback=True):
            admin.execute(f"GRANT UPDATE ON {table} TO executor")
            admin.execute("SET SESSION AUTHORIZATION executor")
            with pytest.raises(psycopg.errors.RaiseException, match="cannot be changed"):
                with admin.transaction():
                    admin.execute(statement)
            admin.execute("RESET SESSION AUTHORIZATION")
        with pytest.raises(psycopg.errors.RaiseException, match="cannot be changed"):
            admin.execute(statement)
    rows = admin.execute(f"SELECT count(*) AS n FROM {table}").fetchone()["n"]
    assert rows == 1


def test_order_refused_for_human_only_even_with_two_seniors(admin, as_role, ex):
    rid, write = _order(admin, "HUMAN_ONLY")
    approve_all(as_role("approver"), rid, [(ANNA, "SeniorApprover"), (PETROS, "SeniorApprover")])
    with pytest.raises(psycopg.errors.RaiseException, match="HUMAN_ONLY"):
        write(ex)
    assert orders(admin) == 0
    # Control: the same approvals on a HOLD request (the strictest tier that allows an order).
    rid, write = _order(admin, "HOLD")
    approve_all(as_role("approver"), rid, [(ANNA, "SeniorApprover"), (PETROS, "SeniorApprover")])
    write(ex)
    assert orders(admin) == 1


@pytest.mark.parametrize("kind", EFFECTS)
@pytest.mark.parametrize("tier", ["HUMAN_ONLY", "REJECT"])
def test_no_effect_for_a_tier_no_approval_allows(admin, as_role, ex, kind, tier):
    rid, write = EFFECTS[kind](admin, tier)
    approve_all(as_role("approver"), rid, [(ANNA, "SeniorApprover"), (PETROS, "SeniorApprover"),
                                           ("0adc7093-4b20-5a09-b9ef-682eef8811b2", "SeniorApprover")])
    with pytest.raises(psycopg.errors.RaiseException, match=f"tier {tier}"):
        write(ex)
    assert written(admin) == 0


def test_required_approvals_per_tier(admin):
    expected = {"T0": (0, False), "T1": (1, False), "T2": (2, False), "HOLD": (2, True)}
    for tier in TIERS + ["t1", "T3", "", None]:
        rows = admin.execute("SELECT n, senior FROM required_approvals(%s)", (tier,)).fetchall()
        want = [dict(zip(("n", "senior"), expected[tier]))] if tier in expected else []
        assert rows == want, tier


def test_assessment_tier_is_on_the_closed_list(admin):
    rid = add_credit(admin, 49, 2, tier=None)
    for bad in ("T3", "t0", "", "ALLOW"):
        with pytest.raises(psycopg.errors.CheckViolation):
            assess(admin, rid, bad)
    for tier in TIERS:  # control: every tier the rules can return (app/risk/rules.py)
        other = add_credit(admin, 49, 2, tier=None)
        assess(admin, other, tier)


def test_one_assessment_per_request(admin, as_role):
    # An engine (or anyone holding its password) cannot replace a strict verdict with a lenient one.
    rid = add_credit(admin, 49, 2, tier="T2")
    engine = as_role("risk_engine")
    with pytest.raises(psycopg.errors.UniqueViolation):
        engine.execute(
            "INSERT INTO risk_assessments (request_id, tier, score, reasons, engine_version) "
            "VALUES (%s, 'T0', 0, '{}', 'rules-1')",
            (rid,),
        )


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


@pytest.mark.parametrize("table", ASSESSMENT_TABLES)
@pytest.mark.parametrize("column, value", [("actor", "approver"), ("created_at", "2000-01-01")])
def test_risk_engine_cannot_forge_who_or_when(admin, as_role, table, column, value):
    rid = add_credit(admin, 49, 2, tier=None)
    statement, values = _assessment_insert(table, rid, (column, value))
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        as_role("risk_engine").execute(statement, values)


APPEND_ONLY = {
    "risk_assessments": ["UPDATE risk_assessments SET tier = 'T0'", "DELETE FROM risk_assessments",
                         "TRUNCATE risk_assessments"],
    "call_assessments": ["UPDATE call_assessments SET decision = 'allow'", "DELETE FROM call_assessments",
                         "TRUNCATE call_assessments"],
}


def _one_of_each(admin):
    rid = add_credit(admin, 49, 2, tier="T2")
    admin.execute(
        "INSERT INTO call_assessments (lease_hash, tool, decision, reasons) "
        "VALUES (sha256('x'), 'issue_bill_credit', 'deny', ARRAY['one_effect_per_ticket'])"
    )
    return rid


@pytest.mark.parametrize("table", APPEND_ONLY)
def test_assessments_append_only(admin, as_role, table):
    _one_of_each(admin)
    allowed = []
    for role in _login_roles(admin):
        conn = as_role(role)
        for statement in APPEND_ONLY[table]:
            try:
                conn.execute(statement)
            except psycopg.errors.InsufficientPrivilege:
                continue
            allowed.append(f"{role}: {statement}")
    assert allowed == []
    # Behind the grants: an UPDATE or DELETE grant added by mistake, or the superuser, still
    # cannot change a row (TRUNCATE is left to the superuser, for the test suite's reset).
    for statement in APPEND_ONLY[table][:2]:
        with admin.transaction(force_rollback=True):
            admin.execute(f"GRANT UPDATE, DELETE ON {table} TO risk_engine")
            admin.execute("SET SESSION AUTHORIZATION risk_engine")
            with pytest.raises(psycopg.errors.RaiseException, match="append only"):
                with admin.transaction():
                    admin.execute(statement)
            admin.execute("RESET SESSION AUTHORIZATION")
        with pytest.raises(psycopg.errors.RaiseException, match="append only"):
            admin.execute(statement)
    assert admin.execute(f"SELECT count(*) AS n FROM {table}").fetchone()["n"] == 1


@pytest.mark.parametrize(
    "table, readers",
    [
        ("risk_assessments", {"executor", "approver", "risk_engine"}),
        ("call_assessments", {"risk_engine"}),
        ("agent_control", {"gateway", "risk_engine"}),
    ],
)
def test_who_reads_the_risk_tables(admin, as_role, table, readers):
    _one_of_each(admin)
    can_read = set()
    for role in _login_roles(admin):
        try:
            rows = as_role(role).execute(f"SELECT * FROM {table}").fetchall()
        except psycopg.errors.InsufficientPrivilege:
            continue
        assert rows, f"{role} may read {table} but sees no row"
        can_read.add(role)
    assert can_read == readers


RISK_TABLES = ["risk_assessments", "call_assessments", "agent_control"]


def test_rls_is_forced_on_the_risk_tables(admin):
    rows = admin.execute(
        "SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class "
        "WHERE relname = ANY(%s) AND relkind = 'r' ORDER BY relname",
        (RISK_TABLES,),
    ).fetchall()
    assert [(r["relname"], r["relrowsecurity"], r["relforcerowsecurity"]) for r in rows] == [
        (name, True, True) for name in sorted(RISK_TABLES)
    ]


@pytest.mark.parametrize("table", RISK_TABLES)
@pytest.mark.parametrize("role", ["tool_issue_bill_credit", "tool_request_disconnection", "executor"])
def test_rls_backstop_hides_risk_rows_from_tool_roles(admin, table, role):
    _one_of_each(admin)
    with admin.transaction(force_rollback=True):
        admin.execute(f"GRANT SELECT ON {table} TO {role}")
        admin.execute(f"SET LOCAL ROLE {role}")
        seen = admin.execute(f"SELECT count(*) AS n FROM {table}").fetchone()["n"]
        admin.execute("RESET ROLE")
    # The executor is the control: a role the policy names sees the rows.
    assert (seen > 0) is (role == "executor")


# --- agent_control: the stop switch ---

def control(admin):
    return admin.execute("SELECT paused, reason FROM agent_control").fetchall()


def test_agents_start_unpaused_and_there_is_one_switch(admin):
    assert control(admin) == [{"paused": False, "reason": ""}]
    with pytest.raises(psycopg.errors.CheckViolation):
        admin.execute("INSERT INTO agent_control (id, paused) VALUES (2, true)")


def test_risk_engine_pauses_and_approver_resumes(admin, as_role):
    as_role("risk_engine").execute("SELECT pause_agents('repeated_denials')")
    assert control(admin) == [{"paused": True, "reason": "repeated_denials"}]
    as_role("approver").execute("SELECT resume_agents()")
    assert control(admin) == [{"paused": False, "reason": ""}]
    events = admin.execute("SELECT kind, actor, detail FROM events ORDER BY id").fetchall()
    assert events == [
        {"kind": "agents_paused", "actor": "risk_engine", "detail": "repeated_denials"},
        {"kind": "agents_resumed", "actor": "approver", "detail": ""},
    ]


def test_only_risk_engine_pauses_and_only_approver_resumes(admin, as_role):
    allowed = []
    for role in _login_roles(admin):
        conn = as_role(role)
        for call, owner in (("SELECT pause_agents('x')", "risk_engine"), ("SELECT resume_agents()", "approver")):
            if role == owner:
                continue
            try:
                conn.execute(call)
            except psycopg.errors.InsufficientPrivilege:
                continue
            allowed.append(f"{role}: {call}")
        for statement in ("UPDATE agent_control SET paused = false", "DELETE FROM agent_control",
                          "INSERT INTO agent_control (id, paused) VALUES (1, false)"):
            try:
                conn.execute(statement)
            except psycopg.errors.InsufficientPrivilege:
                continue
            allowed.append(f"{role}: {statement}")
    assert allowed == []
    assert control(admin) == [{"paused": False, "reason": ""}]


@pytest.mark.parametrize(
    "function, intruder", [("pause_agents('x')", "gateway"), ("resume_agents()", "risk_engine")]
)
def test_pause_and_resume_check_the_caller_not_only_the_grant(admin, function, intruder):
    # A grant added by mistake: the function still refuses a session that is not its one caller.
    signature = "pause_agents(text)" if function.startswith("pause") else "resume_agents()"
    with admin.transaction(force_rollback=True):
        admin.execute(f"GRANT EXECUTE ON FUNCTION {signature} TO {intruder}")
        admin.execute(f"SET SESSION AUTHORIZATION {intruder}")
        with pytest.raises(psycopg.errors.RaiseException, match="may not"):
            with admin.transaction():
                admin.execute(f"SELECT {function}")
        admin.execute("RESET SESSION AUTHORIZATION")


RISK_FUNCTIONS = {
    # signature: (owner, security definer, callers)
    "pause_agents(text)": ("risk_owner", True, {"risk_engine"}),
    "resume_agents()": ("risk_owner", True, {"approver"}),
    "required_approvals(text)": ("risk_owner", False, {"executor", "approver", "risk_engine"}),
    "check_approval_floor(integer,timestamp with time zone)": ("risk_owner", False, {"executor"}),
}


@pytest.mark.parametrize("signature", RISK_FUNCTIONS)
def test_risk_functions_have_a_fixed_search_path_and_named_callers_only(admin, signature):
    owner, definer, callers = RISK_FUNCTIONS[signature]
    row = admin.execute(
        "SELECT p.prosecdef, p.proconfig, pg_get_userbyid(p.proowner) AS owner, "
        "ARRAY(SELECT r.rolname FROM pg_roles r "
        "      WHERE r.rolname !~ '^pg_' AND r.rolname <> pg_get_userbyid(p.proowner) "
        "        AND NOT r.rolsuper AND has_function_privilege(r.oid, p.oid, 'EXECUTE')) AS callers "
        "FROM pg_proc p WHERE p.oid = %s::regprocedure",
        (signature,),
    ).fetchone()
    assert row["prosecdef"] is definer
    assert row["proconfig"] == ["search_path=public, pg_temp"]
    assert row["owner"] == owner
    assert set(row["callers"]) == callers


# --- approver roles ---

def test_approver_role_is_on_the_closed_list_and_defaults_to_approver(admin, as_role):
    rid = add_credit(admin, 49, 2, tier="T1")
    staff = as_role("approver")
    with pytest.raises(psycopg.errors.CheckViolation):
        approve_as(staff, rid, ANNA, "Admin")
    for nobody in ("", "  ", "\t"):
        with pytest.raises(psycopg.errors.InvalidTextRepresentation):
            approve_as(staff, rid, nobody)
    staff.execute("INSERT INTO approvals (request_id, approver) VALUES (%s, %s)", (rid, PETROS))
    assert admin.execute("SELECT approver_role FROM approvals").fetchall() == [{"approver_role": "Approver"}]


# --- amounts: NaN and Infinity (carried in from the A3 review) ---
# numeric accepts 'NaN', and PostgreSQL sorts NaN above every number, so `amount > 0` alone lets it
# through; since PostgreSQL 14 numeric also takes 'Infinity'.

@pytest.mark.parametrize("amount", ["0", "-5", "NaN", "Infinity", "-Infinity"])
def test_credit_request_refuses_nan_and_infinity(admin, as_role, amount):
    lease = open_lease(admin, 1)
    with pytest.raises(psycopg.errors.RaiseException, match="positive finite number"):
        as_role("tool_issue_bill_credit").execute(
            "SELECT api_request_credit(%s, %s::numeric, 'duplicate_charge', 2)", (lease, amount)
        )
    assert admin.execute("SELECT count(*) AS n FROM action_requests").fetchone()["n"] == 0


def test_credit_request_accepts_a_normal_amount(admin, as_role):
    # Control for the test above.
    as_role("tool_issue_bill_credit").execute(
        "SELECT api_request_credit(%s, 49.00, 'duplicate_charge', 2)", (open_lease(admin, 1),)
    )
    assert admin.execute("SELECT amount_eur FROM action_requests").fetchone()["amount_eur"] == 49


def test_credit_trigger_refuses_nan(admin, as_role, ex):
    rid = add_credit(admin, 49, 2)
    with pytest.raises(psycopg.errors.RaiseException, match="positive finite number"):
        insert_credit(ex, rid, 1, "NaN")
    # Infinity cannot even be stored in numeric(10,2): the row is refused before the trigger.
    with pytest.raises(psycopg.errors.NumericValueOutOfRange):
        insert_credit(ex, rid, 1, "Infinity")
    assert credits_count(admin) == 0
