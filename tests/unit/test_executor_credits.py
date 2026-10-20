

from app.executor.credits import process_credits
from tests.conftest import assess


def add_credit(admin, amount, evidence, reason="duplicate_charge", account_id=1, ticket_id=1, tier="T0") -> int:
    """A pending credit request with a risk assessment (T0 by default: no approval needed), so the
    tests here check the executor and check_credit, not the approval floor (tests/test_risk_floor.py).
    tier=None leaves it unassessed."""
    admin.execute(
        "INSERT INTO action_requests (kind, ticket_id, account_id, amount_eur, reason, evidence_ref) "
        "VALUES ('credit', %s, %s, %s, %s, %s)",
        (ticket_id, account_id, amount, reason, evidence),
    )
    rid = admin.execute("SELECT max(id) AS id FROM action_requests").fetchone()["id"]
    if tier is not None:
        assess(admin, rid, tier)
    return rid


def statuses(admin):
    return [r["status"] for r in admin.execute("SELECT status FROM action_requests ORDER BY id")]


def test_salami_on_same_evidence(admin, as_role, settings, now):  # ④
    for _ in range(20):
        add_credit(admin, 49, 2)
    process_credits(as_role("executor"), settings, now)
    assert statuses(admin) == ["executed"] + ["rejected"] * 19
    alerts = admin.execute("SELECT detail, actor FROM events WHERE kind = 'ALERT'").fetchall()
    assert alerts == [{"detail": "repeated rejected credits account=1", "actor": "executor"}]


def give_account_2_a_duplicate(admin):
    """Account 2 gets a real duplicate pair (10, 11). Test setup rather than seed: only this
    test needs it, and a seed change would need a rebuilt stack and show up in what the agent reads."""
    admin.execute("INSERT INTO charges VALUES (10, 2, '2026-08', 30.00), (11, 2, '2026-08', 30.00)")


def test_amount_above_evidence_is_rejected(admin, as_role, settings, now):
    add_credit(admin, 60, 2)
    process_credits(as_role("executor"), settings, now)
    assert statuses(admin) == ["rejected"]


def insert_credit(conn, request_id, account_id, amount, evidence=2):
    conn.execute(
        "INSERT INTO credits (request_id, account_id, amount_eur, evidence_ref) VALUES (%s, %s, %s::numeric, %s)",
        (request_id, account_id, str(amount), evidence),
    )


def credits_count(admin):
    return admin.execute("SELECT count(*) AS n FROM credits").fetchone()["n"]


# --- the charges must back the credit (final review F2) ---
# Each request below matches its credit row exactly (account, amount, evidence), so only the
# check against the charges table can refuse it. The executor would not get this far.

def _charges(admin, *rows):
    admin.execute(
        "INSERT INTO charges VALUES " + ", ".join(["(%s, %s, %s, %s)"] * len(rows)),
        [value for row in rows for value in row],
    )


def _matching(admin, amount, evidence):
    return add_credit(admin, amount, evidence), 1, amount, evidence


def _charge_on_another_account(admin):
    give_account_2_a_duplicate(admin)  # charges 10 and 11, account 2
    return _matching(admin, 30, 11)


def _same_amount_in_another_period(admin):
    _charges(admin, (20, 1, "2026-10", 49))  # 49.00 in 2026-07/08/09, but not in 2026-10
    return _matching(admin, 49, 20)


def _same_period_another_amount(admin):
    _charges(admin, (21, 1, "2026-07", 30))  # 2026-07 has two charges of 49.00, none of 30.00
    return _matching(admin, 30, 21)


def _twin_on_another_account(admin):
    _charges(admin, (22, 2, "2026-10", 25), (23, 1, "2026-10", 25))
    return _matching(admin, 25, 23)


def _above_the_hard_cap(admin):
    _charges(admin, (24, 1, "2026-10", 600), (25, 1, "2026-10", 600))
    return _matching(admin, 600, 25)


UNSUPPORTED_CREDITS = {
    "no such charge": (lambda admin: _matching(admin, 49, 999), "not a charge on account"),
    "charge on another account": (_charge_on_another_account, "not a charge on account"),
    "first of the pair": (lambda admin: _matching(admin, 49, 1), "not a duplicate"),
    "same amount, another period": (_same_amount_in_another_period, "not a duplicate"),
    "same period, another amount": (_same_period_another_amount, "not a duplicate"),
    "twin on another account": (_twin_on_another_account, "not a duplicate"),
    "more than the charge": (lambda admin: _matching(admin, 60, 2), "above charge"),
    "above the hard cap": (_above_the_hard_cap, "hard cap"),
}


# --- risk tiers: the executor acts only on assessed requests, and waits for the
# approvals the tier asks for. The database floor (tests/test_risk_floor.py) is the wall behind it.


def test_t1_credit_executes_after_one_approval(admin, as_role, settings, now):
    from tests.conftest import approve_as

    rid = add_credit(admin, 49, 2, tier="T1")
    ex = as_role("executor")
    process_credits(ex, settings, now)
    # Waits, quietly: still pending, nothing written, no trigger refusal.
    assert statuses(admin) == ["pending"] and credits_count(admin) == 0
    assert admin.execute("SELECT count(*) AS n FROM events").fetchone()["n"] == 0
    approve_as(as_role("approver"), rid, "eeab6c5e-f5bc-5d16-af4b-813d9b88be01")
    process_credits(ex, settings, now)
    assert statuses(admin) == ["executed"] and credits_count(admin) == 1


