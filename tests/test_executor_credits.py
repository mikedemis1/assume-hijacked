import dataclasses

import psycopg
import pytest

from app.executor.credits import decide_credit, process_credits


def add_credit(admin, amount, evidence, reason="duplicate_charge", account_id=1, ticket_id=1) -> int:
    admin.execute(
        "INSERT INTO action_requests (kind, ticket_id, account_id, amount_eur, reason, evidence_ref) "
        "VALUES ('credit', %s, %s, %s, %s, %s)",
        (ticket_id, account_id, amount, reason, evidence),
    )
    return admin.execute("SELECT max(id) AS id FROM action_requests").fetchone()["id"]


def statuses(admin):
    return [r["status"] for r in admin.execute("SELECT status FROM action_requests ORDER BY id")]


def test_valid_duplicate_charge_is_credited(admin, as_role, settings, now):
    add_credit(admin, 49, 2)
    process_credits(as_role("executor"), settings, now)
    assert statuses(admin) == ["executed"]
    assert admin.execute("SELECT count(*) AS n FROM credits").fetchone()["n"] == 1


def test_salami_on_same_evidence(admin, as_role, settings, now):  # ④
    for _ in range(20):
        add_credit(admin, 49, 2)
    process_credits(as_role("executor"), settings, now)
    assert statuses(admin) == ["executed"] + ["rejected"] * 19
    alerts = admin.execute("SELECT detail, actor FROM events WHERE kind = 'ALERT'").fetchall()
    assert alerts == [{"detail": "repeated rejected credits account=1", "actor": "executor"}]


def test_monthly_cap_sends_the_rest_to_staff(admin, as_role, settings, now):  # ④
    for evidence in (2, 4, 6):
        add_credit(admin, 49, evidence)
    process_credits(as_role("executor"), settings, now)
    assert statuses(admin) == ["executed", "executed", "needs_staff"]


def test_evidence_that_is_not_a_duplicate_goes_to_staff(admin, as_role, settings, now):
    # Decision 4: no automatic evidence means a person looks at it, not an automatic no.
    add_credit(admin, 49, 1)  # first of the pair, not the duplicate
    add_credit(admin, 49, 7, account_id=2, ticket_id=2)  # account 2's own single charge
    add_credit(admin, 49, 999)  # no such charge
    process_credits(as_role("executor"), settings, now)
    assert statuses(admin) == ["needs_staff", "needs_staff", "needs_staff"]
    assert admin.execute("SELECT count(*) AS n FROM credits").fetchone()["n"] == 0


def give_account_2_a_duplicate(admin):
    """Account 2 gets a real duplicate pair (10, 11). Test setup rather than seed: only this
    test needs it, and a seed change would need a rebuilt stack and show up in what the agent reads."""
    admin.execute("INSERT INTO charges VALUES (10, 2, '2026-08', 30.00), (11, 2, '2026-08', 30.00)")


def test_evidence_from_another_account_is_not_accepted(admin, as_role, settings, now):  # gap I5
    give_account_2_a_duplicate(admin)
    mine = add_credit(admin, 30, 11)  # account 1 claims account 2's duplicate
    process_credits(as_role("executor"), settings, now)
    assert statuses(admin) == ["needs_staff"]
    reason = admin.execute("SELECT decision_reason FROM action_requests WHERE id = %s", (mine,)).fetchone()
    assert reason["decision_reason"] == "evidence not found for this account"
    assert admin.execute("SELECT count(*) AS n FROM credits").fetchone()["n"] == 0


def test_the_same_duplicate_is_credited_to_its_own_account(admin, as_role, settings, now):
    # Control for the test above: charge 11 is good evidence, for account 2.
    give_account_2_a_duplicate(admin)
    add_credit(admin, 30, 11, account_id=2, ticket_id=2)
    process_credits(as_role("executor"), settings, now)
    assert statuses(admin) == ["executed"]
    assert admin.execute("SELECT account_id FROM credits").fetchone()["account_id"] == 2


def test_amount_above_evidence_is_rejected(admin, as_role, settings, now):
    add_credit(admin, 60, 2)
    process_credits(as_role("executor"), settings, now)
    assert statuses(admin) == ["rejected"]


def test_above_automatic_limit_goes_to_staff(admin, as_role, settings, now):
    admin.execute("INSERT INTO charges VALUES (8, 1, '2026-10', 80.00), (9, 1, '2026-10', 80.00)")
    add_credit(admin, 80, 9)
    process_credits(as_role("executor"), settings, now)
    assert statuses(admin) == ["needs_staff"]


def test_reason_without_automatic_check_goes_to_staff(admin, as_role, settings, now):
    add_credit(admin, 10, 2, reason="outage")
    process_credits(as_role("executor"), settings, now)
    assert statuses(admin) == ["needs_staff"]


def test_global_daily_cap_holds_and_alerts(admin, as_role, settings, now):
    tight = dataclasses.replace(settings, credit_day_global_max_eur=60)
    add_credit(admin, 49, 2)
    add_credit(admin, 49, 4)
    process_credits(as_role("executor"), tight, now)
    assert statuses(admin) == ["executed", "held_global"]
    assert admin.execute("SELECT count(*) AS n FROM events WHERE kind = 'ALERT'").fetchone()["n"] == 1


def test_one_bad_credit_does_not_block_the_batch(admin, as_role, settings, now):
    first = add_credit(admin, 49, 2)
    add_credit(admin, 49, 4)
    # A corrupt credits row already holds the first request's id, under evidence 999, so the
    # first request's credit INSERT violates UNIQUE(request_id) and its transaction fails.
    # check_credit refuses such a row even from the superuser, so it is switched off for this
    # one insert (and back on before the commit). Evidence 2 is not marked as credited, so the
    # executor gets as far as the INSERT.
    with admin.transaction():
        admin.execute("ALTER TABLE credits DISABLE TRIGGER credits_check")
        admin.execute(
            "INSERT INTO credits (request_id, account_id, amount_eur, evidence_ref) VALUES (%s, 1, 49, 999)",
            (first,),
        )
        admin.execute("ALTER TABLE credits ENABLE TRIGGER credits_check")
    process_credits(as_role("executor"), settings, now)
    assert statuses(admin) == ["pending", "executed"]
    error = admin.execute("SELECT detail FROM events WHERE kind = 'executor_error'").fetchall()
    assert [e["detail"] for e in error] == [f"credit request={first}: UniqueViolation"]


@pytest.mark.parametrize("amount", [-49, 0])
def test_non_positive_amount_is_rejected(as_role, settings, amount, now):
    # The database refuses these rows (CHECK on action_requests); the executor refuses them too.
    req = {"id": 1, "account_id": 1, "amount_eur": amount, "reason": "duplicate_charge", "evidence_ref": 2}
    assert decide_credit(as_role("executor"), req, settings, now)[0] == "rejected"


def test_missing_amount_is_rejected(admin, as_role, settings, now):
    admin.execute(
        "INSERT INTO action_requests (kind, ticket_id, account_id, amount_eur, reason, evidence_ref) "
        "VALUES ('credit', 1, 1, NULL, 'duplicate_charge', 2)"
    )
    process_credits(as_role("executor"), settings, now)
    assert statuses(admin) == ["rejected"]
    assert admin.execute("SELECT count(*) AS n FROM events WHERE kind = 'executor_error'").fetchone()["n"] == 0


def test_negative_credit_cannot_make_room_under_the_monthly_cap(admin, as_role, settings, now):
    with pytest.raises(psycopg.errors.CheckViolation):
        add_credit(admin, -49, 2)  # refused by the database, even for the superuser
    add_credit(admin, 49, 4)
    add_credit(admin, 49, 6)
    process_credits(as_role("executor"), settings, now)
    assert statuses(admin) == ["executed", "executed"]
    total = admin.execute("SELECT sum(amount_eur) AS s FROM credits").fetchone()["s"]
    assert total == 98


def insert_credit(conn, request_id, account_id, amount, evidence=2):
    conn.execute(
        "INSERT INTO credits (request_id, account_id, amount_eur, evidence_ref) VALUES (%s, %s, %s::numeric, %s)",
        (request_id, account_id, str(amount), evidence),
    )


def credits_count(admin):
    return admin.execute("SELECT count(*) AS n FROM credits").fetchone()["n"]


def test_database_accepts_a_credit_that_matches_its_request(admin, as_role):
    # Control for the refusals below: each of them changes one thing in this row.
    rid = add_credit(admin, 49, 2)
    insert_credit(as_role("executor"), rid, 1, 49)
    assert credits_count(admin) == 1


def _move_out_request(admin):
    # Same account and amount as the credit row, so only the request kind is wrong.
    admin.execute(
        "INSERT INTO action_requests (kind, ticket_id, account_id, amount_eur, move_out_date) "
        "VALUES ('move_out', 1, 1, 49, current_date)"
    )
    return admin.execute("SELECT max(id) AS id FROM action_requests").fetchone()["id"]


BROKEN_CREDITS = {  # gap N2: as executor, a credits row used to accept anything
    "wrong amount": lambda admin: (add_credit(admin, 49, 2), 1, 60),
    "wrong account": lambda admin: (add_credit(admin, 49, 2), 2, 49),
    "another evidence": lambda admin: (add_credit(admin, 49, 2), 1, 49, 4),
    "move-out request": lambda admin: (_move_out_request(admin), 1, 49),
    "unknown request": lambda admin: (999, 1, 49),
    "zero": lambda admin: (add_credit(admin, 49, 2), 1, 0),
    "negative": lambda admin: (add_credit(admin, 49, 2), 1, -49),
    "NaN": lambda admin: (add_credit(admin, 49, 2), 1, "NaN"),
}


@pytest.mark.parametrize("case", BROKEN_CREDITS)
def test_database_refuses_a_credit_that_does_not_match_its_request(admin, as_role, case):
    with pytest.raises((psycopg.errors.RaiseException, psycopg.errors.CheckViolation)):
        insert_credit(as_role("executor"), *BROKEN_CREDITS[case](admin))
    assert credits_count(admin) == 0


@pytest.mark.parametrize("amount", ["0", "-49", "NaN"])
def test_credit_amount_must_be_positive_even_without_the_trigger(admin, amount):
    rid = add_credit(admin, 49, 2)
    # Always rolled back, so the trigger is enabled again afterwards whatever happens inside.
    with admin.transaction(force_rollback=True):
        admin.execute("ALTER TABLE credits DISABLE TRIGGER credits_check")
        with pytest.raises(psycopg.errors.CheckViolation):
            with admin.transaction():
                insert_credit(admin, rid, 1, amount)


def test_executor_cannot_choose_the_credit_time(admin, as_role):
    # A credit dated 2000-01-01 would fall outside the daily and monthly windows.
    rid = add_credit(admin, 49, 2)
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        as_role("executor").execute(
            "INSERT INTO credits (request_id, account_id, amount_eur, evidence_ref, created_at) "
            "VALUES (%s, 1, 49, 2, '2000-01-01')",
            (rid,),
        )


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


@pytest.mark.parametrize("case", UNSUPPORTED_CREDITS)
def test_database_refuses_a_credit_the_charges_do_not_back(admin, as_role, case):
    setup, reason = UNSUPPORTED_CREDITS[case]
    row = setup(admin)
    with pytest.raises(psycopg.errors.RaiseException, match=reason):
        insert_credit(as_role("executor"), *row)
    assert credits_count(admin) == 0


def test_database_accepts_a_credit_at_the_hard_cap(admin, as_role):
    # Control for "above the hard cap": 500.00 exactly is allowed.
    _charges(admin, (26, 1, "2026-10", 500), (27, 1, "2026-10", 500))
    insert_credit(as_role("executor"), *_matching(admin, 500, 27))
    assert credits_count(admin) == 1


def test_database_accepts_less_than_the_charge(admin, as_role):
    # Control for "more than the charge": part of a duplicate may be credited.
    insert_credit(as_role("executor"), *_matching(admin, 20, 2))
    assert credits_count(admin) == 1
