"""The protection flags and who may change them (db/sql/07-register.sql).

A flag says "someone in this home depends on electricity" (life-support equipment). It is the one
thing that must never be lost: no flag and a fresh register means the home can be disconnected.

  staff           REMOVE a flag only by request plus two distinct SeniorApprover approvals; the
                  second approval deletes the flag and raises an ALERT.
  anyone else     nothing. Only the removal function's owner holds DELETE on flags, and a trigger
                  refuses any other DELETE or UPDATE even with a grant added by mistake.
"""

import threading
import time

import psycopg
import pytest


# Staff are named by their Entra object id (a UUID), so one person has one spelling.
SENIOR_A = "0f8a3c1e-2b4d-4e6f-8a1b-3c5d7e9f0a11"
SENIOR_B = "1a2b3c4d-5e6f-4a1b-9c2d-3e4f5a6b7c22"
SENIOR_C = "2b3c4d5e-6f7a-4b2c-8d3e-4f5a6b7c8d33"
REQUESTER = "3c4d5e6f-7a8b-4c3d-9e4f-5a6b7c8d9e44"
REASON = "register says the equipment was returned"


def flags(admin):
    return {r["supply_point_id"]: r["source"] for r in admin.execute("SELECT supply_point_id, source FROM flags")}


def alerts(admin):
    return admin.execute("SELECT actor, detail FROM events WHERE kind = 'ALERT' ORDER BY id").fetchall()


def login_roles(admin, exclude=()):
    rows = admin.execute("SELECT rolname FROM pg_roles WHERE rolcanlogin AND NOT rolsuper ORDER BY rolname")
    return [r["rolname"] for r in rows if r["rolname"] not in exclude]


@pytest.fixture
def staff(as_role):
    return as_role("approver")


def request_removal(staff, sp="SP-1003", reason=REASON, by=REQUESTER):
    return staff.execute("SELECT request_flag_removal(%s, %s, %s) AS id", (sp, reason, by)).fetchone()["id"]


def approve_removal(staff, request_id, who):
    return staff.execute("SELECT approve_flag_removal(%s, %s) AS done", (request_id, who)).fetchone()["done"]


@pytest.mark.parametrize("statement", ["DELETE FROM flags", "UPDATE flags SET supply_point_id = 'SP-1002'",
                                       "UPDATE flags SET source = 'x'"])
def test_even_the_superuser_cannot_delete_or_move_a_flag_directly(admin, statement):
    # Moving a flag to another home is a removal for the first home; changing its source rewrites
    # where it came from. Only approve_flag_removal deletes.
    with pytest.raises(psycopg.errors.RaiseException, match="flags"):
        admin.execute(statement)
    assert flags(admin) == {"SP-1003": "state_register"}


def test_nobody_but_the_removal_function_owner_holds_delete_on_flags(admin):
    rows = admin.execute(
        "SELECT rolname FROM pg_roles WHERE NOT rolsuper AND rolname !~ '^pg_' "
        "AND has_table_privilege(oid, 'flags', 'DELETE') ORDER BY 1"
    ).fetchall()
    assert [r["rolname"] for r in rows] == ["flags_remover"]
    rows = admin.execute(
        "SELECT rolname FROM pg_roles WHERE NOT rolsuper AND rolname !~ '^pg_' "
        "AND (has_table_privilege(oid, 'flags', 'UPDATE') OR has_table_privilege(oid, 'flags', 'TRUNCATE'))"
    ).fetchall()
    assert rows == []


def test_request_flag_removal_takes_the_home_lock(admin, staff):
    # Every writer of a home's flag takes this lock; so must the request for its removal, or a
    # request could be filed in the middle of a removal or of a flag being added back, and its
    # time would not tell whether it was raised against the flag that is there now.
    staff.execute("SET lock_timeout = '300ms'")
    admin.execute("SELECT pg_advisory_lock(hashtext('SP-1003'))")
    try:
        with pytest.raises(psycopg.errors.LockNotAvailable):
            request_removal(staff)
    finally:
        admin.execute("SELECT pg_advisory_unlock_all()")
    assert admin.execute("SELECT count(*) AS n FROM flag_removal_requests").fetchone()["n"] == 0
    request_removal(staff)  # control: lock free
    assert admin.execute("SELECT count(*) AS n FROM flag_removal_requests").fetchone()["n"] == 1


def test_a_request_for_another_home_does_not_wait_for_the_lock(admin, staff):
    admin.execute("INSERT INTO flags (supply_point_id, source) VALUES ('SP-1001', 'state_register')")
    staff.execute("SET lock_timeout = '300ms'")
    admin.execute("SELECT pg_advisory_lock(hashtext('SP-1003'))")
    try:
        request_removal(staff, sp="SP-1001")
    finally:
        admin.execute("SELECT pg_advisory_unlock_all()")


def test_flag_removal_needs_two_distinct_seniors_and_alerts(admin, staff):
    rid = request_removal(staff)
    assert approve_removal(staff, rid, SENIOR_A) is False
    assert flags(admin) == {"SP-1003": "state_register"}
    # The same person again, spelled another way: still one person.
    for same in (SENIOR_A.upper(), "{" + SENIOR_A + "}", SENIOR_A.replace("-", "")):
        assert approve_removal(staff, rid, same) is False
    assert flags(admin) == {"SP-1003": "state_register"} and alerts(admin) == []
    assert approve_removal(staff, rid, SENIOR_B) is True
    assert flags(admin) == {}
    # The alert comes from the function's owner: an approver can write events, but not as that actor.
    assert alerts(admin) == [{"actor": "flags_remover",
                              "detail": f"protection flag removed supply_point=SP-1003 request={rid}"}]
    approvals = admin.execute(
        "SELECT approver::text AS approver, approver_role FROM flag_removal_approvals WHERE request_id = %s "
        "ORDER BY 1", (rid,)
    ).fetchall()
    assert approvals == [{"approver": SENIOR_A, "approver_role": "SeniorApprover"},
                         {"approver": SENIOR_B, "approver_role": "SeniorApprover"}]
    # A finished request is closed: a third approval cannot remove a flag the register adds back.
    admin.execute("INSERT INTO flags (supply_point_id, source) VALUES ('SP-1003', 'state_register')")
    with pytest.raises(psycopg.errors.RaiseException, match="closed"):
        approve_removal(staff, rid, SENIOR_C)
    assert flags(admin) == {"SP-1003": "state_register"}


def test_each_removal_request_needs_its_own_two_seniors(admin, staff):
    first = request_removal(staff)
    approve_removal(staff, first, SENIOR_A)
    second = request_removal(staff, reason="second request")
    assert approve_removal(staff, second, SENIOR_B) is False  # one on each request is not two
    assert flags(admin) == {"SP-1003": "state_register"}


def test_flag_removal_request_needs_a_flag_a_reason_and_a_requester(admin, staff):
    for sp, reason, by, message in (
        ("SP-1001", REASON, REQUESTER, "no protection flag"),
        ("SP-9999", REASON, REQUESTER, "no protection flag"),
        ("SP-1003", "  ", REQUESTER, "reason"),
        ("SP-1003", None, REQUESTER, "reason"),
        ("SP-1003", "x" * 501, REQUESTER, "reason"),
        ("SP-1003", REASON, " ", "requester"),
        ("SP-1003", REASON, None, "requester"),
        ("SP-1003", REASON, "staff.ioanna", "requester"),  # not an Entra object id
    ):
        with pytest.raises(psycopg.errors.RaiseException, match=message):
            request_removal(staff, sp, reason, by)
    assert admin.execute("SELECT count(*) AS n FROM flag_removal_requests").fetchone()["n"] == 0


def test_flag_removal_approval_refuses_unknown_requests_and_blank_approvers(admin, staff):
    with pytest.raises(psycopg.errors.RaiseException, match="unknown"):
        approve_removal(staff, 999, SENIOR_A)
    rid = request_removal(staff)
    # Blank, a name, or a UUID with a no-break space or a Cyrillic "a" in it: none is an object id,
    # so none can pass for a second person.
    for who in ("", " \t", None, "senior.anna", SENIOR_A + "\u00a0", SENIOR_A.replace("a", "\u0430", 1)):
        with pytest.raises(psycopg.errors.RaiseException, match="approver"):
            approve_removal(staff, rid, who)
    assert flags(admin) == {"SP-1003": "state_register"}
    assert admin.execute("SELECT count(*) AS n FROM flag_removal_approvals").fetchone()["n"] == 0


def test_the_requester_cannot_approve_their_own_removal(admin, staff):
    rid = request_removal(staff)
    for same in (REQUESTER, REQUESTER.upper()):
        with pytest.raises(psycopg.errors.RaiseException, match="requester"):
            approve_removal(staff, rid, same)
    assert approve_removal(staff, rid, SENIOR_A) is False
    with pytest.raises(psycopg.errors.RaiseException, match="requester"):
        approve_removal(staff, rid, REQUESTER)
    assert flags(admin) == {"SP-1003": "state_register"}
    assert approve_removal(staff, rid, SENIOR_B) is True  # control: two other people


def closed(admin, rid):
    row = admin.execute(
        "SELECT done_at IS NOT NULL AS done, closed_reason FROM flag_removal_requests WHERE id = %s", (rid,)
    ).fetchone()
    return row["done"], row["closed_reason"]


def test_a_stale_removal_request_cannot_remove_a_flag_added_later(admin, staff):
    # Two requests for the same home. The first removes the flag, the flag is added back, and
    # the second must not remove the new flag: it was raised against the old one.
    first, second = request_removal(staff), request_removal(staff, reason="second request")
    approve_removal(staff, first, SENIOR_A)
    assert approve_removal(staff, first, SENIOR_B) is True
    admin.execute("INSERT INTO flags (supply_point_id, source) VALUES ('SP-1003', 'state_register')")
    for who in (SENIOR_A, SENIOR_B):
        with pytest.raises(psycopg.errors.RaiseException, match="closed"):
            approve_removal(staff, second, who)
    assert flags(admin) == {"SP-1003": "state_register"}
    assert len(alerts(admin)) == 1


def test_a_removal_closes_every_other_open_request_for_the_home(admin, staff):
    first, second = request_removal(staff), request_removal(staff, reason="second request")
    approve_removal(staff, first, SENIOR_A)
    approve_removal(staff, first, SENIOR_B)
    assert closed(admin, first) == (True, "removed") and closed(admin, second) == (True, "superseded")


def replace_flag_behind_the_functions(admin, sp="SP-1003"):
    """A flag deleted and added again without the removal functions (only the superuser can, with
    the triggers off), so an open request now points at a newer flag than the one it was raised on."""
    with admin.transaction():
        admin.execute("SET LOCAL session_replication_role = replica")
        admin.execute("DELETE FROM flags WHERE supply_point_id = %s", (sp,))
        admin.execute(
            "INSERT INTO flags (supply_point_id, source, created_at) "
            "VALUES (%s, 'state_register', now() + interval '1 second')", (sp,)
        )


def test_a_request_whose_flag_was_replaced_is_closed_without_removing_the_new_flag(admin, staff):
    rid = request_removal(staff)
    replace_flag_behind_the_functions(admin)
    assert approve_removal(staff, rid, SENIOR_A) is False
    assert closed(admin, rid) == (True, "stale")
    with pytest.raises(psycopg.errors.RaiseException, match="closed"):
        approve_removal(staff, rid, SENIOR_B)
    assert flags(admin) == {"SP-1003": "state_register"} and alerts(admin) == []
    assert admin.execute("SELECT count(*) AS n FROM flag_removal_approvals").fetchone()["n"] == 0
    events = admin.execute("SELECT kind, detail FROM events WHERE kind = 'flag_removal_closed'").fetchall()
    assert events == [{"kind": "flag_removal_closed", "detail": f"request={rid} supply_point=SP-1003 reason=stale"}]


@pytest.mark.parametrize("table", ["flags", "register_sync", "flag_removal_requests", "flag_removal_approvals"])
def test_register_tables_cannot_be_truncated_even_by_the_superuser(admin, table):
    with pytest.raises(psycopg.errors.RaiseException, match="truncate"):
        admin.execute(f"TRUNCATE {table} CASCADE")
    assert flags(admin) == {"SP-1003": "state_register"}


def test_flag_removal_request_is_logged_without_the_reason(admin, staff):
    rid = request_removal(staff, reason="oxygen concentrator returned")
    events = admin.execute("SELECT kind, actor, detail FROM events ORDER BY id").fetchall()
    assert events == [{"kind": "flag_removal_requested", "actor": "flags_remover",
                       "detail": f"request={rid} supply_point=SP-1003"}]


def test_two_seniors_approving_at_the_same_moment_still_remove_the_flag(admin, as_role):
    # Without a row lock, each would count only its own approval and neither would delete.
    first, second = as_role("approver"), as_role("approver")
    rid = request_removal(first)
    result = {}
    with first.transaction():
        result["first"] = approve_removal(first, rid, SENIOR_A)
        worker = threading.Thread(target=lambda: result.__setitem__("second", approve_removal(second, rid, SENIOR_B)))
        worker.start()
        time.sleep(0.5)  # the second approval waits for the first transaction
        assert "second" not in result
    worker.join(10)
    assert result == {"first": False, "second": True}
    assert flags(admin) == {}


REMOVAL_CALLS = {
    "request": f"SELECT request_flag_removal('SP-1003', 'r', '{REQUESTER}')",
    "approve": f"SELECT approve_flag_removal(1, '{SENIOR_A}')",
}


@pytest.mark.parametrize("call", REMOVAL_CALLS)
def test_only_the_approver_role_can_remove_flags(admin, as_role, staff, call):
    request_removal(staff)  # request 1 exists
    allowed = []
    for role in login_roles(admin, exclude=("approver",)):
        try:
            as_role(role).execute(REMOVAL_CALLS[call])
        except psycopg.errors.InsufficientPrivilege:
            continue
        allowed.append(role)
    assert allowed == []
    assert flags(admin) == {"SP-1003": "state_register"}


REGISTER_FUNCTIONS = {
    # signature: (owner, callers)
    "request_flag_removal(text,text,text)": ("flags_remover", {"approver"}),
    "approve_flag_removal(integer,text)": ("flags_remover", {"approver"}),
}


@pytest.mark.parametrize("signature", REGISTER_FUNCTIONS)
def test_register_functions_are_definers_with_a_fixed_search_path_and_named_callers(admin, signature):
    row = admin.execute(
        "SELECT p.prosecdef, p.proconfig, pg_get_userbyid(p.proowner) AS owner, "
        "ARRAY(SELECT r.rolname FROM pg_roles r "
        "      WHERE r.rolname !~ '^pg_' AND r.rolname <> pg_get_userbyid(p.proowner) "
        "        AND NOT r.rolsuper AND has_function_privilege(r.oid, p.oid, 'EXECUTE')) AS callers "
        "FROM pg_proc p WHERE p.oid = %s::regprocedure",
        (signature,),
    ).fetchone()
    owner, callers = REGISTER_FUNCTIONS[signature]
    assert row["prosecdef"] is True
    assert row["proconfig"] == ["search_path=public, pg_temp"]
    assert row["owner"] == owner
    assert set(row["callers"]) == callers


@pytest.mark.parametrize(
    "signature, call",
    [
        ("request_flag_removal(text,text,text)", f"request_flag_removal('SP-1003', 'r', '{REQUESTER}')"),
        ("approve_flag_removal(integer,text)", f"approve_flag_removal(1, '{SENIOR_A}')"),
    ],
)
def test_register_functions_check_the_caller_not_only_the_grant(admin, signature, call):
    with admin.transaction(force_rollback=True):
        admin.execute(f"GRANT EXECUTE ON FUNCTION {signature} TO gateway")
        admin.execute("SET SESSION AUTHORIZATION gateway")
        with pytest.raises(psycopg.errors.RaiseException, match="may not"):
            with admin.transaction():
                admin.execute(f"SELECT {call}")
        admin.execute("RESET SESSION AUTHORIZATION")


def test_the_removing_owner_can_delete_but_not_add(admin):
    row = admin.execute(
        "SELECT has_any_column_privilege('flags_remover', 'flags', 'INSERT') AS ins, "
        "has_table_privilege('flags_remover', 'flags', 'DELETE') AS del"
    ).fetchone()
    assert row == {"ins": False, "del": True}


@pytest.mark.parametrize("table", ["flags", "register_sync", "flag_removal_requests", "flag_removal_approvals"])
def test_rls_is_forced_on_the_register_tables(admin, table):
    row = admin.execute(
        "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = %s AND relkind = 'r'", (table,)
    ).fetchone()
    assert row == {"relrowsecurity": True, "relforcerowsecurity": True}
