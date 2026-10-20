"""Approvals and resuming the agents only for known staff (db/sql/06-risk.sql, 09-dev-staff.sql).

The console role cannot write an approval or the staff list. It can only call approve_request and
resume_agents, and those refuse an object id that is not on the list, is inactive, or lacks the
role the action needs. So a compromised console or a leaked approver password cannot invent two
approvers to satisfy the two-person rule, or resume the agents.
"""

import uuid

import psycopg
import pytest

from tests.conftest import ANNA_DEV, BOB_DEV, CAROL_DEV, assess

LISTED = "not on the staff list"


def credit_request(admin, tier="T2") -> int:
    rid = admin.execute(
        "INSERT INTO action_requests (kind, ticket_id, account_id, amount_eur, reason, evidence_ref) "
        "VALUES ('credit', 1, 1, 60, 'duplicate_charge', 2) RETURNING id"
    ).fetchone()["id"]
    assess(admin, rid, tier)
    return rid


def approvals(admin, rid):
    return admin.execute(
        "SELECT approver::text AS approver, approver_role FROM approvals WHERE request_id = %s ORDER BY approver",
        (rid,),
    ).fetchall()


def approve(conn, rid, oid):
    conn.execute("SELECT approve_request(%s, %s::uuid)", (rid, oid))


def paused(admin) -> bool:
    return admin.execute("SELECT paused FROM agent_control").fetchone()["paused"]


# --- approve_request ---

def test_invented_uuid_is_refused(admin, as_role):
    rid = credit_request(admin)
    with pytest.raises(psycopg.errors.RaiseException, match=LISTED):
        approve(as_role("approver"), rid, str(uuid.uuid4()))
    assert approvals(admin, rid) == []


def test_two_invented_uuids_cannot_satisfy_the_two_person_rule(admin, as_role):
    rid = credit_request(admin, "T2")
    staff = as_role("approver")
    for _ in range(2):
        with pytest.raises(psycopg.errors.RaiseException, match=LISTED):
            approve(staff, rid, str(uuid.uuid4()))
    assert approvals(admin, rid) == []


def test_known_approver_is_accepted_with_the_listed_role(admin, as_role):
    rid = credit_request(admin)
    staff = as_role("approver")
    approve(staff, rid, ANNA_DEV)
    approve(staff, rid, BOB_DEV)
    assert approvals(admin, rid) == [
        {"approver": ANNA_DEV, "approver_role": "Approver"},
        {"approver": BOB_DEV, "approver_role": "SeniorApprover"},
    ]


def test_inactive_staff_is_refused(admin, as_role):
    rid = credit_request(admin)
    admin.execute("UPDATE staff SET active = false WHERE oid = %s", (ANNA_DEV,))
    with pytest.raises(psycopg.errors.RaiseException, match=LISTED):
        approve(as_role("approver"), rid, ANNA_DEV)
    assert approvals(admin, rid) == []


def test_the_same_person_cannot_approve_twice(admin, as_role):
    rid = credit_request(admin)
    staff = as_role("approver")
    approve(staff, rid, ANNA_DEV)
    with pytest.raises(psycopg.errors.UniqueViolation):
        approve(staff, rid, ANNA_DEV)


def test_a_request_that_is_no_longer_pending_cannot_be_approved(admin, as_role):
    rid = credit_request(admin)
    admin.execute("UPDATE action_requests SET status = 'refused' WHERE id = %s", (rid,))
    with pytest.raises(psycopg.errors.RaiseException, match="not pending"):
        approve(as_role("approver"), rid, ANNA_DEV)


# --- resume_agents ---

def test_approver_without_senior_role_cannot_resume(admin, as_role):
    admin.execute("UPDATE agent_control SET paused = true WHERE id = 1")
    with pytest.raises(psycopg.errors.RaiseException, match="SeniorApprover"):
        as_role("approver").execute("SELECT resume_agents(%s::uuid)", (ANNA_DEV,))
    assert paused(admin)


@pytest.mark.parametrize("who", ["invented", "inactive"])
def test_unknown_or_inactive_senior_cannot_resume(admin, as_role, who):
    admin.execute("UPDATE agent_control SET paused = true WHERE id = 1")
    oid = str(uuid.uuid4()) if who == "invented" else CAROL_DEV
    if who == "inactive":
        admin.execute("UPDATE staff SET active = false WHERE oid = %s", (oid,))
    with pytest.raises(psycopg.errors.RaiseException, match="SeniorApprover"):
        as_role("approver").execute("SELECT resume_agents(%s::uuid)", (oid,))
    assert paused(admin)


def test_known_senior_approver_resumes_and_the_event_names_them(admin, as_role):
    admin.execute("UPDATE agent_control SET paused = true WHERE id = 1")
    as_role("approver").execute("SELECT resume_agents(%s::uuid)", (CAROL_DEV,))
    assert not paused(admin)
    event = admin.execute("SELECT actor, detail FROM events WHERE kind = 'agents_resumed'").fetchone()
    assert event == {"actor": "approver", "detail": CAROL_DEV}


# --- the walls around the list and the approvals ---

TABLE_PRIVILEGES = ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")


def login_roles(admin):
    return [r["rolname"] for r in admin.execute(
        "SELECT rolname FROM pg_roles WHERE rolcanlogin AND rolname <> 'postgres' ORDER BY rolname").fetchall()]


def test_approver_role_cannot_insert_approvals_directly(admin, as_role):
    rid = credit_request(admin)
    assert not admin.execute("SELECT has_table_privilege('approver', 'approvals', 'INSERT') AS ok").fetchone()["ok"]
    for column in ("request_id", "approver", "approver_role", "created_at"):
        assert not admin.execute(
            "SELECT has_column_privilege('approver', 'approvals', %s, 'INSERT') AS ok", (column,)).fetchone()["ok"], column
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        as_role("approver").execute(
            "INSERT INTO approvals (request_id, approver, approver_role) VALUES (%s, %s, 'SeniorApprover')",
            (rid, str(uuid.uuid4())))


def test_no_login_role_has_any_privilege_on_the_staff_list(admin):
    for role in login_roles(admin):
        for privilege in TABLE_PRIVILEGES:
            assert not admin.execute(
                "SELECT has_table_privilege(%s, 'staff', %s) AS ok", (role, privilege)).fetchone()["ok"], (role, privilege)
        for privilege in ("SELECT", "INSERT", "UPDATE", "REFERENCES"):
            for column in ("oid", "display_name", "roles", "active"):
                assert not admin.execute(
                    "SELECT has_column_privilege(%s, 'staff', %s, %s) AS ok",
                    (role, column, privilege)).fetchone()["ok"], (role, column, privilege)


def test_console_role_cannot_write_or_read_the_staff_list(as_role):
    staff = as_role("approver")
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        staff.execute("INSERT INTO staff (oid, display_name, roles) VALUES (%s, 'Mallory', '{SeniorApprover}')",
                      (str(uuid.uuid4()),))
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        staff.execute("UPDATE staff SET active = true")
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        staff.execute("SELECT oid FROM staff")


def test_staff_list_is_owned_by_a_role_nobody_logs_in_as(admin):
    owner = admin.execute(
        "SELECT r.rolname, r.rolcanlogin, r.rolsuper FROM pg_class c JOIN pg_roles r ON r.oid = c.relowner "
        "WHERE c.oid = 'public.staff'::regclass").fetchone()
    assert owner == {"rolname": "staff_owner", "rolcanlogin": False, "rolsuper": False}


def test_only_the_approver_role_may_run_the_staff_functions(admin):
    for signature in ("approve_request(int, uuid)", "resume_agents(uuid)"):
        for role in login_roles(admin):
            ok = admin.execute("SELECT has_function_privilege(%s, %s, 'EXECUTE') AS ok", (role, signature)).fetchone()["ok"]
            assert ok == (role == "approver"), (signature, role)


def test_staff_functions_are_security_definer_with_a_pinned_search_path(admin):
    rows = admin.execute(
        "SELECT proname, prosecdef, proconfig FROM pg_proc "
        "WHERE proname IN ('approve_request', 'resume_agents') AND pronamespace = 'public'::regnamespace").fetchall()
    assert {r["proname"] for r in rows} == {"approve_request", "resume_agents"}
    for row in rows:
        assert row["prosecdef"], row["proname"]
        assert row["proconfig"] == ["search_path=pg_catalog, pg_temp"], row["proname"]


def test_roles_on_the_list_are_a_closed_set(admin):
    for bad in ("{Admin}", "{}", "{Approver,Root}"):
        with pytest.raises(psycopg.errors.CheckViolation):
            admin.execute("INSERT INTO staff (oid, display_name, roles) VALUES (%s, 'x', %s::text[])",
                          (str(uuid.uuid4()), bad))


def test_the_local_staff_are_seeded(admin):
    rows = admin.execute("SELECT oid::text AS oid, roles, active FROM staff WHERE oid IN (%s, %s, %s) ORDER BY oid",
                         (ANNA_DEV, BOB_DEV, CAROL_DEV)).fetchall()
    assert rows == [
        {"oid": ANNA_DEV, "roles": ["Approver"], "active": True},
        {"oid": BOB_DEV, "roles": ["SeniorApprover"], "active": True},
        {"oid": CAROL_DEV, "roles": ["SeniorApprover"], "active": True},
    ]


def test_console_role_cannot_write_events(as_role):
    # resume_agents writes its own event; a console that could insert events could fake one.
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        as_role("approver").execute("INSERT INTO events (kind, detail) VALUES ('agents_resumed', 'forged')")
