"""What the database says when it refuses something about a home.

A home id plus the words "protected" or "has a flag" is health data: it tells a reader that someone
in that home depends on electricity. A refusal is read by the executor and by staff, can land in
a log, and the server may log it too, so the text names requests and rules, never a home.
"""
import psycopg
import pytest

from tests.unit.test_executor_moveouts import insert_order, ready_for_order

HOMES = ("SP-1001", "SP-1002", "SP-1003", "SP-9999")


def refusal_text(call) -> str:
    with pytest.raises(psycopg.errors.RaiseException) as caught:
        call()
    return str(caught.value)


def test_an_order_at_a_protected_home_is_refused_without_naming_the_home(admin, as_role):
    rid = ready_for_order(admin, as_role("approver"), account_id=3, ticket_id=3)
    text = refusal_text(lambda: insert_order(as_role("executor"), rid, "SP-1003"))
    assert "protected" in text  # the reason is still given
    assert not any(home in text for home in HOMES), text
    assert "SP-" not in text


def test_an_order_for_another_home_is_refused_without_naming_either_home(admin, as_role):
    rid = ready_for_order(admin, as_role("approver"), account_id=1, ticket_id=1)
    text = refusal_text(lambda: insert_order(as_role("executor"), rid, "SP-1003"))
    assert str(rid) in text  # the request id is not a home
    assert "SP-" not in text, text


def test_an_order_for_a_request_that_is_not_pending_is_refused_without_naming_the_home(admin, as_role):
    rid = ready_for_order(admin, as_role("approver"), account_id=3, ticket_id=3)
    admin.execute("UPDATE action_requests SET status = 'manual_only' WHERE id = %s", (rid,))
    text = refusal_text(lambda: insert_order(as_role("executor"), rid, "SP-1003"))
    assert "SP-" not in text, text


def test_control_an_order_that_fits_the_request_is_accepted(admin, as_role):
    rid = ready_for_order(admin, as_role("approver"), account_id=1, ticket_id=1)
    insert_order(as_role("executor"), rid, "SP-1001")
