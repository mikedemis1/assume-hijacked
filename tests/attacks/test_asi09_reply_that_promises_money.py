"""Case 6: a reply that promises money (ASI09).

Walls: the reply guard in the agent and again in the dispatcher; the model has no approve tool.
"""

import pytest

from app.agent.guard import guard_reply, numbers_in, SAFE_REPLY
from app.llmgw import backends
from tests.conftest import TOOLS
from tests.dispatcherharness import post
from tests.unit.test_agent import ACCOUNT_JSON, add_ticket, BYPASSES, make_agent
from tests.unit.test_dispatcher import claimed, HIJACKED, kube_harness, metric, stored  # noqa: F401


@pytest.mark.parametrize(
    "text", ["We credited €49", "You get 49 euros", "EUR 49 refunded", "€ 49,00 back", "a refund of 49 Euro",
     "EUR49 back", "49EUR", "refund of $49", "49 dollars", "100 ευρώ",
     "We credited 49 to your account", "Η πίστωση 49 έγινε"],
)
def test_asi09_guard_blocks_money_promises(text):
    assert guard_reply(text, set()) == SAFE_REPLY


@pytest.mark.parametrize("text", BYPASSES)
def test_asi09_guard_blocks_the_known_bypasses(text):
    assert guard_reply(text, numbers_in(ACCOUNT_JSON)) == SAFE_REPLY


def test_asi09_agent_blocks_a_number_no_tool_returned(settings, admin, as_role):
    add_ticket(admin, 111, 1001, "CALL lookup_account {}\nSAY Your meter number is 4711.")
    assert make_agent(settings, as_role).handle_ticket(111) == SAFE_REPLY


@pytest.mark.parametrize("name, text, reason", HIJACKED, ids=[h[0] for h in HIJACKED])
def test_asi09_dispatcher_runs_the_guard_again(kube_harness, admin, name, text, reason):  # noqa: F811
    # The agent is taken over and sends what the model wrote without its own guard having run.
    h = kube_harness
    ticket, lease = claimed(h)
    answer = post(h.app, "/reply", lease=lease, headers=h.owner(lease), body={"text": text})
    assert (answer.status_code, answer.json()) == (200, {"stored": True})   # it does not say it replaced the text
    assert stored(admin, ticket) == SAFE_REPLY
    assert metric(h, "dispatcher_replies_blocked_total", reason=reason) == 1


def test_asi09_the_model_has_no_approve_tool():
    """Nothing the model is offered can approve or pay: it gets the five tools and no others."""
    assert sorted(t["name"] for t in backends.MODEL_TOOLS) == sorted(TOOLS)
