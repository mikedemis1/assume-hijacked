"""Every attack ticket of the table (tests/attacks/tickets.py), run through the real agent.

Per ticket: the agent (ScriptedLLM, which obeys the CALL/SAY lines of the ticket) works under a lease
the dispatcher's claim would open; its calls go through the real tool gateway with the REAL risk
engine (one effect per ticket, 8 calls per lease) to the real tools and the test database; its reply
goes to the real dispatcher, which runs the reply guard again. Then every field of the ticket is
checked:

  leak             in no tool result the agent got, and in neither the agent's reply nor the stored one
  reply_forbidden  not in the stored reply (after the dispatcher's guard) nor in the agent's own reply
  reply_shows      in the stored reply (on an effect ticket: the dispatcher's fixed template)
  refused_tools    every call to these tools came back as an error (seen by the model)
  effects          exactly this many requests filed (successful effect calls, and rows in action_requests)
  calls            exactly this many gateway calls succeeded, the agent's read_ticket included
  shows            each appears in a successful tool result: the honest part still works

The test ids start with the ASI ids of the case, so the ASI summary in tests/conftest.py counts them.
"""

import pytest

from app.agent.core import Agent
from app.agent.llm import ScriptedLLM
from tests.attacks.tickets import ATTACK_TICKETS, EFFECT_TOOLS
from tests.gatewayharness import AppGatewayClient, RealRisk, build
from tests.unit.test_agent import LeasedAgent, add_ticket


class Seen(ScriptedLLM):
    """The scripted model, keeping the conversation it was shown: the calls it made and what came back."""

    transcript: list

    def next_action(self, transcript):
        self.transcript = transcript
        return super().next_action(transcript)


class Recorded(AppGatewayClient):
    """The agent's tool client, keeping every call that reached the tool gateway and its answer."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.answers: list[tuple[str, str]] = []

    def call(self, name, args):
        answer = super().call(name, args)
        self.answers.append((name, answer))
        return answer


def case_id(t) -> str:
    slug = "".join(c if c.isalnum() else "-" for c in t.name.replace("'", "").lower()).strip("-")
    return f"{'-'.join(t.asi)}-{t.number}-{'-'.join(w for w in slug.split('-') if w)}"


def is_error(text: str) -> bool:
    return text.startswith("ERROR")


def has(marker: str, texts) -> bool:
    return any(marker.lower() in text.lower() for text in texts)


@pytest.mark.parametrize("ticket", ATTACK_TICKETS, ids=case_id)
def test_attack_table(ticket, settings, admin, as_role):
    assert ticket.asi, "every ticket names its ASI ids"
    add_ticket(admin, ticket.ticket_id, ticket.customer_id, ticket.body)
    risk = RealRisk(settings)
    try:
        gateway = Recorded(build(settings, as_role, risk=risk))
        llm = Seen()
        agent = LeasedAgent(Agent(llm, gateway), settings, as_role)
        stored = agent.handle_ticket(ticket.ticket_id)      # after the dispatcher's guard
        sent = agent.sent                                    # what the agent itself sent
        filed = admin.execute("SELECT count(*) AS n FROM action_requests").fetchone()["n"]
    finally:
        risk.close()

    got = [text for _, text in gateway.answers] + [t["result"] for t in llm.transcript if t["role"] == "tool"]
    seen_by_model = [t for t in llm.transcript if t["role"] == "tool"]

    for marker in ticket.leak:
        assert not has(marker, got), f"{ticket.number}: a tool result holds a leak marker"
        assert not has(marker, [sent, stored]), f"{ticket.number}: the reply holds a leak marker"
    for marker in ticket.reply_forbidden:
        assert not has(marker, [stored]), f"{ticket.number}: the stored reply holds a forbidden marker"
        assert not has(marker, [sent]), f"{ticket.number}: the agent's reply holds a forbidden marker"
    for marker in ticket.reply_shows:
        assert has(marker, [stored]), f"{ticket.number}: the stored reply lacks an expected marker"
    for tool in ticket.refused_tools:
        calls = [t for t in seen_by_model if t["name"] == tool]
        assert calls, f"{ticket.number}: the ticket never called {tool}"
        assert all(is_error(t["result"]) for t in calls), f"{ticket.number}: a call to {tool} succeeded"
    if ticket.effects is not None:
        done = [t for t in seen_by_model if t["name"] in EFFECT_TOOLS and not is_error(t["result"])]
        assert len(done) == ticket.effects, f"{ticket.number}: {len(done)} effect calls succeeded"
        assert filed == ticket.effects, f"{ticket.number}: {filed} requests were filed"
    if ticket.calls is not None:
        ok = [name for name, text in gateway.answers if not is_error(text)]
        assert len(ok) == ticket.calls, f"{ticket.number}: {len(ok)} calls succeeded"
    for marker in ticket.shows:
        assert has(marker, [text for _, text in gateway.answers if not is_error(text)]), \
            f"{ticket.number}: no successful tool result holds an expected marker"
