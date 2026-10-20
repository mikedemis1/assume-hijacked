"""Attack cases need a valid effect request as a control for the refusal cases."""

import pytest

from tests.attacks.tickets import ATTACK_TICKETS, Call, plan
from tests.k8s.test_replay import require_scripted_container


@pytest.mark.parametrize("ticket", [ticket for ticket in ATTACK_TICKETS if ticket.effects],
                         ids=lambda ticket: str(ticket.number))
def test_effect_attacks_include_a_control_with_the_current_tool_arguments(ticket):
    required = {
        "issue_bill_credit": {"amount_eur", "reason", "evidence_ref"},
        "request_disconnection": {"move_out_date"},
    }
    controls = [step for step in plan(ticket.body) if isinstance(step, Call)
                and step.tool in required and required[step.tool] <= step.args.keys()]
    assert controls, f"attack {ticket.number} has no valid effect control"


@pytest.mark.parametrize("backend", ["anthropic", "foundry", "", None])
def test_live_replay_refuses_provider_or_ambiguous_backend(backend):
    container = {"command": ["python", "-m", "app.llmgw.main"], "env": []}
    if backend is not None:
        container["env"].append({"name": "LLM_BACKEND", "value": backend})
    with pytest.raises(AssertionError, match="scripted backend"):
        require_scripted_container(container)


def test_live_replay_allows_explicit_scripted_backend():
    require_scripted_container({"command": ["python", "-m", "app.llmgw.main"],
                                "env": [{"name": "LLM_BACKEND", "value": "scripted"}]})
