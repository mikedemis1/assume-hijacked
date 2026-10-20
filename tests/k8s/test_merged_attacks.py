"""Attack cases need a valid effect request as a control for the refusal cases."""

import pytest

from tests.k8s.test_replay import require_scripted_container


@pytest.mark.parametrize("backend", ["anthropic", "foundry", "", None])
def test_live_replay_refuses_provider_or_ambiguous_backend(backend):
    container = {"command": ["python", "-m", "app.llmgw.main"], "env": []}
    if backend is not None:
        container["env"].append({"name": "LLM_BACKEND", "value": backend})
    with pytest.raises(AssertionError, match="scripted backend"):
        require_scripted_container(container)


