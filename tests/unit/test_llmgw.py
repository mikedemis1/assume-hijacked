"""The LLM gateway: the agent's only way to a model.

It is built the way the container builds it: the real HTTP app with the real caller check and the
real budget. Only the edges are replaced: the network by an ASGI transport that sets the source
address, the TokenReview by a function, and the model provider by a fake upstream that records what
it was sent.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx2
import pytest

from app.common.ops import Metrics
from app.common.tokenreview import Review
from app.gateway.auth import AGENT_USER
from app.llmgw import backends, main as llmgw_main
from app.llmgw.backends import AnthropicBackend, ScriptedBackend
from app.llmgw.main import Budget, LlmGateway, build_app, init_metrics

ROOT = Path(__file__).resolve().parents[2]
AGENT_IP = "10.250.3.5"  # the address a request comes from (the budget's key; the caller check ignores it)
LEASE = "ab" * 32
OTHER_LEASE = "cd" * 32
EVENTS = "assume_hijacked.security"
TICKET = [{"role": "ticket", "text": "My bill looks wrong."}]


# --- the harness ---------------------------------------------------------------------------------


def request(app, method, path, *, headers=None, content=None, ip=AGENT_IP):
    async def go():
        client = None if ip is None else (ip, 50000)
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app, client=client), base_url="http://llm-gateway.test"
        ) as http:
            return await http.request(method, path, headers=headers, content=content)

    return asyncio.run(go())


def post_next(app, transcript=TICKET, *, lease=LEASE, headers=None, ip=AGENT_IP, body=None, auth=True):
    """POST /next. By default with a token for a pod of its own per lease (a pod has one lease for
    its life); `headers` are added to that and can replace it; `auth=False` sends no token at all."""
    sent = {"Authorization": f"Bearer lease-{lease}"} if auth else {}
    sent.update(headers or {})
    if lease is not None:
        sent["X-Lease"] = lease
    content = json.dumps({"transcript": transcript}) if body is None else body
    return request(app, "POST", "/next", headers=sent, content=content, ip=ip)


class CountingBackend:
    """Wraps a backend and counts how often it was reached: a refused request must leave it at 0."""

    def __init__(self, inner=None):
        self.inner = inner or ScriptedBackend()
        self.calls = 0

    async def next(self, transcript):
        self.calls += 1
        return await self.inner.next(transcript)


def agent_reviewer(token, audience):
    """The default TokenReview stand-in: every token is the agent's, issued to a pod named after it."""
    assert audience == "llm-gateway"
    return Review(username=AGENT_USER, pod=f"agent-{token}")


class Harness:
    def __init__(self, backend=None, *, mode="k8s", limit=20000, reviewer=None, total=None, **budget):
        self.metrics = Metrics()
        init_metrics(self.metrics)
        self.backend = backend if backend is not None else CountingBackend()
        self.gateway = LlmGateway(self.backend, Budget(limit, **budget), self.metrics, total_limit=total)
        self.auth = llmgw_main.caller_auth(mode, reviewer or agent_reviewer)
        self.app = build_app(self.gateway, self.auth, self.metrics)

    def post(self, *args, **kwargs):
        return post_next(self.app, *args, **kwargs)


def reviewer_for(tokens):
    def review(token, audience):
        assert audience == "llm-gateway"
        found = tokens.get(token)
        return None if found is None else Review(username=found[0], pod=found[1])

    return review


def metric(h, name, **labels):
    key = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
    for line in h.metrics.render().splitlines():
        if line.startswith(f"{name}{{{key}}} " if key else f"{name} "):
            return float(line.rsplit(" ", 1)[1])
    raise AssertionError(f"no series {name}{{{key}}}")


@pytest.fixture
def h():
    return Harness()


# --- the budget ------------------------------------------------------------------------------


def test_budget_exceeded_returns_429():
    h = Harness(limit=250)
    answers = [h.post(lease=LEASE) for _ in range(20)]
    codes = [a.status_code for a in answers]
    assert codes[0] == 200                                          # the control: a lease under budget is served
    assert 429 in codes
    first = codes.index(429)
    assert set(codes[first:]) == {429}                              # and once over it stays over
    assert answers[first].json() == {"error": "budget"}
    reached = h.backend.calls
    assert h.post(lease=LEASE).status_code == 429
    assert h.backend.calls == reached                               # the model was not asked again
    assert metric(h, "llmgw_requests_total", outcome="budget") >= 1


def test_the_budget_is_per_lease():
    h = Harness(limit=250)
    while h.post(lease=LEASE).status_code == 200:
        pass
    assert h.post(lease=LEASE).status_code == 429
    assert h.post(lease=OTHER_LEASE).status_code == 200            # another run is not affected


# --- the caller check -------------------------------------------------------------------------


def test_kubernetes_needs_the_agents_service_account_a_token_for_this_audience_and_a_pod():
    tokens = {
        "good": (AGENT_USER, "agent-1-abcde"),
        "other-sa": ("system:serviceaccount:ah-tools:tool-read-ticket", "tool-x"),
        "no-pod": (AGENT_USER, None),
    }
    h = Harness(mode="k8s", reviewer=reviewer_for(tokens))
    for headers in ({}, {"Authorization": "Bearer nope"}, {"Authorization": "Bearer other-sa"},
                    {"Authorization": "Bearer no-pod"}, {"Authorization": "Basic good"},
                    {"Authorization": "Bearer good extra"}):
        assert h.post(headers=headers, auth=False).status_code == 401, headers
    assert h.backend.calls == 0
    assert h.post(headers={"Authorization": "Bearer good"}).status_code == 200   # the control
    assert h.backend.calls == 1


# --- the Anthropic backend against a fake upstream -------------------------------------------------

GATEWAY_KEY = "sk-gateway-held-key"


class Upstream:
    """A fake model provider: records every request and answers from a queue."""

    def __init__(self, *answers):
        self.answers = list(answers) or [message(text="Hello from the model")]
        self.seen: list[httpx2.Request] = []

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.seen.append(request)
        answer = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        if isinstance(answer, httpx2.Response):
            return answer
        return httpx2.Response(200, json=answer)

    def body(self, index=-1):
        return json.loads(self.seen[index].content)

    @property
    def transport(self):
        return httpx2.MockTransport(self)


def message(text=None, tool=None, usage=(120, 30)):
    content = []
    if text is not None:
        content.append({"type": "text", "text": text})
    if tool is not None:
        content.append({"type": "tool_use", "id": "toolu_x", "name": tool[0], "input": tool[1]})
    return {"id": "msg_1", "type": "message", "role": "assistant", "content": content,
            "stop_reason": "tool_use" if tool else "end_turn", "usage": {"input_tokens": usage[0], "output_tokens": usage[1]}}


@pytest.fixture
def key_file(tmp_path):
    path = tmp_path / "anthropic-key"
    path.write_text(GATEWAY_KEY + "\n", encoding="utf-8")
    return path


def anthropic(upstream, key_file, model="claude-haiku-5-5"):
    return AnthropicBackend(str(key_file), model, base_url="https://api.anthropic.test", transport=upstream.transport)


def test_anthropic_backend_against_fake_upstream(key_file):
    upstream = Upstream(message(tool=("lookup_account", {})), message(text="Your account is active."))
    h = Harness(anthropic(upstream, key_file))
    first = h.post(TICKET)
    assert first.json() == {"type": "call", "name": "lookup_account", "args": {}}
    second = h.post([*TICKET, {"role": "tool", "name": "lookup_account", "args": {}, "result": '{"status": "active"}'}])
    assert second.json() == {"type": "reply", "text": "Your account is active."}
    # What went to the provider.
    request_ = upstream.seen[0]
    assert str(request_.url) == "https://api.anthropic.test/v1/messages"
    assert request_.headers["x-api-key"] == GATEWAY_KEY
    assert request_.headers["anthropic-version"] == "2023-06-01"
    body = upstream.body(0)
    assert body["model"] == "claude-haiku-5-5" and body["max_tokens"] == backends.MAX_OUTPUT_TOKENS
    assert "untrusted" in body["system"].lower()
    assert body["messages"] == [{"role": "user", "content": [{"type": "text", "text": TICKET[0]["text"]}]}]
    # The tool results go back as tool_use / tool_result pairs with matching ids.
    again = upstream.body(1)["messages"]
    assert [m["role"] for m in again] == ["user", "assistant", "user"]
    use, result = again[1]["content"][0], again[2]["content"][0]
    assert use["type"] == "tool_use" and use["name"] == "lookup_account" and use["input"] == {}
    assert result == {"type": "tool_result", "tool_use_id": use["id"], "content": '{"status": "active"}'}
    # Tokens come from the provider's usage.
    assert metric(h, "llmgw_tokens_total") == 2 * (120 + 30)


# --- the caller's own credentials never reach the provider ---------------------------------------------


def everything_sent(upstream):
    return "\n".join(
        f"{request.method} {request.url}\n{dict(request.headers)}\n{request.content.decode()}" for request in upstream.seen
    )


def test_caller_key_is_dropped(key_file):
    upstream = Upstream()
    h = Harness(anthropic(upstream, key_file))
    forged = {
        "x-api-key": "caller-key-1", "Authorization": "Bearer caller-token-1", "anthropic-version": "1999-01-01",
        "anthropic-beta": "caller-beta", "Cookie": "caller-cookie", "api-key": "caller-key-2",
    }
    assert h.post(headers=forged).status_code == 200
    assert len(upstream.seen) == 1                                  # the control: the provider was reached
    sent = upstream.seen[0]
    assert sent.headers["x-api-key"] == GATEWAY_KEY                 # the gateway's own key, not the caller's
    assert "authorization" not in sent.headers
    assert sent.headers["anthropic-version"] == "2023-06-01"
    text = everything_sent(upstream)
    for caller_value in ("caller-key-1", "caller-key-2", "caller-token-1", "caller-beta", "caller-cookie", "1999-01-01"):
        assert caller_value not in text
    assert LEASE not in text                                        # nor the lease: the provider has no use for it


# --- choosing the backend and starting the process -----------------------------------------------------


def env(**more):
    return {"CALLER_AUTH": "k8s", **more}


