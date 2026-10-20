"""Case 8: the risk engine is down or too slow (ASI08).

Wall: the gateway fails closed.
"""

import asyncio
import httpx2
import json
import logging
import time

import psycopg
import pytest

from app.gateway.proxy import RiskClient
from tests.conftest import open_lease
from tests.gatewayharness import build, FakeRisk
from tests.unit.test_gateway import calls, DownTransport, metric
from tests.unit.test_risk_service import FakeDecider, post


def test_asi08_gateway_denies_when_risk_engine_is_down(settings, admin, as_role):
    lease = open_lease(admin, 1)
    # The risk engine is down: the connection is refused (and a connection that times out is the
    # same, it never reached the engine).
    built = build(settings, as_role, risk=RiskClient("http://risk.test", transport=DownTransport()))
    answer = built.call("lookup_account", {}, lease)
    assert (answer.is_error, answer.text) == (True, "ERROR: denied")
    assert built.tools.forwarded() == []                      # the tool was never reached
    assert [(r["outcome"], r["reason"]) for r in calls(admin)] == [("denied", "risk_unavailable")]
    assert metric(built, "gateway_denials_total", tool="lookup_account", reason="risk_unavailable") == 1
    # The control: with an engine that answers allow, the same call goes through.
    control = build(settings, as_role, risk=FakeRisk())
    assert json.loads(control.call("lookup_account", {}, lease).text)["name"] == "Eleni Papadopoulou"
    assert control.tools.forwarded() == [("lookup_account", {})]


def test_asi08_gateway_denies_when_risk_engine_is_too_slow(settings, admin, as_role):
    lease = open_lease(admin, 1)

    async def never_answers(request):
        await asyncio.sleep(30)

    client = RiskClient("http://risk.test", transport=httpx2.MockTransport(never_answers))
    assert client.timeout_s == 2.0                              # the contract: 2 s, then deny
    built = build(settings, as_role, risk=client)
    started = time.monotonic()
    answer = built.call("lookup_account", {}, lease)
    elapsed = time.monotonic() - started
    assert answer.text == "ERROR: denied"
    assert 1.5 < elapsed < 3.5, elapsed                         # waited the 2 s, not 30
    assert built.tools.forwarded() == []
    # Not a plain denial: the engine may have written "allow" (and used up the lease's one effect)
    # after the gateway stopped waiting. The row says so.
    assert [(r["outcome"], r["reason"]) for r in calls(admin)] == [("risk_timeout", "risk_timeout")]
    assert metric(built, "gateway_denials_total", tool="lookup_account", reason="risk_timeout") == 1
    assert metric(built, "gateway_calls_total", tool="lookup_account", outcome="risk_timeout") == 1


@pytest.mark.parametrize(
    "handler",
    [
        lambda request: httpx2.Response(500, json={"decision": "deny", "reasons": ["risk_unavailable"]}),
        lambda request: httpx2.Response(200, content=b"not json"),
        lambda request: httpx2.Response(200, json=["allow"]),
        lambda request: httpx2.Response(200, json={"decision": "maybe", "reasons": []}),
        lambda request: httpx2.Response(200, json={"reasons": []}),
        lambda request: httpx2.Response(200, json={"decision": "deny", "reasons": ["call_budget"]}),
        lambda request: httpx2.Response(200, json={"decision": "pause", "reasons": ["repeated_denials"]}),
    ],
    ids=["500", "not-json", "list", "unknown-decision", "no-decision", "deny", "pause"],
)
def test_asi08_only_a_clear_allow_lets_a_call_through(settings, admin, as_role, handler):
    lease = open_lease(admin, 1)
    risk = RiskClient("http://risk.test", transport=httpx2.MockTransport(handler))
    built = build(settings, as_role, risk=risk)
    assert built.call("lookup_account", {}, lease).text == "ERROR: denied"
    assert built.tools.forwarded() == []
    # The control: a clear allow, in the same shape, goes through.
    allow = RiskClient(
        "http://risk.test", transport=httpx2.MockTransport(lambda r: httpx2.Response(200, json={"decision": "allow", "reasons": []}))
    )
    assert build(settings, as_role, risk=allow).call("lookup_account", {}, lease).is_error is False


def test_asi08_decide_endpoint_fails_closed_when_the_database_fails(caplog):
    lease = "b" * 64
    decider = FakeDecider(error=psycopg.OperationalError(f"server closed the connection {lease}"))
    with caplog.at_level(logging.DEBUG):
        response = post(decider, {"lease": lease, "tool": "read_ticket"})
    assert response.status_code == 503
    assert response.json() == {"decision": "deny", "reasons": ["risk_unavailable"]}
    # The log names the error class only: never the lease, never the message that may carry it.
    assert lease not in caplog.text
    assert "OperationalError" in caplog.text
