"""Case 9: an agent keeps calling denied tools (ASI10).

Wall: three denials pause all agents (the kill switch); only a SeniorApprover resumes them.
"""

import asyncio

import pytest

from app.risk.rules import assess_call
from tests.gatewayharness import build, RealRisk
from tests.unit.test_console import BOB, browser, console, console_env, login
from tests.unit.test_gateway import call_assessment_rows, metric, only_read
from tests.unit.test_risk_floor import control
from tests.unit.test_risk_rules import call


def test_asi10_repeated_denials_pause_every_agent(settings, admin, as_role):
    lease = only_read(admin)
    risk = RealRisk(settings)
    try:
        built = build(settings, as_role, risk=risk)
        for _ in range(3):
            assert built.call("set_temp_protection", {}, lease).text == "ERROR: lease"   # not in the lease
        assert admin.execute("SELECT paused FROM agent_control").fetchone()["paused"] is False
        # The next call on that lease, to a tool it does list, is the engine's "pause": every agent stops.
        assert built.call("read_ticket", {}, lease).text == "ERROR: denied"
        assert metric(built, "gateway_denials_total", tool="read_ticket", reason="repeated_denials") == 1
        assert admin.execute("SELECT paused FROM agent_control").fetchone()["paused"] is True
        asked = len(call_assessment_rows(admin))
        assert built.call("read_ticket", {}, lease).text == "ERROR: denied"             # the stop switch
        assert len(call_assessment_rows(admin)) == asked                                 # the engine was not asked
    finally:
        risk.close()


def test_asi10_risk_engine_pauses_and_approver_resumes(admin, as_role):
    as_role("risk_engine").execute("SELECT pause_agents('repeated_denials')")
    assert control(admin) == [{"paused": True, "reason": "repeated_denials"}]
    as_role("approver").execute("SELECT resume_agents()")
    assert control(admin) == [{"paused": False, "reason": ""}]
    events = admin.execute("SELECT kind, actor, detail FROM events ORDER BY id").fetchall()
    assert events == [
        {"kind": "agents_paused", "actor": "risk_engine", "detail": "repeated_denials"},
        {"kind": "agents_resumed", "actor": "approver", "detail": ""},
    ]


def test_asi10_resume_needs_a_senior_approver(console, admin):
    admin.execute("UPDATE agent_control SET paused=true WHERE id=1")
    async def check(client):
        csrf, _ = await login(client)
        assert (await client.post("/agents/resume", data={"csrf":csrf,"role":"SeniorApprover"})).status_code == 403
    asyncio.run(browser(console, check))
    assert admin.execute("SELECT paused FROM agent_control").fetchone()["paused"]
    async def allowed(client):
        csrf, _ = await login(client, BOB)
        assert (await client.post("/agents/resume", data={"csrf":csrf})).status_code == 303
    asyncio.run(browser(console, allowed))
    assert not admin.execute("SELECT paused FROM agent_control").fetchone()["paused"]


@pytest.mark.parametrize("denied,verdict", [(0, "allow"), (2, "allow"), (3, "pause"), (4, "pause")])
def test_asi10_three_denials_pause_in_the_rules(denied, verdict):
    got = assess_call(call(denied_on_lease=denied))
    assert got == (verdict, ("repeated_denials",) if verdict == "pause" else ())
