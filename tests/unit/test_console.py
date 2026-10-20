"""Browser approval boundaries, using local identity-provider keys and the real database."""

import asyncio
import json
import re
import time

import httpx2
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from tests.conftest import assess
import psycopg

ANNA = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
BOB = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
CAROL = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
TENANT = "11111111-1111-4111-8111-111111111111"
CLIENT = "22222222-2222-4222-8222-222222222222"


@pytest.fixture
def console_env(monkeypatch):
    monkeypatch.setenv("APP_ENV", "local")
    monkeypatch.setenv("AUTH_MODE", "dev")
    monkeypatch.setenv("CONSOLE_DEV_USERS", json.dumps({ANNA: ["Approver"], BOB: ["SeniorApprover"], CAROL: ["SeniorApprover"]}))


@pytest.fixture
def console(console_env, settings):
    from app.console.main import build_app
    return build_app(settings=settings)


async def browser(app, action):
    async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url="http://127.0.0.1:8084") as client:
        return await action(client)


async def login(client, who=ANNA):
    response = await client.get("/", headers={"X-Dev-User": who})
    assert response.status_code == 200, response.text
    csrf = re.search(r'name="csrf" value="([^"]+)"', response.text).group(1)
    return csrf, response


def request_credit(admin, tier="T1"):
    rid = admin.execute("INSERT INTO action_requests (kind,ticket_id,account_id,amount_eur,reason) VALUES ('credit',1,1,60,'private reason') RETURNING id").fetchone()["id"]
    assess(admin, rid, tier, reasons=("above_auto_limit",))
    return rid


def test_approve_records_oid_and_role(console, admin):
    rid = request_credit(admin)
    async def check(client):
        csrf, _ = await login(client, BOB)
        response = await client.post(f"/approve/{rid}", data={"csrf":csrf,"approver":CAROL,"approver_role":"Approver"})
        assert response.status_code == 303
    asyncio.run(browser(console, check))
    row = admin.execute("SELECT approver,approver_role FROM approvals WHERE request_id=%s", (rid,)).fetchone()
    assert str(row["approver"]) == BOB and row["approver_role"] == "SeniorApprover"


@pytest.mark.parametrize("route", ["/approve/1", "/reject/1", "/agents/resume", "/logout"])
@pytest.mark.parametrize("csrf", [None,"forged"])
def test_csrf_required(console, route, csrf):
    async def check(client):
        await login(client, BOB)
        response = await client.post(route, data={} if csrf is None else {"csrf":csrf})
        assert response.status_code == 403
    asyncio.run(browser(console, check))


@pytest.mark.parametrize("tier",[None,"HUMAN_ONLY","REJECT"])
def test_unapprovable_tier_refused_even_with_valid_csrf(console,admin,tier):
    rid=request_credit(admin,tier or "T1")
    if tier is None:
        with admin.transaction():
            admin.execute("SET LOCAL session_replication_role = replica")
            admin.execute("DELETE FROM risk_assessments WHERE request_id=%s",(rid,))
    async def check(client):
        csrf,response=await login(client)
        assert (await client.post(f"/approve/{rid}",data={"csrf":csrf})).status_code == 409
        if tier is None:
            assert "Protected customer" in response.text
    asyncio.run(browser(console,check))


@pytest.fixture
def provider():
    private = rsa.generate_private_key(public_exponent=65537,key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key()))
    jwk.update(kid="local-key",alg="RS256",use="sig")
    def token(nonce="nonce", **changes):
        claims = dict(iss=f"https://login.microsoftonline.com/{TENANT}/v2.0",aud=CLIENT,tid=TENANT,oid=BOB,roles=["SeniorApprover"],nonce=nonce,iat=int(time.time()),exp=int(time.time())+300,sub="subject")
        claims.update(changes)
        return jwt.encode(claims,private,algorithm="RS256",headers={"kid":"local-key"})
    return {"keys":[jwk]}, token


@pytest.mark.parametrize("changes", [{"aud":"other"},{"iss":"https://attacker.test"},{"exp":1},{"oid":"staff.name"},{"roles":["Admin"]},{"nonce":"wrong"},{"tid":CLIENT}])
def test_entra_token_wrong_audience_or_issuer_rejected(provider, changes):
    from app.console.auth import verify_id_token
    jwks, token = provider
    with pytest.raises(ValueError):
        verify_id_token(token(**changes),jwks,TENANT,CLIENT,"nonce")
    identity, _ = verify_id_token(token(),jwks,TENANT,CLIENT,"nonce")
    assert identity.oid == BOB and identity.role == "SeniorApprover"


def test_asi03_one_person_cannot_count_twice(admin,as_role):
    rid=request_credit(admin,"T2")
    staff=as_role("approver")
    staff.execute("INSERT INTO approvals(request_id,approver) VALUES (%s,%s)",(rid,ANNA))
    with pytest.raises(psycopg.errors.UniqueViolation):
        staff.execute("INSERT INTO approvals(request_id,approver) VALUES (%s,%s)",(rid,ANNA.upper().replace("-","")))
    with pytest.raises(psycopg.errors.InvalidTextRepresentation):
        staff.execute("INSERT INTO approvals(request_id,approver) VALUES (%s,%s)",(rid,"\u00a0"+ANNA))


def test_asi10_resume_needs_a_senior_approver(console, admin):  # noqa: F811
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
