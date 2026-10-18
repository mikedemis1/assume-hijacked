"""Browser approval boundaries, using local identity-provider keys and the real database."""

import asyncio
import base64
import hashlib
import importlib.util
import json
import re
import time
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx2
import jwt
import psycopg
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from tests.conftest import assess

ANNA = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
BOB = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
CAROL = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
TENANT = "11111111-1111-4111-8111-111111111111"
CLIENT = "22222222-2222-4222-8222-222222222222"


def test_console_exists():
    assert importlib.util.find_spec("app.console") is not None, "approval console is missing"


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


def test_console_refuses_dev_auth_in_azure(console_env, monkeypatch):
    from app.console.main import build_app
    monkeypatch.setenv("APP_ENV", "azure")
    with pytest.raises(ValueError, match="dev"):
        build_app()


def test_queue_never_shows_ticket_text_or_diagnosis(console, admin):
    rid = request_credit(admin, "HUMAN_ONLY")
    admin.execute("UPDATE tickets SET body='SECRET TICKET DIAGNOSIS' WHERE id=1")
    admin.execute("INSERT INTO events(kind,detail) VALUES ('ALERT','SECRET HEALTH EVENT')")
    admin.execute("INSERT INTO heartbeats VALUES ('executor',now())")
    async def check(client):
        _, response = await login(client)
        assert "HUMAN_ONLY" in response.text and "above_auto_limit" in response.text
        assert "Protected customer" in response.text and "call the registered number first" in response.text
        assert "SECRET" not in response.text and "private reason" not in response.text
        assert "executor" in response.text and "ALERT" in response.text
        assert f"/approve/{rid}" not in response.text
    asyncio.run(browser(console, check))


def test_approve_records_oid_and_role(console, admin):
    rid = request_credit(admin)
    async def check(client):
        csrf, _ = await login(client, BOB)
        response = await client.post(f"/approve/{rid}", data={"csrf":csrf,"approver":CAROL,"approver_role":"Approver"})
        assert response.status_code == 303
    asyncio.run(browser(console, check))
    row = admin.execute("SELECT approver,approver_role FROM approvals WHERE request_id=%s", (rid,)).fetchone()
    assert str(row["approver"]) == BOB and row["approver_role"] == "SeniorApprover"


@pytest.mark.parametrize("route", ["/approve/1", "/reject/1", "/flags/removal", "/flags/removal/1/approve", "/agents/resume", "/logout"])
@pytest.mark.parametrize("csrf", [None,"forged"])
def test_csrf_required(console, route, csrf):
    async def check(client):
        await login(client, BOB)
        response = await client.post(route, data={} if csrf is None else {"csrf":csrf})
        assert response.status_code == 403
    asyncio.run(browser(console, check))


def test_resume_needs_senior(console, admin):
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


def test_flag_removal_needs_senior_and_distinct_people(console, admin, as_role):
    async def requested(client):
        csrf, _ = await login(client)
        assert (await client.post("/flags/removal", data={"csrf":csrf,"supply_point_id":"SP-1003","reason":"SECRET DIAGNOSIS","requested_by":BOB})).status_code == 303
    asyncio.run(browser(console, requested))
    row = admin.execute("SELECT * FROM flag_removal_requests").fetchone()
    rid = row["id"]
    assert str(row["requested_by"]) == ANNA
    async def blocked(client):
        csrf, _ = await login(client)
        assert (await client.post(f"/flags/removal/{rid}/approve", data={"csrf":csrf,"role":"SeniorApprover"})).status_code == 403
    asyncio.run(browser(console, blocked))
    assert admin.execute("SELECT count(*) AS n FROM flag_removal_approvals").fetchone()["n"] == 0
    for who in (BOB, CAROL):
        async def allowed(client):
            csrf, response = await login(client, who)
            assert "SECRET" not in response.text
            assert (await client.post(f"/flags/removal/{rid}/approve", data={"csrf":csrf})).status_code == 303
        asyncio.run(browser(console, allowed))
    assert admin.execute("SELECT closed_reason FROM flag_removal_requests").fetchone()["closed_reason"] == "removed"
    async def closed(client):
        _, response = await login(client)
        assert "removed" in response.text and "ALERT" in response.text
    asyncio.run(browser(console, closed))


def test_reject_and_unassessed_approval(console, admin):
    rid = request_credit(admin)
    async def check(client):
        csrf, _ = await login(client)
        assert (await client.post(f"/reject/{rid}", data={"csrf":csrf})).status_code == 303
        assert (await client.post(f"/approve/{rid}", data={"csrf":csrf})).status_code == 409
    asyncio.run(browser(console, check))
    row = admin.execute("SELECT status, decision_reason FROM action_requests WHERE id=%s", (rid,)).fetchone()
    assert row["status"] == "refused" and row["decision_reason"] == "staff_rejected"


def test_moveout_can_be_approved_after_notice(console,admin):
    rid=admin.execute("INSERT INTO action_requests(kind,ticket_id,account_id,move_out_date,status) VALUES ('move_out',1,1,CURRENT_DATE,'notice_sent') RETURNING id").fetchone()["id"]
    assess(admin,rid,"T1")
    async def check(client):
        csrf,response=await login(client)
        assert f"/approve/{rid}" in response.text
        assert (await client.post(f"/approve/{rid}",data={"csrf":csrf})).status_code == 303
    asyncio.run(browser(console,check))
    assert admin.execute("SELECT count(*) AS n FROM approvals WHERE request_id=%s",(rid,)).fetchone()["n"] == 1


def test_dev_browser_login_requires_csrf_and_configured_uuid(console):
    async def check(client):
        page=await client.get("/login")
        assert page.status_code == 200
        csrf=re.search(r'name="csrf" value="([^"]+)"',page.text).group(1)
        assert (await client.post("/login",data={"user":BOB,"csrf":"forged"})).status_code == 403
        assert (await client.post("/login",data={"user":"forged","csrf":csrf})).status_code == 401
        assert (await client.post("/login",data={"user":BOB,"csrf":csrf})).status_code == 303
        assert (await client.get("/")).status_code == 200
        assert (await client.post("/agents/resume",data={"csrf":csrf})).status_code == 403
    asyncio.run(browser(console,check))


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
        if tier is None: assert "Protected customer" in response.text
    asyncio.run(browser(console,check))


def test_csrf_bound_to_session_and_non_ascii_refused(console):
    async def check(client):
        csrf,_=await login(client)
        await login(client,BOB)
        for forged in (csrf,"\u03ba\u03bb\u03b5\u03b9\u03b4\u03af"):
            assert (await client.post("/agents/resume",data={"csrf":forged})).status_code == 403
    asyncio.run(browser(console,check))


def test_security_headers_and_session_lifetime(console):
    async def check(client):
        csrf, response = await login(client)
        assert response.headers["content-security-policy"] == "default-src 'self'; frame-ancestors 'none'"
        assert response.headers["cache-control"] == "no-store"
        cookie = response.headers["set-cookie"]
        assert "HttpOnly" in cookie and "SameSite=strict" in cookie
        assert (await client.post("/logout", data={"csrf":csrf})).status_code == 303
        assert (await client.get("/")).status_code == 303
    asyncio.run(browser(console, check))


def test_untrusted_dev_identity_and_expired_session(console):
    async def check(client):
        assert (await client.get("/",headers={"X-Dev-User":"unconfigured"})).status_code == 401
        await login(client)
        for session in console.state.auth.sessions.values():
            session.expires_at = 0
        assert (await client.get("/")).status_code == 303
    asyncio.run(browser(console, check))


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


def entra_app(monkeypatch, settings, provider):
    from app.console.main import build_app
    monkeypatch.setenv("APP_ENV","local")
    monkeypatch.setenv("AUTH_MODE","entra")
    monkeypatch.setenv("ENTRA_TENANT_ID",TENANT)
    monkeypatch.setenv("ENTRA_CLIENT_ID",CLIENT)
    monkeypatch.setenv("CONSOLE_REDIRECT_URI","http://127.0.0.1:8084/auth/callback")
    import tempfile
    from pathlib import Path
    secret_path=Path(tempfile.gettempdir())/"ah-console-test-secret"
    secret_path.write_text("LOCAL_TEST_SECRET",encoding="utf-8")
    monkeypatch.setenv("CONSOLE_CLIENT_SECRET_FILE",str(secret_path))
    calls = []
    def upstream(request):
        calls.append(request)
        if request.url.path.endswith("/keys"):
            return httpx2.Response(200,json=provider[0])
        form = parse_qs(request.content.decode())
        assert form["grant_type"] == ["authorization_code"]
        assert form["client_secret"] == ["LOCAL_TEST_SECRET"]
        assert form["redirect_uri"] == ["http://127.0.0.1:8084/auth/callback"]
        assert hashlib.sha256(form["code_verifier"][0].encode()).digest() == challenge[0]
        return httpx2.Response(200,json={"id_token":provider[1](nonce=nonce[0])})
    challenge, nonce = [], []
    app = build_app(settings=settings, oidc_transport=httpx2.MockTransport(upstream))
    return app,calls,challenge,nonce


def test_oidc_code_pkce_state_nonce_and_replay(monkeypatch,settings,provider):
    app,calls,challenge,nonce = entra_app(monkeypatch,settings,provider)
    async def check(client):
        start = await client.get("/login")
        correlation=client.cookies.get("ah_oidc")
        params = parse_qs(urlsplit(start.headers["location"]).query)
        assert params["response_type"] == ["code"] and params["code_challenge_method"] == ["S256"]
        assert "SameSite=lax" in start.headers["set-cookie"]
        challenge.append(base64.urlsafe_b64decode(params["code_challenge"][0]+"="))
        nonce.append(params["nonce"][0])
        callback = "/auth/callback?"+urlencode({"code":"LOCAL_CODE","state":params["state"][0]})
        result = await client.get(callback)
        assert result.status_code == 200 and 'href="/"' in result.text
        assert "location" not in result.headers
        assert any("SameSite=strict" in cookie for cookie in result.headers.get_list("set-cookie"))
        assert (await client.get("/")).status_code == 200
        client.cookies.set("ah_oidc",correlation,path="/auth/callback")
        assert (await client.get(callback)).status_code == 401
        assert len(calls) == 2
    asyncio.run(browser(app,check))


@pytest.mark.parametrize("attack",["wrong_state","no_cookie","expired"])
def test_oidc_callback_refuses_unbound_state(monkeypatch,settings,provider,attack):
    app,calls,_,_ = entra_app(monkeypatch,settings,provider)
    async def check(client):
        start = await client.get("/login")
        state = parse_qs(urlsplit(start.headers["location"]).query)["state"][0]
        if attack == "wrong_state": state = "forged"
        if attack == "no_cookie": client.cookies.clear()
        if attack == "expired":
            for pending in app.state.auth.pending.values(): pending.expires_at=0
        response = await client.get("/auth/callback?"+urlencode({"state":state,"code":"code"}))
        assert response.status_code == 401 and not calls
    asyncio.run(browser(app,check))


def test_uuid_database_identity_cannot_count_twice(admin,as_role):
    rid=request_credit(admin,"T2")
    staff=as_role("approver")
    staff.execute("INSERT INTO approvals(request_id,approver) VALUES (%s,%s)",(rid,ANNA))
    with pytest.raises(psycopg.errors.UniqueViolation):
        staff.execute("INSERT INTO approvals(request_id,approver) VALUES (%s,%s)",(rid,ANNA.upper().replace("-","")))
    with pytest.raises(psycopg.errors.InvalidTextRepresentation):
        staff.execute("INSERT INTO approvals(request_id,approver) VALUES (%s,%s)",(rid,"\u00a0"+ANNA))


def test_heartbeat_read_cannot_write(as_role):
    staff=as_role("approver")
    assert staff.execute("SELECT component,last_beat FROM heartbeats").fetchall() == []
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        staff.execute("INSERT INTO heartbeats VALUES ('executor',now())")


def test_oidc_invalid_signature_and_key_rejected(provider):
    from app.console.auth import verify_id_token
    jwks,token=provider
    signed=token()
    head,body,signature=signed.split(".")
    forged=signature[:-10]+("A" if signature[-10] != "A" else "B")+signature[-9:]
    with pytest.raises(ValueError):
        verify_id_token(".".join((head,body,forged)),jwks,TENANT,CLIENT,"nonce")
    with pytest.raises(ValueError):
        verify_id_token(signed,{"keys":[]},TENANT,CLIENT,"nonce")
    assert verify_id_token(signed,jwks,TENANT,CLIENT,"nonce")[0].oid == BOB


def test_no_database_access_without_session_or_csrf(console,monkeypatch):
    from app.console import main
    async def check(client):
        csrf,_=await login(client)
        def forbidden(*args,**kwargs):
            pytest.fail("unauthorised browser request reached the database")
        monkeypatch.setattr(main,"connect",forbidden)
        assert (await client.post("/approve/1",data={"csrf":"forged"})).status_code == 403
        client.cookies.clear()
        assert (await client.post("/approve/1",data={"csrf":csrf})).status_code == 401
        assert (await client.get("/")).status_code == 303
    asyncio.run(browser(console,check))


def test_secure_session_cookie_outside_local(console_env,settings,monkeypatch):
    from app.console.main import build_app
    monkeypatch.setenv("APP_ENV","kind")
    app=build_app(settings=settings)
    async def check():
        async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app),base_url="https://console.test") as client:
            response=await client.get("/",headers={"X-Dev-User":BOB})
            assert response.status_code == 200
            assert "Secure" in response.headers["set-cookie"]
            assert "HttpOnly" in response.headers["set-cookie"]
            assert "SameSite=strict" in response.headers["set-cookie"]
    asyncio.run(check())


@pytest.mark.parametrize("users",["[]","{}",'{"staff.anna":["Approver"]}','{"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa":["Admin"]}'])
def test_invalid_dev_users_fail_startup(console_env,monkeypatch,users):
    from app.console.main import build_app
    monkeypatch.setenv("CONSOLE_DEV_USERS",users)
    with pytest.raises(ValueError): build_app()


def test_protection_free_text_and_unknown_reason_not_rendered(console,admin):
    rid=request_credit(admin)
    with admin.transaction():
        admin.execute("SET LOCAL session_replication_role = replica")
        admin.execute("UPDATE risk_assessments SET reasons=ARRAY['<script>alert(1)</script>','SECRET DIAGNOSIS'] WHERE request_id=%s",(rid,))
    async def check(client):
        _,response=await login(client)
        assert "<script>" not in response.text and "SECRET" not in response.text
    asyncio.run(browser(console,check))


def test_safe_console_read_grants(as_role):
    staff=as_role("approver")
    assert staff.execute("SELECT paused FROM agent_control").fetchone()["paused"] is False
    assert staff.execute("SELECT id,kind,actor,created_at FROM events").fetchall() == []
    for query in ("SELECT detail FROM events","SELECT reason FROM agent_control","SELECT body FROM tickets","SELECT source FROM flags"):
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            staff.execute(query)
