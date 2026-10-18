"""The token the tool gateway signs for every tool call, and the check each tool makes before it
touches anything (app/security, app/tools/serve.py).

A tool trusts one thing: a short-lived ES256 token, minted for that tool alone, used once. The lease
(which names the ticket) travels inside it, so the model cannot choose the ticket by setting an
argument.
"""

import asyncio
import base64
import dataclasses
import hashlib
import hmac
import json
import logging
import time

import httpx2
import jwt
import pytest
from mcp import Client

from app import config
from app.security.client import ToolTokenAuth
from app.security.tokens import ISSUER, JtiCache, TokenError, mint_tool_token, verify_tool_token
from app.tools import serve
from tests.conftest import open_lease
from tests.toolhttp import (  # noqa: F401  (the key fixtures are used by name)
    AppToolGateway,
    MCP_HEADERS,
    ConnectSpy,
    bearer,
    keypair,
    mcp_client,
    other_keypair,
    post,
    post_each,
)

NOW = 1_800_000_000.0
LEASE = "ab" * 32


def run(coro):
    return asyncio.run(coro)


def forge(private_pem, claims=None, **overrides):
    """A token with the right signature and claims of our choosing: what a holder of the signing
    key could write. The tool must still refuse the claims that are wrong."""
    base = {"iss": ISSUER, "aud": "read_ticket", "iat": int(NOW), "exp": int(NOW) + 60,
            "jti": "c" * 32, "lease": LEASE}
    base.update(claims or {})
    for key in [k for k, v in overrides.items() if v is None]:
        base.pop(key, None)
    return jwt.encode(base, private_pem, algorithm="ES256")


# --- the token -------------------------------------------------------------------------------

def test_mint_and_verify_roundtrip(keypair):
    private, public = keypair
    token = mint_tool_token(private, "read_ticket", LEASE, NOW)
    claims = verify_tool_token(public, token, "read_ticket", NOW, JtiCache())
    assert claims["iss"] == "tool-gateway"
    assert claims["aud"] == "read_ticket"
    assert claims["lease"] == LEASE
    assert claims["iat"] == int(NOW) and claims["exp"] == int(NOW) + 60
    assert len(claims["jti"]) == 32 and int(claims["jti"], 16) >= 0
    assert jwt.get_unverified_header(token)["alg"] == "ES256"


def test_every_token_has_its_own_jti(keypair):
    private, _ = keypair
    jtis = {jwt.decode(mint_tool_token(private, "read_ticket", LEASE, NOW), options={"verify_signature": False})["jti"]
            for _ in range(50)}
    assert len(jtis) == 50


@pytest.mark.parametrize("mint_for, check_at, reason", [
    ("lookup_account", NOW, "audience"),          # minted for another tool
    ("read_ticket", NOW + 60, "expired"),         # exp is exclusive: valid for 60 s
    ("read_ticket", NOW + 3600, "expired"),
])
def test_verify_refuses_wrong_audience_and_expired(keypair, mint_for, check_at, reason):
    private, public = keypair
    token = mint_tool_token(private, mint_for, LEASE, NOW)
    with pytest.raises(TokenError) as refused:
        verify_tool_token(public, token, "read_ticket", check_at, JtiCache())
    assert refused.value.reason == reason


def test_a_token_is_good_until_it_expires(keypair):
    private, public = keypair
    token = mint_tool_token(private, "read_ticket", LEASE, NOW)
    assert verify_tool_token(public, token, "read_ticket", NOW + 59, JtiCache())["lease"] == LEASE


def test_verify_refuses_a_replayed_token(keypair):
    private, public = keypair
    token = mint_tool_token(private, "read_ticket", LEASE, NOW)
    seen = JtiCache()
    verify_tool_token(public, token, "read_ticket", NOW, seen)
    with pytest.raises(TokenError) as refused:
        verify_tool_token(public, token, "read_ticket", NOW + 1, seen)
    assert refused.value.reason == "replayed"


@pytest.mark.parametrize("mint_for, minted_at", [("lookup_account", NOW), ("read_ticket", NOW - 120)],
                         ids=["wrong-audience", "expired"])
def test_a_refused_token_is_not_remembered(keypair, mint_for, minted_at):
    # Only a token that passed every check enters the cache, so junk cannot fill it.
    private, public = keypair
    seen = JtiCache()
    token = mint_tool_token(private, mint_for, LEASE, minted_at)
    with pytest.raises(TokenError):
        verify_tool_token(public, token, "read_ticket", NOW, seen)
    assert len(seen) == 0
    assert seen.add(jwt.decode(token, options={"verify_signature": False})["jti"], NOW) is True


def test_verify_refuses_another_signer(keypair, other_keypair):
    token = mint_tool_token(other_keypair[0], "read_ticket", LEASE, NOW)
    with pytest.raises(TokenError) as refused:
        verify_tool_token(keypair[1], token, "read_ticket", NOW, JtiCache())
    assert refused.value.reason == "signature"


def test_verify_refuses_an_unsigned_token(keypair):
    def part(data):
        return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()

    claims = {"iss": ISSUER, "aud": "read_ticket", "iat": int(NOW), "exp": int(NOW) + 60,
              "jti": "d" * 32, "lease": LEASE}
    token = f"{part({'alg': 'none', 'typ': 'JWT'})}.{part(claims)}."
    with pytest.raises(TokenError):
        verify_tool_token(keypair[1], token, "read_ticket", NOW, JtiCache())


def test_verify_refuses_hs256_signed_with_the_public_key(keypair):
    # The classic algorithm confusion: the public key is not a secret, so it must never work as
    # an HMAC key. PyJWT refuses to sign with a PEM public key, so the token is built by hand.
    def part(data):
        return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()

    claims = {"iss": ISSUER, "aud": "read_ticket", "iat": int(NOW), "exp": int(NOW) + 60,
              "jti": "e" * 32, "lease": LEASE}
    signing_input = f"{part({'alg': 'HS256', 'typ': 'JWT'})}.{part(claims)}"
    mac = hmac.new(keypair[1], signing_input.encode(), hashlib.sha256).digest()
    token = signing_input + "." + base64.urlsafe_b64encode(mac).rstrip(b"=").decode()
    with pytest.raises(TokenError):
        verify_tool_token(keypair[1], token, "read_ticket", NOW, JtiCache())


@pytest.mark.parametrize("claims, drop, reason", [
    ({"iss": "someone-else"}, None, "issuer"),
    ({}, "jti", "claims"),
    ({}, "lease", "claims"),
    ({}, "exp", "claims"),
    ({}, "iat", "claims"),
    ({"lease": ""}, None, "claims"),
    ({"lease": 7}, None, "claims"),
    ({"jti": ""}, None, "claims"),
    ({"exp": int(NOW) + 3600}, None, "lifetime"),   # longer than the 60 s a token may live
    ({"iat": int(NOW) + 3600, "exp": int(NOW) + 3660}, None, "claims"),  # issued in the future
])
def test_verify_refuses_wrong_claims(keypair, claims, drop, reason):
    private, public = keypair
    token = forge(private, claims, **({drop: None} if drop else {}))
    with pytest.raises(TokenError) as refused:
        verify_tool_token(public, token, "read_ticket", NOW, JtiCache())
    assert refused.value.reason == reason


@pytest.mark.parametrize("text", ["", "x", "a.b.c", "Bearer abc", "é" * 10, "a" * 5000])
def test_verify_refuses_garbage(keypair, text):
    with pytest.raises(TokenError) as refused:
        verify_tool_token(keypair[1], text, "read_ticket", NOW, JtiCache())
    assert refused.value.reason in {"malformed", "signature"}


def test_jti_cache_remembers_for_120_seconds():
    cache = JtiCache()
    assert cache.add("one", 1000.0) is True
    assert cache.add("one", 1000.0) is False
    assert cache.add("one", 1119.0) is False
    assert cache.add("one", 1120.0) is True     # forgotten after 120 s
    assert cache.add("two", 1120.0) is True


def test_jti_cache_forgets_old_entries_so_it_stays_small():
    cache = JtiCache(ttl_seconds=10)
    for i in range(1000):
        cache.add(f"jti-{i}", float(i))
    assert len(cache) <= 11


# --- the tool: what it checks before it opens a database connection --------------------------

def tool_app(tool, public_pem, spy, *, settings=None, clock=lambda: NOW):
    return serve.build_app(tool, settings or config.load(), public_pem, connect=spy, clock=clock)


def test_tool_rejects_wrong_audience_expired_and_replayed_tokens(keypair, caplog):
    private, public = keypair
    spy = ConnectSpy()
    app = tool_app("read_ticket", public, spy)
    caplog.set_level(logging.INFO, logger="assume_hijacked.security")

    wrong_audience = mint_tool_token(private, "lookup_account", LEASE, NOW)
    expired = mint_tool_token(private, "read_ticket", LEASE, NOW - 120)
    valid = mint_tool_token(private, "read_ticket", LEASE, NOW)

    # The valid token is the control: it is let through (tools/list needs no database), once.
    answers = run(post_each(app, bearer(wrong_audience), bearer(expired), bearer(valid), bearer(valid)))
    assert [a.status_code == 401 for a in answers] == [True, True, False, True]
    assert spy.calls == 0

    reasons = [json.loads(r.getMessage())["reason"] for r in caplog.records
               if r.name == "assume_hijacked.security"]
    assert reasons == ["audience", "expired", "replayed"]


def test_tool_rejects_missing_bearer_before_db(keypair):
    _, public = keypair
    spy = ConnectSpy()
    app = tool_app("read_ticket", public, spy)
    for headers in (
        MCP_HEADERS,                                              # no Authorization at all
        {**MCP_HEADERS, "Authorization": ""},
        {**MCP_HEADERS, "Authorization": "Bearer"},
        {**MCP_HEADERS, "Authorization": "Bearer "},
        {**MCP_HEADERS, "Authorization": "Basic dXNlcjpwYXNz"},
        {**MCP_HEADERS, "Authorization": "Bearer not.a.token"},
        {**MCP_HEADERS, "Authorization": "Bearer " + "a" * 5000},
    ):
        answer = run(post(app, headers))
        assert answer.status_code == 401, headers
        assert answer.headers["www-authenticate"] == "Bearer"
        assert answer.json() == {"error": "unauthorized"}     # no reason in the answer
    assert spy.calls == 0


def test_tool_rejects_two_authorization_headers(keypair):
    private, public = keypair
    spy = ConnectSpy()
    app = tool_app("read_ticket", public, spy)
    good = mint_tool_token(private, "read_ticket", LEASE, NOW)

    async def two_headers():
        async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url="http://tool.test") as http:
            return await http.post(
                "/mcp", content=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
                headers=[("Authorization", f"Bearer {good}"), ("Authorization", f"Bearer {good}"),
                         ("Accept", "application/json, text/event-stream"), ("Content-Type", "application/json")],
            )

    assert run(two_headers()).status_code == 401


@pytest.mark.parametrize("method", ["GET", "DELETE"])
def test_every_method_needs_a_token(keypair, method):
    # The check is on the whole app, not on the POST route.
    _, public = keypair
    app = tool_app("read_ticket", public, ConnectSpy())

    async def call():
        async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url="http://tool.test") as http:
            return await http.request(method, "/mcp")

    assert run(call()).status_code == 401


def test_tool_rejects_other_paths_without_a_token(keypair):
    _, public = keypair
    app = tool_app("read_ticket", public, ConnectSpy())

    async def call():
        async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url="http://tool.test") as http:
            return await http.get("/anything")

    assert run(call()).status_code == 401


def test_a_valid_token_reaches_the_tool_and_its_database(keypair):
    # The control for the refusals above: the same app, a good token, and the connection is asked for.
    private, public = keypair
    spy = ConnectSpy()
    app = tool_app("read_ticket", public, spy)

    async def call():
        auth = ToolTokenAuth(private, "read_ticket", LEASE, lambda: NOW)
        async with mcp_client(app, auth) as client:
            return await client.call_tool("read_ticket", {})

    result = run(call())
    assert result.is_error
    assert spy.calls == 1


def test_lease_comes_from_token_not_arguments(settings, admin, keypair):
    private, public = keypair
    mine, theirs = open_lease(admin, 1), open_lease(admin, 2)    # tickets 1 (Eleni) and 2 (Nikos)

    async def call(args):
        auth = ToolTokenAuth(private, "lookup_account", mine, time.time)
        async with mcp_client(serve.build_app("lookup_account", settings, public), auth) as client:
            return await client.call_tool("lookup_account", args)

    # The token carries ticket 1's lease. Arguments named lease, ticket_id or customer_id are not
    # parameters of the tool: they change nothing, even when they hold a live lease of ticket 2.
    for forged in ({}, {"lease": theirs}, {"ticket_id": 2}, {"lease": theirs, "ticket_id": 2, "customer_id": 1002}):
        result = run(call(forged))
        assert not result.is_error, forged
        text = result.content[0].text
        assert json.loads(text)["name"] == "Eleni Papadopoulou", forged
        assert "Nikos" not in text


def test_lease_in_the_token_is_what_the_database_checks(settings, admin, keypair):
    # A token with a lease nobody opened gets "lease invalid" from the database and nothing else.
    private, public = keypair
    gateway = AppToolGateway(settings, private, public, tools=("read_ticket",))
    out = gateway.call("read_ticket", {"lease": "0" * 64})
    assert out.startswith("ERROR:") and "lease invalid" in out
    assert "PL/pgSQL" not in out


def test_the_tool_has_no_lease_or_ticket_parameter():
    # The schema the model's calls are checked against: no way to name a lease or a ticket.
    for tool in serve.TOOLS:
        server = serve.build_server(tool, dataclasses.replace(config.load(), vulnerable=False))
        (descriptor,) = asyncio.run(server.list_tools())
        properties = set(descriptor.input_schema.get("properties", {}))
        assert not properties & {"lease", "ticket_id", "ticket", "customer_id", "account_id"}, tool


def test_a_tool_without_a_verified_token_has_no_lease(settings):
    # The server on its own (no middleware in front, so nothing verified a token): fail closed.
    spy = ConnectSpy()
    server = serve.build_server("read_ticket", settings, connect=spy)

    async def call():
        async with Client(server) as client:
            return await client.call_tool("read_ticket", {})

    result = run(call())
    assert result.is_error and "lease invalid" in result.content[0].text
    assert spy.calls == 0


def test_every_request_of_one_call_carries_a_fresh_token(settings, admin, keypair):
    # An MCP call is several HTTP requests; each is checked on its own and a token works once, so
    # the client must sign each request separately. One call over a replay-checking app proves it.
    private, public = keypair
    lease = open_lease(admin, 1)
    out = AppToolGateway(settings, private, public, tools=("read_ticket",)).call("read_ticket", {"lease": lease})
    assert json.loads(out)["ticket_id"] == 1


def test_the_lease_is_in_the_token_and_not_in_the_request(settings, admin, keypair):
    # What actually leaves the agent's tool client: a token per request, carrying the lease, and
    # nothing else that could be read as the lease (no header, no argument).
    private, public = keypair
    lease = open_lease(admin, 1)
    gateway = AppToolGateway(settings, private, public, tools=("lookup_account",))
    answer = json.loads(gateway.call("lookup_account", {"lease": lease}))
    assert answer["name"] == "Eleni Papadopoulou"
    assert len(gateway.sent) >= 2          # the handshake and the call are separate requests
    tokens = []
    for headers, body in gateway.sent:
        assert lease.encode() not in body and b'"lease"' not in body
        assert lease not in "".join(headers.values())
        tokens.append(headers["authorization"].removeprefix("Bearer "))
    assert len(set(tokens)) == len(tokens)
    for token in tokens:
        claims = jwt.decode(token, options={"verify_signature": False})
        assert (claims["lease"], claims["aud"]) == (lease, "lookup_account")


def test_a_gateway_without_a_key_cannot_call_a_tool(settings, admin, keypair):
    # The control that the 401 is what stops an unsigned caller: same app, no key.
    _, public = keypair
    lease = open_lease(admin, 1)
    keyless = AppToolGateway(settings, b"", public, tools=("read_ticket",))
    assert keyless.call("read_ticket", {"lease": lease}).startswith("ERROR:")
