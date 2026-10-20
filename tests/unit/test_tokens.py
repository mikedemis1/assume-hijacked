"""The token the tool gateway signs for every tool call, and the check each tool makes before it
touches anything (app/security, app/tools/serve.py).

A tool trusts one thing: a short-lived ES256 token, minted for that tool alone, used once. The lease
(which names the ticket) travels inside it, so the model cannot choose the ticket by setting an
argument.
"""

import asyncio
import json
import logging
import time

import jwt

from app import config
from app.security.client import ToolTokenAuth
from app.security.tokens import JtiCache, mint_tool_token, verify_tool_token
from app.tools import serve
from tests.conftest import open_lease
from tests.toolhttp import CALL_READ_TICKET, MCP_HEADERS, AppToolCaller, ConnectSpy, bearer, keypair, mcp_client, post_each  # noqa: F401

NOW = 1_800_000_000.0
LEASE = "ab" * 32


def run(coro):
    return asyncio.run(coro)


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


# --- the tool: what it checks before it opens a database connection --------------------------

def tool_app(tool, public_pem, spy, *, settings=None, clock=lambda: NOW):
    return serve.build_app(tool, settings or config.load(), public_pem, connect=spy, clock=clock)


def test_lease_comes_from_token_not_arguments(settings, admin, keypair):
    private, public = keypair
    mine, theirs = open_lease(admin, 1), open_lease(admin, 2)    # tickets 1 (Eleni) and 2 (Nikos)

    async def call(args, token_lease):
        auth = ToolTokenAuth(private, "lookup_account", token_lease, time.time)
        async with mcp_client(serve.build_app("lookup_account", settings, public), auth) as client:
            return await client.call_tool("lookup_account", args)

    # The token carries ticket 1's lease. Arguments named lease, ticket_id or customer_id are not
    # parameters of the tool: they change nothing, even when they hold a live lease of ticket 2.
    for forged in ({}, {"lease": theirs}, {"ticket_id": 2}, {"lease": theirs, "ticket_id": 2, "customer_id": 1002}):
        result = run(call(forged, mine))
        assert not result.is_error, forged
        text = result.content[0].text
        assert json.loads(text)["name"] == "Eleni Papadopoulou", forged
        assert "Nikos" not in text
    # The control: the lease in the token is what picks the account. The same call, with ticket 2's
    # lease in the token and ticket 1's lease in the arguments, returns the other customer.
    result = run(call({"lease": mine, "ticket_id": 1}, theirs))
    assert not result.is_error
    assert json.loads(result.content[0].text)["name"] == "Nikos Georgiou"


def test_a_gateway_without_a_key_cannot_call_a_tool(settings, admin, keypair):
    # The control that the 401 is what stops an unsigned caller: same app, no key.
    _, public = keypair
    lease = open_lease(admin, 1)
    keyless = AppToolCaller(settings, b"", public, tools=("read_ticket",))
    assert keyless.call("read_ticket", {"lease": lease}).startswith("ERROR:")


def test_asi03_tool_rejects_wrong_audience_expired_and_replayed_tokens(keypair, caplog):  # noqa: F811
    private, public = keypair
    spy = ConnectSpy()
    app = tool_app("read_ticket", public, spy)
    caplog.set_level(logging.INFO, logger="assume_hijacked.security")

    wrong_audience = mint_tool_token(private, "lookup_account", LEASE, NOW)
    expired = mint_tool_token(private, "read_ticket", LEASE, NOW - 120)
    valid = mint_tool_token(private, "read_ticket", LEASE, NOW)

    # Every request is a read_ticket call, which asks for a database connection when it runs. The
    # valid token is the control: its call runs (the spy is asked once); each refused request
    # leaves the count where it was.
    sent = run(post_each(app, bearer(wrong_audience), bearer(expired), bearer(valid), bearer(valid),
                         body=CALL_READ_TICKET, spy=spy))
    assert [r.status_code for r, _ in sent] == [401, 401, 200, 401]
    assert [calls for _, calls in sent] == [0, 0, 1, 1]

    reasons = [json.loads(r.getMessage())["reason"] for r in caplog.records
               if r.name == "assume_hijacked.security"]
    assert reasons == ["audience", "expired", "replayed"]


def test_asi03_tool_rejects_a_call_without_a_token(keypair):  # noqa: F811
    private, public = keypair
    spy = ConnectSpy()
    app = tool_app("read_ticket", public, spy)
    refused = [
        MCP_HEADERS,                                              # no Authorization at all
        {**MCP_HEADERS, "Authorization": ""},
        {**MCP_HEADERS, "Authorization": "Bearer"},
        {**MCP_HEADERS, "Authorization": "Bearer "},
        {**MCP_HEADERS, "Authorization": "Basic dXNlcjpwYXNz"},
        {**MCP_HEADERS, "Authorization": "Bearer not.a.token"},
        {**MCP_HEADERS, "Authorization": "Bearer " + "a" * 5000},
    ]
    control = bearer(mint_tool_token(private, "read_ticket", LEASE, NOW))
    sent = run(post_each(app, *refused, control, body=CALL_READ_TICKET, spy=spy))
    for (answer, calls), headers in zip(sent[:-1], refused):
        assert answer.status_code == 401, headers
        assert answer.headers["www-authenticate"] == "Bearer"
        assert answer.json() == {"error": "unauthorized"}     # no reason in the answer
        assert calls == 0, headers
    # The control: a good token on the same call reaches the database connection.
    assert sent[-1][0].status_code == 200 and sent[-1][1] == 1
