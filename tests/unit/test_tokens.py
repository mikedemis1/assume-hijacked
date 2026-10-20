"""The token the tool gateway signs for every tool call, and the check each tool makes before it
touches anything (app/security, app/tools/serve.py).

A tool trusts one thing: a short-lived ES256 token, minted for that tool alone, used once. The lease
(which names the ticket) travels inside it, so the model cannot choose the ticket by setting an
argument.
"""

import asyncio
import json
import time

import jwt

from app import config
from app.security.client import ToolTokenAuth
from app.security.tokens import JtiCache, mint_tool_token, verify_tool_token
from app.tools import serve
from tests.conftest import open_lease
from tests.toolhttp import AppToolCaller, keypair, mcp_client

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
