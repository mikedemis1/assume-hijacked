"""The tool gateway (app/gateway): the only way from the agent to a tool.

Every call is checked in this order, and the first wall that says no ends it:
the caller (Kubernetes token), the lease, the bound pod, the stop switch, the arguments the manifest
allows, the risk engine, the tool's description, and then the tool itself, which gets a token that
works once. The agent is told `ERROR: <category>` and never why.

Tests run the real pipeline on the test database as the `gateway` role, with the tools as apps in
this process (tests/gatewayharness.py). The risk engine is a stand-in unless a test says otherwise.
"""

import asyncio
import json
from datetime import datetime, timedelta, timezone

import httpx2
import psycopg
import pytest

from app.gateway.auth import CallerAuth, Review
from app.gateway.server import build_app
from app.tools import serve
from tests.conftest import open_lease
from tests.gatewayharness import AGENT_IP, AGENT_RAW_HEADERS, RealRisk, agent_auth, agent_lease, build
from tests.toolhttp import KEYS, running


def run(coro):
    return asyncio.run(coro)


def calls(admin):
    return admin.execute(
        "SELECT tool, arg_names, dropped_args, outcome, reason, actor, lease_hash FROM tool_calls ORDER BY id"
    ).fetchall()


def metric(built, name, **labels):
    """The value of one series in the gateway's metrics text, 0 if there is none."""
    wanted = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
    for line in built.metrics.render().splitlines():
        if line.startswith(f"{name}{{{wanted}}} "):
            return float(line.rsplit(" ", 1)[1])
    return None


def tomorrow():
    return (datetime.now(timezone.utc).date() + timedelta(days=1)).isoformat()


def only_read(admin, ticket=1):
    return open_lease(admin, ticket, tools=("read_ticket",))


# --- 1. the risk engine: no answer is a no ---


class DownTransport(httpx2.AsyncBaseTransport):
    """A peer that is down: the connection fails the way a refused TCP connection does."""

    async def handle_async_request(self, request):
        raise httpx2.ConnectError("connection refused")


# --- 2. the lease ---


def test_a_tool_that_is_not_in_the_lease_is_a_lease_error_and_the_risk_engine_counts_it(settings, admin, as_role):
    lease = only_read(admin)
    risk = RealRisk(settings)
    try:
        built = build(settings, as_role, risk=risk)
        answer = built.call("issue_bill_credit", {"amount_eur": 5, "reason": "outage", "evidence_ref": 1}, lease)
        assert answer.text == "ERROR: lease"
        assert built.tools.forwarded() == []
        assert metric(built, "gateway_denials_total", tool="issue_bill_credit", reason="tool_not_in_lease") == 1
        # The risk engine saw the denial (it counts them toward pausing a runaway run).
        assert admin.execute("SELECT decision, reasons FROM call_assessments").fetchall() == [
            {"decision": "deny", "reasons": ["tool_not_in_lease"]}
        ]
        assert built.call("read_ticket", {}, lease).is_error is False        # the control
    finally:
        risk.close()


# --- 3. the bound pod (Kubernetes) ---


AGENT_USER = "system:serviceaccount:ah-agent:agent"


def reviewer(tokens):
    """A TokenReview stand-in: token -> (user, pod). Records the audience it was asked for."""
    asked = []

    def review(token, audience):
        asked.append((token, audience))
        found = tokens.get(token)
        return Review(username=found[0], pod=found[1]) if found else None

    review.asked = asked
    return review


async def post_raw(app, headers, body=None, client=(AGENT_IP, 50000)):
    async with running(app):
        async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app, client=client), base_url="http://gateway.test") as http:
            return await http.post(
                "/mcp", headers=headers, content=json.dumps(body or {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
            )


MCP_HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


async def asgi_post(app, raw_headers, body, client=AGENT_IP):
    """POST /mcp straight to the ASGI app with exactly these header lines (a client library would
    not send the same header twice), from the address `client`. Returns (status, body bytes)."""
    sent, chunks = {}, []
    payload = json.dumps(body).encode()

    async def receive():
        return {"type": "http.request", "body": payload, "more_body": False}

    async def send(message):
        if message["type"] == "http.response.start":
            sent["status"] = message["status"]
        elif message["type"] == "http.response.body":
            chunks.append(message.get("body", b""))

    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST", "path": "/mcp",
        "raw_path": b"/mcp", "query_string": b"", "scheme": "http", "server": ("g.test", 80), "client": (client, 50000) if client else None,
        "headers": [(b"host", b"g.test"), (b"content-length", str(len(payload)).encode()),
                    *[(k.lower().encode(), v.encode()) for k, v in MCP_HEADERS.items()], *raw_headers],
    }
    async with running(app):
        await app(scope, receive, send)
    return sent["status"], b"".join(chunks)


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": "Bearer unknown"},
        {"Authorization": "Bearer tok-other-user"},
        {"Authorization": "Bearer tok-no-pod"},
        {"Authorization": "Token tok-a"},
        {"Authorization": "Bearer"},
        {"Authorization": "Bearer tok-a extra"},
    ],
    ids=["none", "unknown-token", "other-service-account", "token-without-pod", "wrong-scheme", "empty", "two-words"],
)
def test_k8s_mode_answers_401_to_a_caller_that_is_not_the_agent(settings, admin, as_role, headers):
    review = reviewer({
        "tok-a": (AGENT_USER, "pod-a"),
        "tok-other-user": ("system:serviceaccount:ah-tools:tool-read-ticket", "pod-x"),
        "tok-no-pod": (AGENT_USER, None),
    })
    built = build(settings, as_role)
    app = build_app(built.gateway, CallerAuth(mode="k8s", reviewer=review))
    refused = run(post_raw(app, {**MCP_HEADERS, **headers}))
    assert refused.status_code == 401 and refused.json() == {"error": "unauthorized"}
    assert built.risk.asked == [] and built.tools.forwarded() == []
    # The control: the agent's token is let in (the request itself is then served).
    ok = run(post_raw(build_app(built.gateway, CallerAuth(mode="k8s", reviewer=review)), {**MCP_HEADERS, "Authorization": "Bearer tok-a"}))
    assert ok.status_code != 401


def test_call_without_token_is_refused(settings, admin, as_role):
    # Nothing but the caller check says "the agent": a request with a lease and no token is a 401
    # before the lease, the risk engine or any tool is looked at.
    lease = agent_lease(admin, 1)
    built = build(settings, as_role)
    call = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "read_ticket", "arguments": {}}}
    lease_only = [(b"x-lease", lease.encode())]
    refused = run(asgi_post(build_app(built.gateway, agent_auth()), lease_only, call))
    assert refused[0] == 401 and json.loads(refused[1]) == {"error": "unauthorized"}
    assert built.risk.asked == [] and built.tools.forwarded() == [] and calls(admin) == []
    # The control: the same call with the agent's token goes through every wall.
    served = run(asgi_post(build_app(built.gateway, agent_auth()), lease_only + AGENT_RAW_HEADERS, call))
    assert served[0] == 200 and json.loads(served[1])["result"]["isError"] is False


# --- 4. the arguments ---


def test_the_arguments_the_manifest_allows_are_forwarded(settings, admin, as_role):
    # The control for the drop: what the manifest lists goes through, in full, and is recorded by name.
    lease = open_lease(admin, 1)
    built = build(settings, as_role)
    day = tomorrow()
    answer = built.call("request_disconnection", {"move_out_date": day, "ticket_id": 2}, lease)
    assert json.loads(answer.text)["status"] == "submitted"
    assert built.tools.forwarded() == [("request_disconnection", {"move_out_date": day})]
    assert [(r["arg_names"], r["dropped_args"]) for r in calls(admin)] == [(["move_out_date"], ["ticket_id"])]
    row = admin.execute("SELECT kind, ticket_id FROM action_requests").fetchone()
    assert row == {"kind": "move_out", "ticket_id": 1}


# --- 5. the tool's description ---

def tampered(tool, settings, description):
    """The app of `tool` as a hijacked tool server would run it: same code, a changed description."""
    from app.security.middleware import RequireToolToken
    from app.security.tokens import JtiCache

    server = serve.build_server(tool, settings)
    server._tool_manager.get_tool(tool).description = description
    inner = server.streamable_http_app(stateless_http=True, json_response=True, host="0.0.0.0")
    return RequireToolToken(inner, tool=tool, public_pem=KEYS[1], seen=JtiCache())


# --- 9. the record and its walls (database) ---

def test_the_gateway_can_add_a_row_and_nothing_else(admin, as_role):
    conn = as_role("gateway")
    conn.execute(
        "INSERT INTO tool_calls (lease_hash, tool, arg_names, dropped_args, outcome, reason) "
        "VALUES (sha256('x'), 'read_ticket', '{}', '{}', 'ok', '')"
    )
    row = admin.execute("SELECT actor, created_at IS NOT NULL AS dated FROM tool_calls").fetchone()
    assert row == {"actor": "gateway", "dated": True}
    for statement in (
        "SELECT * FROM tool_calls",
        "UPDATE tool_calls SET outcome = 'ok'",
        "DELETE FROM tool_calls",
        "TRUNCATE tool_calls",
        "INSERT INTO tool_calls (lease_hash, tool, arg_names, dropped_args, outcome, reason, actor) "
        "VALUES (sha256('x'), 'read_ticket', '{}', '{}', 'ok', '', 'someone else')",
        "INSERT INTO tool_calls (lease_hash, tool, arg_names, dropped_args, outcome, created_at) "
        "VALUES (sha256('x'), 'read_ticket', '{}', '{}', 'ok', '2001-01-01')",
    ):
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute(statement)


# --- 10. the whole chain, with the real risk engine ---

def test_an_honest_ticket_goes_through_every_wall_and_each_wall_leaves_a_record(settings, admin, as_role):
    lease = open_lease(admin, 1)
    risk = RealRisk(settings)
    try:
        built = build(settings, as_role, risk=risk)
        assert json.loads(built.call("read_ticket", {}, lease).text)["ticket_id"] == 1
        assert json.loads(built.call("lookup_account", {}, lease).text)["name"] == "Eleni Papadopoulou"
        credit = built.call("issue_bill_credit", {"amount_eur": 5, "reason": "outage", "evidence_ref": 1}, lease)
        assert json.loads(credit.text)["status"] == "submitted"
        second = built.call("issue_bill_credit", {"amount_eur": 5, "reason": "outage", "evidence_ref": 1}, lease)
        assert second.text == "ERROR: denied"                 # one effect per lease, said by the engine
        assert metric(built, "gateway_denials_total", tool="issue_bill_credit", reason="one_effect_per_ticket") == 1
    finally:
        risk.close()
    assert [(r["tool"], r["outcome"], r["reason"]) for r in calls(admin)] == [
        ("read_ticket", "ok", ""), ("lookup_account", "ok", ""), ("issue_bill_credit", "ok", ""),
        ("issue_bill_credit", "denied", "one_effect_per_ticket"),
    ]
    assert admin.execute("SELECT count(*) AS n FROM action_requests").fetchone()["n"] == 1


def call_assessment_rows(admin):
    return admin.execute("SELECT * FROM call_assessments").fetchall()


