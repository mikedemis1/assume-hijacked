"""Case 11 (CI part): reach a tool directly, or replay a token (ASI03).

Wall: the tool-gateway signs a token for each call (one audience, 60 seconds, used once). The network half
of case 11 is in tests/k8s (chart render and live probes).
"""

import json
import logging


from app.security.tokens import mint_tool_token
from tests.toolhttp import bearer, CALL_READ_TICKET, ConnectSpy, keypair, MCP_HEADERS, post_each  # noqa: F401
from tests.unit.test_tokens import LEASE, NOW, run, tool_app


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


