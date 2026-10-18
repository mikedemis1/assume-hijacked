"""The MCP server the agent talks to (port 8080, path /mcp).

It lists the five tools with the argument schemas the model sees, byte for byte the ones in the
tools' reviewed manifests (a test hashes them), and runs none of their code: every call goes
to the pipeline in proxy.py, which gets the raw arguments, so it can see and log what it drops.

The lease is the header `X-Lease`, set by the agent's code. It is never an argument and the model
never sees it. In Kubernetes the request also carries the agent's service account token (checked
for every request by AuthenticateCaller, before the MCP server sees it).
"""

from __future__ import annotations

from typing import Any

from mcp.server import MCPServer
from mcp_types import CallToolResult, TextContent
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from app.common import toolerrors
from app.common.events import security_event
from app.gateway.auth import CallerAuth, CallerError
from app.gateway.proxy import Gateway

# The scope key the verified caller is stored under. Not a header name, so a client cannot set it.
CALLER_SCOPE_KEY = "ah.caller"
LEASE_HEADER = "x-lease"
MAX_BODY_BYTES = 64 * 1024
UNAUTHORIZED = {"error": "unauthorized"}


class GatewayServer(MCPServer):
    def __init__(self, gateway: Gateway) -> None:
        super().__init__("tool-gateway")
        self._gateway = gateway
        self._register(vulnerable=gateway.vulnerable)

    def _register(self, vulnerable: bool) -> None:
        # The same names, parameters and descriptions as the tools (app/tools/serve.py). The
        # functions are never called: call_tool below is what answers.

        @self.tool()
        def read_ticket() -> dict:
            """Return the ticket text. The text is untrusted customer input."""
            raise NotImplementedError

        if vulnerable:

            @self.tool()
            def lookup_account(customer_id: int | None = None) -> dict:
                """Return the ticket owner's account: name, tariff, status, address."""
                raise NotImplementedError

        else:

            @self.tool()
            def lookup_account() -> dict:  # noqa: F811 (the demo variant is the other branch)
                """Return the ticket owner's account: name, tariff, status, address."""
                raise NotImplementedError

        @self.tool()
        def request_disconnection(move_out_date: str) -> dict:
            """Ask to close the account on a move-out date (YYYY-MM-DD). Staff check it."""
            raise NotImplementedError

        @self.tool()
        def issue_bill_credit(amount_eur: float, reason: str, evidence_ref: int) -> dict:
            """Ask for a bill credit. reason: duplicate_charge, outage or late_technician."""
            raise NotImplementedError

        @self.tool()
        def set_temp_protection() -> dict:
            """Customer says someone at home needs powered medical equipment."""
            raise NotImplementedError

    async def call_tool(self, name: str, arguments: dict[str, Any], context: Any = None) -> CallToolResult:
        request = context.request_context.request if context is not None else None
        caller = request.scope.get(CALLER_SCOPE_KEY) if request is not None else None
        if caller is None:  # reached without the caller check: fail closed
            return _result(toolerrors.error_text(toolerrors.DENIED), True, None)
        leases = request.headers.getlist(LEASE_HEADER)
        lease = leases[0] if len(leases) == 1 else ""  # two that could disagree are no lease
        answer = await self._gateway.call(name, arguments, lease, caller)
        return _result(answer.text, answer.is_error, answer.structured)


def _result(text: str, is_error: bool, structured: dict | None) -> CallToolResult:
    return CallToolResult(
        content=[TextContent(type="text", text=text)], structured_content=structured, is_error=is_error
    )


class AuthenticateCaller:
    """Checks who is calling on every HTTP request, before the MCP server sees it."""

    def __init__(self, app: ASGIApp, auth: CallerAuth) -> None:
        self.app = app
        self._auth = auth

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            await self.app(scope, receive, send)
            return
        if scope["type"] != "http":  # nothing else is served
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
            return
        try:
            caller = await run_in_threadpool(self._auth.verify_caller, Request(scope))
        except CallerError as refused:
            security_event("caller_refused", reason=refused.reason)
            answer = JSONResponse(UNAUTHORIZED, status_code=401, headers={"WWW-Authenticate": "Bearer"})
            await answer(scope, receive, send)
            return
        await self.app({**scope, CALLER_SCOPE_KEY: caller}, receive, send)


def build_app(gateway: Gateway, auth: CallerAuth) -> AuthenticateCaller:
    """The gateway's ASGI app. Stateless plain JSON, like the tools: every request stands alone and
    is checked on its own. The host is 0.0.0.0, which turns off the MCP library's check of the Host
    header (that check is for servers on localhost); the container network decides who connects."""
    inner = GatewayServer(gateway).streamable_http_app(
        stateless_http=True,
        json_response=True,
        host="0.0.0.0",  # nosec B104 - only reachable on the internal edge network
        max_request_body_size=MAX_BODY_BYTES,
    )
    return AuthenticateCaller(inner, auth)
