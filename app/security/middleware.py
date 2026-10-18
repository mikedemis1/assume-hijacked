"""Every request to a tool must carry a valid gateway token, checked before anything else runs.

This wraps the whole MCP app, so it covers every path and every method, not just POST /mcp. A
request without a good token gets 401 and a fixed body; the reason goes to the security log only
(a category, never the token). The lease inside a good token is put in the ASGI scope for the tool
function; nothing else can supply it (the request's headers and body cannot write to the scope).
"""

from __future__ import annotations

import time
from collections.abc import Callable

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from app.common.events import security_event
from app.security.tokens import JtiCache, TokenError, verify_tool_token

# The scope key the lease is stored under. Not a header name, so a client cannot set it.
LEASE_SCOPE_KEY = "ah.tool_token_lease"
UNAUTHORIZED = {"error": "unauthorized"}


def _bearer_token(scope: Scope) -> str | None:
    values = [value for name, value in scope["headers"] if name == b"authorization"]
    if len(values) != 1:  # none, or two that could disagree
        return None
    scheme, _, token = values[0].decode("latin-1").partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not token or " " in token:
        return None
    return token


class RequireToolToken:
    def __init__(
        self,
        app: ASGIApp,
        *,
        tool: str,
        public_pem: bytes,
        seen: JtiCache | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.app = app
        self._tool = tool
        self._public_pem = public_pem
        self._seen = seen if seen is not None else JtiCache()
        self._clock = clock

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            await self.app(scope, receive, send)
            return
        if scope["type"] != "http":  # nothing else is served
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
            return
        token = _bearer_token(scope)
        try:
            if token is None:
                raise TokenError("missing")
            claims = verify_tool_token(self._public_pem, token, self._tool, self._clock(), self._seen)
        except TokenError as refused:
            security_event("tool_token_refused", tool=self._tool, reason=refused.reason)
            answer = JSONResponse(UNAUTHORIZED, status_code=401, headers={"WWW-Authenticate": "Bearer"})
            await answer(scope, receive, send)
            return
        await self.app({**scope, LEASE_SCOPE_KEY: claims["lease"]}, receive, send)
