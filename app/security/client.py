"""The calling side: sign every HTTP request to a tool with its own fresh token."""

from __future__ import annotations

import time
from collections.abc import Callable, Generator

import httpx2

from app.security.tokens import mint_tool_token


class ToolTokenAuth(httpx2.Auth):
    """Adds `Authorization: Bearer <token>` to each request, a new token each time.

    One MCP call is several HTTP requests (the handshake, the call, closing), and a tool accepts a
    token once, so a token cannot be set once on the client."""

    def __init__(
        self, private_pem: bytes, tool: str, lease: str, clock: Callable[[], float] = time.time
    ) -> None:
        self._private_pem = private_pem
        self._tool = tool
        self._lease = lease
        self._clock = clock

    def auth_flow(self, request: httpx2.Request) -> Generator[httpx2.Request, httpx2.Response, None]:
        token = mint_tool_token(self._private_pem, self._tool, self._lease, self._clock())
        request.headers["Authorization"] = f"Bearer {token}"
        yield request
