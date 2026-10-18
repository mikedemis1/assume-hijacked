"""Calls the MCP tools over HTTP, signing each request with the lease's token.

The lease travels in the arguments dict from the agent code to here (the model never sets it, see
app/agent/core.py), and leaves it again: the tool is told the lease only through the signed token,
never as an argument. A tool without a good token answers 401, which comes back as "tool
unavailable".

The signing key stays with whoever signs for the tools. Until the tool gateway runs as its own
service, that is this client; it is the only component that holds the key.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager

import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from app.security.client import ToolTokenAuth

# One call to a tool, from the first request to the answer. A tool that hangs is an answer too.
TIMEOUT_S = 30.0


class ToolGateway:
    def __init__(
        self,
        targets: dict[str, str],
        signing_key: bytes | None = None,
        clock: Callable[[], float] = time.time,
    ):
        self._targets = targets
        self._signing_key = signing_key
        self._clock = clock

    def call(self, name: str, args: dict) -> str:
        args = dict(args)
        lease = args.pop("lease", None)
        try:
            return asyncio.run(self._call(name, args, lease))
        except Exception:
            # A tool that is down, unreachable or that refuses the token is an answer, not a
            # crash of the agent.
            return "ERROR: tool unavailable"

    async def _call(self, name: str, args: dict, lease: str | None) -> str:
        async with self._connect(name, lease) as client:
            result = await client.call_tool(name, args)
        texts = [block.text for block in result.content if hasattr(block, "text")]
        if result.is_error:
            return "ERROR: " + " ".join(texts)
        if result.structured_content is not None:
            return json.dumps(result.structured_content, ensure_ascii=False)
        return " ".join(texts)

    @asynccontextmanager
    async def _transport(self, name: str) -> AsyncIterator[httpx2.AsyncBaseTransport | None]:
        """How requests to this tool leave the process: the network (None). A test serves the tool
        from inside the process instead."""
        yield None

    @asynccontextmanager
    async def _connect(self, name: str, lease: str | None) -> AsyncIterator[Client]:
        # Without a key or a lease there is nothing to sign: the request goes out unsigned and the
        # tool refuses it.
        auth = None
        if self._signing_key and lease:
            auth = ToolTokenAuth(self._signing_key, name, lease, self._clock)
        async with self._transport(name) as transport:
            async with httpx2.AsyncClient(auth=auth, timeout=httpx2.Timeout(TIMEOUT_S), transport=transport) as http:
                async with Client(streamable_http_client(self._targets[name], http_client=http)) as client:
                    yield client
