"""Calls the tools, through the tool gateway and nowhere else.

The agent has one edge, to the gateway. It sends the lease in the header `X-Lease` (the lease travels
in the arguments dict from the agent code to here, see app/agent/core.py, and leaves it again: it is
never an MCP argument, and the model never sees it). In Kubernetes it also sends its projected
service account token, which the gateway checks with a TokenReview.

The agent holds no key of any kind. What it gets back is a result, or `ERROR: <category>` from a
fixed list (app/common/toolerrors.py): the gateway does not say why a call was refused.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import asynccontextmanager

import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from app.common import toolerrors

# One call to the gateway, from the first request to the answer. A gateway that hangs is an answer too.
TIMEOUT_S = 60.0
LEASE_HEADER = "X-Lease"


class ToolGateway:
    def __init__(
        self,
        url: str,
        headers: Callable[[], Mapping[str, str]] | None = None,
        timeout_s: float = TIMEOUT_S,
    ):
        self._url = url
        self._headers = headers or dict
        self._timeout_s = timeout_s

    def call(self, name: str, args: dict) -> str:
        args = dict(args)
        lease = args.pop("lease", None)
        try:
            return asyncio.run(self._call(name, args, lease))
        except Exception:
            # A gateway that is down or unreachable is an answer, not a crash of the agent.
            return toolerrors.error_text(toolerrors.UNAVAILABLE)

    async def _call(self, name: str, args: dict, lease: str | None) -> str:
        # The callback supplies caller authentication only. The agent owns the lease header,
        # whose name is case-insensitive on the wire.
        headers = {key: value for key, value in self._headers().items()
                   if key.lower() != LEASE_HEADER.lower()}
        if lease:
            headers[LEASE_HEADER] = lease  # last, so nothing else can replace it
        async with self._transport() as transport:
            async with httpx2.AsyncClient(
                headers=headers, timeout=httpx2.Timeout(self._timeout_s), transport=transport
            ) as http:
                async with Client(streamable_http_client(self._url, http_client=http)) as client:
                    result = await client.call_tool(name, args)
        texts = [block.text for block in result.content if hasattr(block, "text")]
        if result.is_error:
            # Only the gateway's own words are passed on. Anything else (a protocol error from the
            # MCP library, which can repeat the arguments) becomes a plain tool error.
            text = " ".join(texts)
            return text if toolerrors.category_of(text) else toolerrors.error_text(toolerrors.TOOL_ERROR)
        if result.structured_content is not None:
            return json.dumps(result.structured_content, ensure_ascii=False)
        return " ".join(texts)

    @asynccontextmanager
    async def _transport(self) -> AsyncIterator[httpx2.AsyncBaseTransport | None]:
        """How requests leave the process: the network (None). A test serves the gateway from
        inside the process instead."""
        yield None
