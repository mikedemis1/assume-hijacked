"""Calls MCP tools. A target is a URL (Compose) or an MCPServer object (tests, in memory)."""

from __future__ import annotations

import asyncio
import json

from mcp import Client


class ToolGateway:
    def __init__(self, targets: dict[str, object]):
        self._targets = targets

    def call(self, name: str, args: dict) -> str:
        try:
            return asyncio.run(self._call(name, args))
        except Exception:
            # A tool that is down or unreachable is an answer, not a crash of the agent.
            return "ERROR: tool unavailable"

    async def _call(self, name: str, args: dict) -> str:
        async with Client(self._targets[name]) as client:
            result = await client.call_tool(name, args)
        texts = [block.text for block in result.content if hasattr(block, "text")]
        if result.is_error:
            return "ERROR: " + " ".join(texts)
        if result.structured_content is not None:
            return json.dumps(result.structured_content, ensure_ascii=False)
        return " ".join(texts)
