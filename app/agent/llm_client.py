"""The agent's way to a model: the LLM gateway, and nowhere else.

POST <LLM_GATEWAY_URL>/next with the conversation so far and the lease in the header `X-Lease`
(set by this class from the lease the dispatcher handed out; the model never sees it). In Kubernetes
the request also carries the agent's projected service account token for the audience `llm-gateway`
(app/common/calls.py auth_headers). The agent holds no model key and no model identity: the gateway
has them (app/llmgw), so a hijacked agent cannot read one.

The answer is a tool call or a reply, or an `LlmError` with a category and nothing else: what the
gateway or a provider said about a failure is not passed on.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import asynccontextmanager

import httpx2

from app.agent.llm import Reply, ToolCall

# One request, from the first byte to the answer. A model that is slow is an answer too.
TIMEOUT_S = 60.0
LEASE_HEADER = "X-Lease"
MAX_ANSWER_BYTES = 512 * 1024
MAX_NAME_CHARS = 200


class LlmError(Exception):
    """The model did not answer with a step. `category` is for the security log."""

    def __init__(self, category: str) -> None:
        super().__init__(category)
        self.category = category


# What the gateway's status codes mean to the agent.
_CATEGORY_BY_STATUS = {429: "budget", 401: "unauthorized", 400: "bad_request", 413: "bad_request"}


class LlmGatewayClient:
    def __init__(
        self,
        url: str,
        lease: str,
        headers: Callable[[], Mapping[str, str]] | None = None,
        timeout_s: float = TIMEOUT_S,
    ) -> None:
        self._url = url.rstrip("/") + "/next"
        self._lease = lease
        self._headers = headers or dict
        self._timeout_s = timeout_s

    def next_action(self, transcript: list[dict]) -> ToolCall | Reply:
        try:
            return asyncio.run(self._post(transcript))
        except LlmError:
            raise
        except Exception as err:
            # A gateway that is down, unreachable or slow is an answer, not a crash of the agent.
            raise LlmError("unavailable") from err

    async def _post(self, transcript: list[dict]) -> ToolCall | Reply:
        headers = {k: v for k, v in self._headers().items() if k.lower() != LEASE_HEADER.lower()}
        headers[LEASE_HEADER] = self._lease  # the only one, whatever the callback sent
        async with self._transport() as transport:
            async with httpx2.AsyncClient(transport=transport, timeout=httpx2.Timeout(self._timeout_s)) as http:
                response = await http.post(self._url, headers=headers, json={"transcript": transcript})
        if response.status_code != 200:
            raise LlmError(_CATEGORY_BY_STATUS.get(response.status_code, "unavailable"))
        if len(response.content) > MAX_ANSWER_BYTES:
            raise LlmError("bad_answer")
        return _step(response)

    @asynccontextmanager
    async def _transport(self) -> AsyncIterator[httpx2.AsyncBaseTransport | None]:
        """How requests leave the process: the network (None). A test serves the gateway from
        inside the process instead."""
        yield None


def _step(response: httpx2.Response) -> ToolCall | Reply:
    try:
        data = response.json()
    except ValueError as err:
        raise LlmError("bad_answer") from err
    if isinstance(data, dict) and data.get("type") == "reply" and isinstance(data.get("text"), str):
        return Reply(data["text"])
    if (
        isinstance(data, dict)
        and data.get("type") == "call"
        and isinstance(data.get("name"), str)
        and 0 < len(data["name"]) <= MAX_NAME_CHARS
        and isinstance(data.get("args"), dict)
    ):
        return ToolCall(data["name"], data["args"])
    raise LlmError("bad_answer")
