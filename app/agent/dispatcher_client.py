"""The agent's side of the dispatcher (app/dispatcher/main.py): ask for a ticket, send the reply.

POST /claim answers {"ticket_id", "lease"}, or 204 when there is nothing for this caller. POST /reply
takes the lease in the header `X-Lease` and the text in the body, and with it the names of what the
agent dropped (never a value): the dispatcher takes the ticket from the lease. In Kubernetes both calls carry the agent's projected service account
token for the audience `dispatcher`.

A failure is a `DispatcherError` with a category (unauthorized, unavailable, bad_answer, lease,
duplicate, bad_request) and nothing the other side said.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass

import httpx2

TIMEOUT_S = 15.0
LEASE_HEADER = "X-Lease"
LEASE_FORMAT = re.compile(r"[0-9a-f]{64}")


class DispatcherError(Exception):
    def __init__(self, category: str) -> None:
        super().__init__(category)
        self.category = category


@dataclass(frozen=True)
class Claim:
    ticket_id: int
    lease: str


class DispatcherClient:
    def __init__(
        self, url: str, headers: Callable[[], Mapping[str, str]] | None = None, timeout_s: float = TIMEOUT_S
    ) -> None:
        self._url = url.rstrip("/")
        self._headers = headers or dict
        self._timeout_s = timeout_s

    def claim(self) -> Claim | None:
        """The ticket this run is for and the lease it works under, or None if there is none."""
        response = self._call("/claim", None, None)
        if response.status_code == 204:
            return None
        if response.status_code != 200:
            raise DispatcherError(_category(response.status_code))
        try:
            data = response.json()
        except ValueError as err:
            raise DispatcherError("bad_answer") from err
        ticket, lease = (data.get("ticket_id"), data.get("lease")) if isinstance(data, dict) else (None, None)
        if (
            not isinstance(ticket, int) or isinstance(ticket, bool) or ticket < 1
            or not isinstance(lease, str) or not LEASE_FORMAT.fullmatch(lease)
        ):
            raise DispatcherError("bad_answer")
        return Claim(ticket, lease)

    def reply(self, lease: str, text: str, events: list[dict] | None = None) -> None:
        """Send the reply, and with it the events (names of what the agent dropped, see
        app/agent/core.py event_list), if there are any. Returns when the dispatcher has stored the
        reply; raises DispatcherError otherwise."""
        body: dict = {"text": text}
        if events:
            body["events"] = events
        response = self._call("/reply", lease, body)
        if response.status_code != 200:
            raise DispatcherError(_category(response.status_code))
        try:
            stored = response.json().get("stored")
        except (ValueError, AttributeError) as err:
            raise DispatcherError("bad_answer") from err
        if stored is not True:
            raise DispatcherError("bad_answer")

    def _call(self, path: str, lease: str | None, body: dict | None) -> httpx2.Response:
        try:
            return asyncio.run(self._post(path, lease, body))
        except Exception as err:
            raise DispatcherError("unavailable") from err

    async def _post(self, path: str, lease: str | None, body: dict | None) -> httpx2.Response:
        headers = {k: v for k, v in self._headers().items() if k.lower() != LEASE_HEADER.lower()}
        if lease is not None:
            headers[LEASE_HEADER] = lease  # the only one, whatever the callback sent
        async with self._transport() as transport:
            async with httpx2.AsyncClient(transport=transport, timeout=httpx2.Timeout(self._timeout_s)) as http:
                return await http.post(self._url + path, headers=headers, json=body)

    @asynccontextmanager
    async def _transport(self) -> AsyncIterator[httpx2.AsyncBaseTransport | None]:
        """How requests leave the process: the network (None). A test serves the dispatcher from
        inside the process instead."""
        yield None


def _category(status: int) -> str:
    return {401: "unauthorized", 403: "lease", 409: "duplicate", 400: "bad_request", 413: "bad_request"}.get(
        status, "unavailable"
    )
