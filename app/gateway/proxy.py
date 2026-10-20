"""Every tool call, from the agent to the tool and back.

The checks, in this order. The first one that says no ends the call, and the agent is told
`ERROR: <category>` (app/common/toolerrors.py) and nothing more:

    1. the tool is one of the five                         unknown_tool
    2. the lease is well formed and live                   lease
    3. the lease is bound to the calling pod               pod_mismatch
    4. the stop switch is off                              paused
    5. arguments the manifest does not list are dropped    (logged by name, never a reason to refuse)
    6. the risk engine allows it (POST /decide, 2 s)       the engine's reason, risk_unavailable,
                                                           risk_timeout
    7. the tool still has the description that was reviewed  descriptor_changed
    8. the tool gets a token that works once, for it alone, and answers

Every call that reaches step 2 leaves one row in tool_calls (names, categories and sha256(lease);
db/sql/05-lease.sql) and moves two counters (gateway_calls_total, gateway_denials_total). Neither
the logs, the metrics nor the rows hold an argument value or a lease.

Timing matters at step 6. The risk engine writes its verdict to the database before it answers.
If the gateway gives up waiting after 2 s, the engine may still have written "allow" (for an effect
tool that uses up the lease's one effect), so the call is recorded as `risk_timeout` and not as an
ordinary denial.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import threading
import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass

import httpx2
import psycopg
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from app.common import toolerrors
from app.common.events import security_event
from app.common.ops import Metrics
from app.gateway.auth import CallerIdentity
from app.gateway.manifest import ToolSpec
from app.security import descriptors
from app.security.client import ToolTokenAuth

# One call to a tool, from the first request to the answer. A tool that hangs is an answer too.
TOOL_TIMEOUT_S = 30.0
# The contract: the risk engine has 2 s, then the call is denied.
RISK_TIMEOUT_S = 2.0

OUTCOMES = ("ok", "tool_error", "denied", "unavailable", "risk_timeout")
# Why a call was refused. The engine's own reasons (app/risk/rules.py) are listed by name so each
# one is a series of its own; any other reason it may send later is counted as risk_other.
RISK_REASONS = ("paused", "lease", "tool_not_in_lease", "repeated_denials", "call_budget", "one_effect_per_ticket")
DENIAL_REASONS = (
    "lease", "pod_mismatch", "paused", "unknown_tool", "descriptor_changed", "db_unavailable",
    "risk_unavailable", "risk_timeout", "risk_other", *(r for r in RISK_REASONS if r not in ("lease", "paused")),
)
ERROR_STAGES = ("db", "record", "heartbeat")
UNKNOWN_TOOL = "unknown"  # the metric label for any tool name that is not one of the five

LEASE_FORMAT = re.compile(r"[0-9a-f]{64}")  # 32 random bytes as hex (open_lease, db/sql/05-lease.sql)
# Argument names come from the model, so they can carry any text. Log and store one only when it
# looks like an identifier; anything else (a sentence, health data, a forged log line) is "<invalid>".
SAFE_NAME = re.compile(r"[A-Za-z0-9_]{1,64}")
NAMES_LIMIT = 20
# What a tool says when its database function refuses the lease, and when it refuses the arguments
# (app/tools/common.py). The MCP library puts "Error executing tool <name>" in front of both.
_TOOL_ERROR = re.compile(
    r"Error executing tool \w+: (?:(?P<lease>lease invalid)|(?P<arg>invalid argument|\d+ validation errors? for ))"
)


def _name(value: object) -> str:
    return value if isinstance(value, str) and SAFE_NAME.fullmatch(value) else "<invalid>"


@dataclass(frozen=True)
class Answer:
    """What the agent gets back: a result, or `ERROR: <category>`."""

    is_error: bool
    text: str
    structured: dict | None = None


@dataclass(frozen=True)
class Verdict:
    decision: str  # allow | deny | pause
    reasons: tuple[str, ...]
    timed_out: bool = False


@dataclass(frozen=True)
class Scope:
    ticket_id: int
    allowed_tools: tuple[str, ...]
    bound_pod: str | None


# --- the risk engine ---

class RiskClient:
    """POST /decide. Anything but a clear 200 with decision "allow" is not an allow."""

    def __init__(self, url: str, timeout_s: float = RISK_TIMEOUT_S, transport: httpx2.AsyncBaseTransport | None = None):
        self._url = url.rstrip("/") + "/decide"
        self.timeout_s = timeout_s
        self._transport = transport

    async def decide(self, lease: str, tool: str) -> Verdict:
        try:
            async with asyncio.timeout(self.timeout_s):
                async with httpx2.AsyncClient(
                    transport=self._transport, timeout=httpx2.Timeout(self.timeout_s)
                ) as http:
                    answer = await http.post(self._url, json={"lease": lease, "tool": tool})
        except (TimeoutError, httpx2.TimeoutException) as err:
            # Never reached the engine (the connection was not made): an ordinary failure. Any
            # other timeout: the engine may have the request and may still answer it.
            if isinstance(err, httpx2.ConnectTimeout):
                return Verdict("deny", ("risk_unavailable",))
            return Verdict("deny", ("risk_timeout",), timed_out=True)
        except Exception:
            return Verdict("deny", ("risk_unavailable",))
        if answer.status_code != 200:
            return Verdict("deny", ("risk_unavailable",))
        try:
            body = answer.json()
        except ValueError:
            return Verdict("deny", ("risk_unavailable",))
        decision = body.get("decision") if isinstance(body, dict) else None
        reasons = body.get("reasons") if isinstance(body, dict) else None
        if decision not in ("allow", "deny", "pause") or not isinstance(reasons, list):
            return Verdict("deny", ("risk_unavailable",))
        return Verdict(decision, tuple(r for r in reasons if isinstance(r, str)))


# --- the tools ---

class ToolUnavailable(Exception):
    """The tool could not be reached or would not talk to the gateway (refused its token, broke
    the protocol). The class name only: the message may carry a URL or a lease."""


class DescriptorChanged(Exception):
    """The tool's live description is not the reviewed one."""


@dataclass(frozen=True)
class ToolReply:
    is_error: bool
    text: str
    structured: dict | None


class ToolClient:
    """Calls the tools over HTTP, signing each request with a token for that tool and lease.

    One MCP call is several HTTP requests (the handshake, the listing, the call, closing) and a
    tool accepts a token once, so every request is signed on its own (app/security/client.py)."""

    def __init__(
        self,
        targets: dict[str, str],
        signing_key: bytes,
        clock: Callable[[], float] = time.time,
        timeout_s: float = TOOL_TIMEOUT_S,
    ) -> None:
        self._targets = targets
        self._signing_key = signing_key
        self._clock = clock
        self._timeout_s = timeout_s

    @asynccontextmanager
    async def _transport(self, name: str) -> AsyncIterator[httpx2.AsyncBaseTransport | None]:
        """How requests to this tool leave the process: the network (None). A test serves the tool
        from inside the process instead."""
        yield None

    @asynccontextmanager
    async def _session(self, name: str, lease: str) -> AsyncIterator[Client]:
        auth = ToolTokenAuth(self._signing_key, name, lease, self._clock)
        async with self._transport(name) as transport:
            async with httpx2.AsyncClient(auth=auth, timeout=httpx2.Timeout(self._timeout_s), transport=transport) as http:
                async with Client(streamable_http_client(self._targets[name], http_client=http)) as client:
                    yield client

    @staticmethod
    async def _call(client: Client, tool: str, arguments: dict) -> ToolReply:
        result = await client.call_tool(tool, arguments)
        texts = [block.text for block in result.content if hasattr(block, "text")]
        return ToolReply(bool(result.is_error), " ".join(texts), result.structured_content)

    async def call_tool(self, tool: str, arguments: dict, lease: str) -> ToolReply:
        """Call the tool without looking at its description. The gateway never uses this."""
        try:
            async with self._session(tool, lease) as client:
                return await self._call(client, tool, arguments)
        except Exception as err:
            raise ToolUnavailable(type(err).__name__) from None

    async def invoke(self, tool: str, arguments: dict, lease: str, expected_sha256: str) -> ToolReply:
        """List the tool's description, compare its fingerprint with the reviewed one, and only
        then call it. The two requests share one session, so the description checked is the
        description of the server that is then called."""
        reply = None
        try:
            async with self._session(tool, lease) as client:
                listed = (await client.list_tools()).tools
                live = [descriptors.descriptor_sha256(descriptors.wire_entry(t)) for t in listed if t.name == tool]
                if live == [expected_sha256]:
                    reply = await self._call(client, tool, arguments)
        except Exception as err:
            raise ToolUnavailable(type(err).__name__) from None
        if reply is None:
            raise DescriptorChanged(tool)
        return reply


def reply_category(reply: ToolReply) -> str:
    """The category of a tool's error answer. Decided from the shape of the text and then thrown
    away: the text itself can repeat the arguments and never reaches the agent."""
    found = _TOOL_ERROR.match(reply.text)
    if found and found.group("lease"):
        return toolerrors.LEASE
    if found and found.group("arg"):
        return toolerrors.INVALID_ARGUMENT
    return toolerrors.TOOL_ERROR


# --- the database ---

class GatewayDb:
    """The gateway's one database connection (role `gateway`): the lease, the stop switch, the
    record of calls, the heartbeat. A lost connection fails the call in hand (it is denied) and the
    next call opens a new one, so a database restart needs no restart of the gateway."""

    def __init__(self, connect: Callable[[], psycopg.Connection]) -> None:
        self._connect = connect
        self._conn: psycopg.Connection | None = None
        self._lock = threading.Lock()

    def _use(self, work: Callable[[psycopg.Connection], object], retry: bool = False):
        with self._lock:
            for attempt in (0, 1):
                reused = self._conn is not None and not self._conn.closed
                if not reused:
                    self._conn = self._connect()
                try:
                    return work(self._conn)
                except psycopg.OperationalError:
                    self._drop()
                    # A read can be asked again on a fresh connection if the old one had gone
                    # stale; a write is not repeated (it may have been executed).
                    if not (retry and reused and attempt == 0):
                        raise

    def _drop(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:  # nosec B110 - closing a broken connection may fail; it is dropped anyway
                pass
            self._conn = None

    def check(self, lease: str) -> tuple[Scope | None, bool]:
        """The live lease's scope (None for an unknown, expired or revoked one) and whether every
        agent is paused. No switch row counts as paused: fail closed."""

        def work(conn):
            row = conn.execute(
                "SELECT ticket_id, allowed_tools, bound_pod FROM lease_scope(%s)", (lease,)
            ).fetchone()
            switch = conn.execute("SELECT paused FROM agent_control WHERE id = 1").fetchone()
            scope = None if row is None else Scope(row["ticket_id"], tuple(row["allowed_tools"]), row["bound_pod"])
            return scope, True if switch is None else bool(switch["paused"])

        return self._use(work, retry=True)

    def record(self, lease_hash: bytes, tool: str, arg_names: list[str], dropped: list[str], outcome: str, reason: str) -> None:
        self._use(lambda conn: conn.execute(
            "INSERT INTO tool_calls (lease_hash, tool, arg_names, dropped_args, outcome, reason) "
            "VALUES (%s, %s, %s, %s, %s, %s)",
            (lease_hash, tool, arg_names, dropped, outcome, reason),
        ))

    def beat(self) -> None:
        self._use(lambda conn: conn.execute("SELECT beat('tool-gateway')"), retry=True)

    def close(self) -> None:
        with self._lock:
            self._drop()


# --- the metrics ---

def init_metrics(metrics: Metrics, specs: dict[str, ToolSpec]) -> None:
    """Every series exists at 0 from the start, so a rate or an alert on one is not blind until the
    first event."""
    for tool in (*specs, UNKNOWN_TOOL):
        for outcome in OUTCOMES:
            metrics.inc("gateway_calls_total", {"tool": tool, "outcome": outcome}, by=0)
        for reason in DENIAL_REASONS:
            metrics.inc("gateway_denials_total", {"tool": tool, "reason": reason}, by=0)
    for stage in ERROR_STAGES:
        metrics.inc("gateway_errors_total", {"stage": stage}, by=0)


# --- the pipeline ---

class Gateway:
    def __init__(
        self,
        *,
        db: GatewayDb,
        risk,
        tools: ToolClient,
        specs: dict[str, ToolSpec],
        metrics: Metrics,
    ) -> None:
        self._db = db
        self._risk = risk
        self._tools = tools
        self._specs = specs
        self._metrics = metrics

    async def call(self, tool: str, arguments: object, lease: str, caller: CallerIdentity) -> Answer:
        spec = self._specs.get(tool) if isinstance(tool, str) else None
        label = tool if spec is not None else UNKNOWN_TOOL
        forwarded, dropped = self._split(spec, arguments)
        record = _Record(
            label, hashlib.sha256((lease if isinstance(lease, str) else "").encode()).digest(), sorted(forwarded), dropped
        )
        if dropped:
            security_event("dropped_args", tool=label, args=dropped)

        # 1, 2: a known tool and a lease of the right shape.
        if spec is None:
            return await self._refuse(record, "unknown_tool", toolerrors.DENIED)
        if not isinstance(lease, str) or not LEASE_FORMAT.fullmatch(lease):
            return await self._refuse(record, "lease", toolerrors.LEASE)
        try:
            scope, paused = await asyncio.to_thread(self._db.check, lease)
        except Exception as err:
            self._error("db", err, label)
            return await self._refuse(record, "db_unavailable", toolerrors.UNAVAILABLE, outcome="unavailable")
        if scope is None:
            return await self._refuse(record, "lease", toolerrors.LEASE)
        # 3: the pod the token was issued to must be the pod the lease is bound to.
        if scope.bound_pod != caller.pod:
            return await self._refuse(record, "pod_mismatch", toolerrors.DENIED)
        # 4: the stop switch.
        if paused:
            return await self._refuse(record, "paused", toolerrors.DENIED)

        # 6: the risk engine (5, the arguments, was settled above so the record names them).
        verdict = await self._risk.decide(lease, tool)
        if verdict.timed_out:
            return await self._refuse(record, "risk_timeout", toolerrors.DENIED, outcome="risk_timeout")
        if verdict.decision != "allow":
            reason = next((r for r in verdict.reasons if r in RISK_REASONS or r == "risk_unavailable"), "risk_other")
            category = toolerrors.LEASE if reason in ("lease", "tool_not_in_lease") else toolerrors.DENIED
            return await self._refuse(record, reason, category)

        # 7, 8: the description, then the call. The description is checked after /decide (cheaper
        # refusals first), so a tool that has drifted still spends the lease's one effect in the
        # engine's count before it is refused. That fails safe: the call is not made, the agent
        # may not try a second effect on this ticket, and the denial is recorded.
        try:
            reply = await self._tools.invoke(tool, forwarded, lease, spec.descriptor_sha256)
        except DescriptorChanged:
            return await self._refuse(record, "descriptor_changed", toolerrors.DENIED)
        except ToolUnavailable as err:
            security_event("gateway_tool_unavailable", tool=label, error=str(err))
            return await self._finish(
                record, "unavailable", "tool_unreachable", Answer(True, toolerrors.error_text(toolerrors.UNAVAILABLE))
            )
        if reply.is_error:
            category = reply_category(reply)
            security_event("gateway_tool_error", tool=label, category=category)
            return await self._finish(record, "tool_error", category, Answer(True, toolerrors.error_text(category)))
        text = json.dumps(reply.structured, ensure_ascii=False) if reply.structured is not None else reply.text
        return await self._finish(record, "ok", "", Answer(False, text, reply.structured))

    def _split(self, spec: ToolSpec | None, arguments: object) -> tuple[dict, list[str]]:
        """The arguments the manifest lists, and the names of the others. The agent's code already
        dropped them; this is the wall for a caller that is not the agent's code."""
        if spec is None or not isinstance(arguments, dict):
            return {}, []
        allowed = spec.args
        kept = {key: value for key, value in arguments.items() if key in allowed}
        dropped = sorted(_name(key) for key in arguments if key not in allowed)[:NAMES_LIMIT]
        return kept, dropped

    async def _refuse(self, record: _Record, reason: str, category: str, outcome: str = "denied") -> Answer:
        self._metrics.inc("gateway_denials_total", {"tool": record.tool, "reason": reason})
        security_event("gateway_denied", tool=record.tool, reason=reason)
        answer = Answer(True, toolerrors.error_text(category))
        return await self._finish(record, outcome, reason, answer)

    async def _finish(self, record: _Record, outcome: str, reason: str, answer: Answer) -> Answer:
        self._metrics.inc("gateway_calls_total", {"tool": record.tool, "outcome": outcome})
        try:
            await asyncio.to_thread(
                self._db.record, record.lease_hash, record.tool, record.arg_names, record.dropped, outcome, reason
            )
        except Exception as err:
            # The call is over: refusing to say so would not undo it. Counted and logged by class.
            self._error("record", err, record.tool)
            security_event("tool_call_not_recorded", tool=record.tool, outcome=outcome)
        return answer

    def _error(self, stage: str, exc: BaseException, tool: str) -> None:
        self._metrics.inc("gateway_errors_total", {"stage": stage})
        security_event("gateway_error", stage=stage, tool=tool, error=type(exc).__name__)


@dataclass(frozen=True)
class _Record:
    tool: str
    lease_hash: bytes
    arg_names: list[str]
    dropped: list[str]
