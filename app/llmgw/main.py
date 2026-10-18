"""python -m app.llmgw.main: the LLM gateway. The agent's only way to a model.

    8083  POST /next    (this file)
    9000  /healthz /metrics   (app/common/ops.py)

The agent holds no model key and no model identity. This is the one place that does (the provider
key file, or the pod's workload identity), so a hijacked agent can neither read a credential nor
send a request the gateway did not build.

POST /next
    Request   header `X-Lease: <the lease, 64 hex>` (exactly one); body JSON
              {"transcript": [{"role": "ticket", "text": "..."},
                              {"role": "tool", "name": "...", "args": {...}, "result": "..."}, ...]},
              at most 256 KiB, 40 items. In Kubernetes also `Authorization: Bearer <projected service
              account token, audience llm-gateway>`.
    200       {"type": "call", "name": "<tool>", "args": {...}}   or   {"type": "reply", "text": "..."}
    400       {"error": "bad_request"}   not a conversation of that shape, or no usable lease header
    401       {"error": "unauthorized"}  the caller is not an agent (see below)
    413       {"error": "too_large"}
    429       {"error": "budget"}        a lease, pod, address or total budget is exhausted
    502       {"error": "upstream"}      the model could not answer; nothing of what it said is passed on

What the gateway does not do: it does not know whether a lease is live (it has no database role; the
tool gateway and the dispatcher do that). So a lease alone cannot be trusted as the unit of spending:
a caller that sends a new random lease with every request would get a new budget each time. Every call
is therefore charged to four keys at once, and has to fit all of them:
    lease    LLM_TOKEN_BUDGET_PER_LEASE (default 20000)
    pod      the same limit, Kubernetes only (a pod has one lease for its life)
    address  the caller's source address, 5 times the per-lease limit
    total    LLM_TOKEN_BUDGET_TOTAL (default 500000), all callers together
Each key is a window of 15 minutes (the life of a lease) from its first spend; then it is forgotten. A
call is charged at least MIN_CALL_TOKENS or one thousandth of the address limit, whichever is greater.
Even a provider reporting a tiny usage cannot reduce that charge. A flood of new lease strings from
one address therefore stops after at most a thousand keys, leaving room for other addresses. The table
has a hard size limit as well and refuses a key it does not know when it is full.

Who may call. Compose: the connection's source address must be inside CALLER_SUBNET, the subnet
pinned on the agent's edge network (the same check as the tool gateway's and the dispatcher's).
Kubernetes: the projected token is checked with a TokenReview for the audience `llm-gateway`; it must
belong to the service account ah-agent/agent and name a pod. Anything else, or any failure of the
check, is a 401 before the request is read.

The caller's credentials never travel on: the request to the provider is built in
app/llmgw/backends.py from the gateway's own key or token, and a header of the agent's (x-api-key,
authorization, or any other) is not copied into it.

Environment: LLM_BACKEND (scripted|anthropic|foundry, default scripted), LLM_MODEL (default
claude-haiku-5-5), LLM_TOKEN_BUDGET_PER_LEASE (default 20000), LLM_TOKEN_BUDGET_TOTAL (default 500000), ANTHROPIC_API_KEY_FILE, FOUNDRY_ENDPOINT
and the workload identity variables, CALLER_AUTH (compose|k8s), CALLER_SUBNET (compose).
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass

import uvicorn
from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

from app.common import calls
from app.common.events import security_event
from app.common.ops import Heartbeat, Metrics, start_ops_server
from app.gateway.auth import CallerAuth, CallerError
from app.llmgw import backends
from app.llmgw.backends import BackendError, Step, estimate_tokens

PORT = 8083
BIND_ALL = "0.0.0.0"  # nosec B104 - only reachable on the agent's edge network; see main()
OPS_PORT = 9000
AUDIENCE = "llm-gateway"
CALLER_SCOPE_KEY = "ah.caller"  # not a header name, so a client cannot set it
LEASE_HEADER = "x-lease"
LEASE_FORMAT = re.compile(r"[0-9a-f]{64}")
MAX_BODY_BYTES = 256 * 1024
MAX_ITEMS = 40
MAX_TEXT_CHARS = 20_000
MAX_NAME_CHARS = 64
DEFAULT_BUDGET = 20_000
MAX_BUDGET = 10_000_000
MAX_BUDGET_KEYS = 10_000
DEFAULT_TOTAL = 500_000
MAX_TOTAL = 1_000_000_000
ADDRESS_FACTOR = 5
WINDOW_S = 15 * 60  # the life of a lease
MIN_CALL_TOKENS = 100  # what one call costs at the least, whatever its estimate
UNAUTHORIZED = {"error": "unauthorized"}

REQUEST_OUTCOMES = ("ok", "budget", "bad_request", "too_large", "upstream")
REFUSAL_REASONS = (
    "wrong_network", "missing", "malformed", "review_failed", "not_authenticated", "wrong_service_account", "no_pod",
)
UPSTREAM_CATEGORIES = ("status_2xx", "status_3xx", "status_4xx", "status_5xx", "unreachable", "too_large", "bad_answer", "no_credential",
                       "token_unreachable", "token_refused", "token_bad_answer", "other")


def init_metrics(metrics: Metrics) -> None:
    """Every series exists at 0 from the start, so a rate or an alert on one is not blind."""
    for outcome in REQUEST_OUTCOMES:
        metrics.inc("llmgw_requests_total", {"outcome": outcome}, by=0)
    for reason in REFUSAL_REASONS:
        metrics.inc("llmgw_callers_refused_total", {"reason": reason}, by=0)
    for category in UPSTREAM_CATEGORIES:
        metrics.inc("llmgw_upstream_errors_total", {"category": category}, by=0)
    metrics.inc("llmgw_tokens_total", by=0)


@dataclass
class _Spending:
    tokens: int
    started: float


@dataclass(frozen=True)
class _Reservation:
    entries: tuple[tuple[str, _Spending], ...]
    tokens: int


BudgetKeys = list[str | tuple[str, int]]


class Budget:
    """Tokens spent, per key, in a window. A call reserves its estimated input first and settles to what
    it really cost; a call that does not fit any one of its keys reserves nothing, on any key. A key is
    forgotten WINDOW_S after its first spend (its spending starts again from 0). A table that is full,
    after the forgotten keys are dropped, refuses a key it does not know: a gateway that forgot keys it
    still needs would give out fresh budgets.

    A key is a name, charged against the default limit, or a (name, limit) pair."""

    def __init__(
        self,
        limit: int,
        max_keys: int = MAX_BUDGET_KEYS,
        *,
        window_s: float = WINDOW_S,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.limit, self._max_keys, self._window_s, self._clock = limit, max_keys, window_s, clock
        self._used: dict[str, _Spending] = {}
        self._lock = threading.Lock()

    def _pairs(self, keys: BudgetKeys) -> list[tuple[str, int]]:
        return [(k, self.limit) if isinstance(k, str) else (k[0], k[1]) for k in keys]

    def _drop_old(self, now: float) -> None:
        for name in [n for n, entry in self._used.items() if now - entry.started >= self._window_s]:
            del self._used[name]

    def reserve(self, keys: BudgetKeys, tokens: int) -> _Reservation | None:
        pairs = self._pairs(keys)
        with self._lock:
            now = self._clock()
            self._drop_old(now)
            if len(self._used) + len([n for n, _ in pairs if n not in self._used]) > self._max_keys:
                return None
            if any((self._used[n].tokens if n in self._used else 0) + tokens > limit for n, limit in pairs):
                return None
            for name, _ in pairs:
                entry = self._used.setdefault(name, _Spending(0, now))
                entry.tokens += tokens
            return _Reservation(tuple((name, self._used[name]) for name, _ in pairs), tokens)

    def settle(self, reservation: _Reservation, actual: int) -> None:
        with self._lock:
            for name, entry in reservation.entries:
                # An old response must never refund or charge a replacement window with the same name.
                if self._used.get(name) is entry:
                    entry.tokens = max(0, entry.tokens + actual - reservation.tokens)


class LlmGateway:
    """The rules, without HTTP."""

    def __init__(self, backend, budget: Budget, metrics: Metrics, *, total_limit: int | None = None) -> None:
        self.backend, self.budget, self.metrics = backend, budget, metrics
        self._address_limit = budget.limit * ADDRESS_FACTOR
        self._total_limit = total_limit if total_limit is not None else budget.limit * ADDRESS_FACTOR * 10
        # Bound the number of new lease keys one address can buy, even with a large token limit.
        self._minimum_charge = max(MIN_CALL_TOKENS, (self._address_limit + 999) // 1000)

    async def next(self, caller: Caller, lease: str, transcript: list[dict]) -> tuple[int, dict]:
        # The lease cannot be checked here, so it is only one of four keys (see the module docstring).
        keys = [
            f"lease:{lease}",
            (f"addr:{getattr(caller, 'address', None) or 'unknown'}", self._address_limit),
            ("total", self._total_limit),
        ] + ([f"pod:{caller.pod}"] if caller.pod else [])
        reserved = max(estimate_tokens(transcript), self._minimum_charge)
        reservation = self.budget.reserve(keys, reserved)
        if reservation is None:
            return self._done(429, "budget", {"error": "budget"})
        try:
            step = await self.backend.next(transcript)
            answer = _answer_of(step)
        except BackendError as err:
            category = err.category if err.category in UPSTREAM_CATEGORIES else "other"
            self.metrics.inc("llmgw_upstream_errors_total", {"category": category})
            security_event("llm_upstream_error", category=category)
            return self._done(502, "upstream", {"error": "upstream"})
        except Exception as err:  # a backend that breaks is "no answer", never a traceback to the agent
            self.metrics.inc("llmgw_upstream_errors_total", {"category": "other"})
            security_event("llm_upstream_error", category="other", error=type(err).__name__)
            return self._done(502, "upstream", {"error": "upstream"})
        spent = max(self._minimum_charge, step.tokens if step.tokens > 0 else reserved + estimate_tokens(answer))
        self.budget.settle(reservation, spent)
        self.metrics.inc("llmgw_tokens_total", by=spent)
        return self._done(200, "ok", answer)

    def _done(self, status: int, outcome: str, body: dict) -> tuple[int, dict]:
        self.metrics.inc("llmgw_requests_total", {"outcome": outcome})
        return status, body


def _answer_of(step: Step) -> dict:
    """What goes back to the agent, or BackendError for a step that is neither a tool call nor a reply."""
    if step.kind == "call":
        if not isinstance(step.name, str) or not step.name or not isinstance(step.args, dict):
            raise BackendError("bad_answer")
        return {"type": "call", "name": step.name, "args": step.args}
    if step.kind == "reply":
        if not isinstance(step.text, str):
            raise BackendError("bad_answer")
        return {"type": "reply", "text": step.text[: backends.MAX_REPLY_CHARS]}
    raise BackendError("bad_answer")


def _clean_transcript(data) -> list[dict] | None:
    """The conversation with only the fields the backends read, or None if it is not one."""
    items = data.get("transcript") if isinstance(data, dict) else None
    if not isinstance(items, list) or not 1 <= len(items) <= MAX_ITEMS:
        return None
    clean: list[dict] = []
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            return None
        if index == 0:
            if item.get("role") != "ticket" or not _text(item.get("text")):
                return None
            clean.append({"role": "ticket", "text": item["text"]})
            continue
        args = item.get("args", {})
        if (item.get("role") != "tool" or not isinstance(item.get("name"), str) or not item["name"]
                or len(item["name"]) > MAX_NAME_CHARS or not isinstance(item.get("result"), str)
                or len(item["result"]) > MAX_TEXT_CHARS or not isinstance(args, dict)):
            return None
        clean.append({"role": "tool", "name": item["name"], "args": args, "result": item["result"]})
    return clean


def _text(value) -> bool:
    return isinstance(value, str) and len(value) <= MAX_TEXT_CHARS


# --- HTTP ---


@dataclass(frozen=True)
class Caller:
    """Who called: the pod (Kubernetes) and the connection's source address (the budget's key)."""

    pod: str | None
    address: str | None


class AuthenticateCaller:
    """Checks who is calling on every HTTP request, before any handler sees it."""

    def __init__(self, app: ASGIApp, auth: CallerAuth, metrics: Metrics | None = None) -> None:
        self.app, self._auth, self._metrics = app, auth, metrics

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
            if self._metrics is not None and refused.reason in REFUSAL_REASONS:
                self._metrics.inc("llmgw_callers_refused_total", {"reason": refused.reason})
            answer = JSONResponse(UNAUTHORIZED, status_code=401, headers={"WWW-Authenticate": "Bearer"})
            await answer(scope, receive, send)
            return
        client = scope.get("client")
        address = client[0] if client else None
        await self.app({**scope, CALLER_SCOPE_KEY: Caller(pod=caller.pod, address=address)}, receive, send)


async def _read_capped(request: Request, limit: int) -> bytes | None:
    """The body, or None if it is over `limit` (declared or actually sent)."""
    declared = request.headers.get("content-length")
    if declared is not None and (not declared.isdigit() or int(declared) > limit):
        return None
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > limit:
            return None
    return bytes(body)


def build_app(gateway: LlmGateway, auth: CallerAuth, metrics: Metrics | None = None) -> AuthenticateCaller:
    metrics = metrics or Metrics()

    def refuse(status: int, outcome: str, name: str) -> JSONResponse:
        metrics.inc("llmgw_requests_total", {"outcome": outcome})
        return JSONResponse({"error": name}, status_code=status)

    async def next_step(request: Request) -> Response:
        caller = request.scope[CALLER_SCOPE_KEY]
        leases = request.headers.getlist(LEASE_HEADER)
        lease = leases[0] if len(leases) == 1 else ""  # two that could disagree are no lease
        body = await _read_capped(request, MAX_BODY_BYTES)
        if body is None:
            return refuse(413, "too_large", "too_large")
        try:
            transcript = _clean_transcript(json.loads(body))
        except (ValueError, RecursionError):
            transcript = None
        if transcript is None or not LEASE_FORMAT.fullmatch(lease):
            return refuse(400, "bad_request", "bad_request")
        status, answer = await gateway.next(caller, lease, transcript)
        return JSONResponse(answer, status_code=status)

    inner = Starlette(routes=[Route("/next", next_step, methods=["POST"])])
    return AuthenticateCaller(inner, auth, metrics)


# --- the process ---


def caller_auth(mode: str, subnet: str | None, reviewer=None) -> CallerAuth:
    """Who may call: the service account ah-agent/agent with a token for the audience `llm-gateway`
    (Kubernetes), or an address in the agent's subnet (Compose). Raises ValueError, in Compose, if
    there is no valid subnet: a gateway that would accept every caller does not start."""
    return CallerAuth(mode=mode, audience=AUDIENCE, allowed_subnet=subnet, reviewer=reviewer)


def _budget_limit(env: Mapping[str, str]) -> int:
    if "LLM_TOKEN_BUDGET_PER_LEASE" not in env:
        return DEFAULT_BUDGET
    raw = env["LLM_TOKEN_BUDGET_PER_LEASE"].strip()
    if not (raw.isascii() and raw.isdigit()) or not 1 <= int(raw) <= MAX_BUDGET:
        raise SystemExit(f"LLM_TOKEN_BUDGET_PER_LEASE must be a whole number from 1 to {MAX_BUDGET}, got {raw!r}")
    return int(raw)


def _total_limit(env: Mapping[str, str]) -> int:
    if "LLM_TOKEN_BUDGET_TOTAL" not in env:
        return DEFAULT_TOTAL
    raw = env["LLM_TOKEN_BUDGET_TOTAL"].strip()
    if not (raw.isascii() and raw.isdigit()) or not 1 <= int(raw) <= MAX_TOTAL:
        raise SystemExit(f"LLM_TOKEN_BUDGET_TOTAL must be a whole number from 1 to {MAX_TOTAL}, got {raw!r}")
    return int(raw)


def prepare(env: Mapping[str, str], *, transport=None, reviewer=None) -> tuple[LlmGateway, CallerAuth]:
    """Everything the process needs, or SystemExit saying what is missing: a gateway that cannot reach
    its model, or would let every caller in, does not start."""
    mode = calls.caller_auth_mode(env)
    try:
        auth = caller_auth(mode, env.get("CALLER_SUBNET") or None, reviewer)
    except ValueError as err:
        raise SystemExit(str(err)) from None
    limit, total = _budget_limit(env), _total_limit(env)
    try:
        backend = backends.make_backend(env, transport=transport)
    except BackendError as err:
        raise SystemExit(str(err)) from None
    metrics = Metrics()
    init_metrics(metrics)
    return LlmGateway(backend, Budget(limit), metrics, total_limit=total), auth


def main() -> None:
    gateway, auth = prepare(os.environ)
    heartbeat = Heartbeat()
    start_ops_server(OPS_PORT, gateway.metrics, heartbeat)
    threading.Thread(target=_beat, args=(heartbeat,), name="beat", daemon=True).start()
    app = build_app(gateway, auth, gateway.metrics)
    # All interfaces of the container: the agent reaches it from another container or pod. The
    # network and the caller check are the wall (edge_agent_llmgw in compose.yaml, NetworkPolicy and
    # TokenReview in Kubernetes); no access log: a request is a ticket and a conversation.
    # proxy_headers off: the caller check reads the peer address of the connection, never a header.
    uvicorn.run(app, host=BIND_ALL, port=PORT, access_log=False, log_level="warning", proxy_headers=False)


def _beat(heartbeat: Heartbeat) -> None:
    """The service has no loop of its own to beat from: it is alive while this process runs."""
    while True:
        heartbeat.beat()
        time.sleep(10)


if __name__ == "__main__":
    main()
