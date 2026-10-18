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
    429       {"error": "budget"}        the lease (or, in Kubernetes, the pod) has used its tokens
    502       {"error": "upstream"}      the model could not answer; nothing of what it said is passed on

What the gateway does not do: it does not know whether a lease is live (it has no database role; the
tool gateway and the dispatcher do that). The lease is the key of the token budget and nothing more.
Without a pod to hang a second budget on (Compose), an agent that sends a new lease string with every
request would get a new budget with each one; Compose is the lab, and Kubernetes also budgets the pod.

Who may call. Compose: the connection's source address must be inside CALLER_SUBNET, the subnet
pinned on the agent's edge network (the same check as the tool gateway's and the dispatcher's).
Kubernetes: the projected token is checked with a TokenReview for the audience `llm-gateway`; it must
belong to the service account ah-agent/agent and name a pod. Anything else, or any failure of the
check, is a 401 before the request is read.

The caller's credentials never travel on: the request to the provider is built in
app/llmgw/backends.py from the gateway's own key or token, and a header of the agent's (x-api-key,
authorization, or any other) is not copied into it.

Environment: LLM_BACKEND (scripted|anthropic|foundry, default scripted), LLM_MODEL (default
claude-haiku-5-5), LLM_TOKEN_BUDGET_PER_LEASE (default 20000), ANTHROPIC_API_KEY_FILE, FOUNDRY_ENDPOINT
and the workload identity variables, CALLER_AUTH (compose|k8s), CALLER_SUBNET (compose).
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
from collections.abc import Mapping

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
from app.gateway.auth import CallerAuth, CallerError, CallerIdentity
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


class Budget:
    """Tokens spent, per key. A call reserves its estimated input first and settles to what it really
    cost; a call that does not fit reserves nothing, on any key. A table that is full refuses a key it
    does not know: a gateway that forgot keys would give out fresh budgets."""

    def __init__(self, limit: int, max_keys: int = MAX_BUDGET_KEYS) -> None:
        self.limit, self._max_keys = limit, max_keys
        self._used: dict[str, int] = {}
        self._lock = threading.Lock()

    def reserve(self, keys: list[str], tokens: int) -> bool:
        with self._lock:
            new = [k for k in keys if k not in self._used]
            if len(self._used) + len(new) > self._max_keys:
                return False
            if any(self._used.get(k, 0) + tokens > self.limit for k in keys):
                return False
            for key in keys:
                self._used[key] = self._used.get(key, 0) + tokens
            return True

    def settle(self, keys: list[str], reserved: int, actual: int) -> None:
        with self._lock:
            for key in keys:
                self._used[key] = max(0, self._used.get(key, 0) + actual - reserved)


class LlmGateway:
    """The rules, without HTTP."""

    def __init__(self, backend, budget: Budget, metrics: Metrics) -> None:
        self.backend, self.budget, self.metrics = backend, budget, metrics

    async def next(self, caller: CallerIdentity, lease: str, transcript: list[dict]) -> tuple[int, dict]:
        # The lease is the budget's key; in Kubernetes so is the pod, which has one lease for its life.
        keys = [f"lease:{lease}"] + ([f"pod:{caller.pod}"] if caller.pod else [])
        reserved = estimate_tokens(transcript)
        if not self.budget.reserve(keys, reserved):
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
        spent = step.tokens if step.tokens > 0 else reserved + estimate_tokens(answer)
        self.budget.settle(keys, reserved, spent)
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
        await self.app({**scope, CALLER_SCOPE_KEY: caller}, receive, send)


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


def prepare(env: Mapping[str, str], *, transport=None, reviewer=None) -> tuple[LlmGateway, CallerAuth]:
    """Everything the process needs, or SystemExit saying what is missing: a gateway that cannot reach
    its model, or would let every caller in, does not start."""
    mode = calls.caller_auth_mode(env)
    try:
        auth = caller_auth(mode, env.get("CALLER_SUBNET") or None, reviewer)
    except ValueError as err:
        raise SystemExit(str(err)) from None
    limit = _budget_limit(env)
    try:
        backend = backends.make_backend(env, transport=transport)
    except BackendError as err:
        raise SystemExit(str(err)) from None
    metrics = Metrics()
    init_metrics(metrics)
    return LlmGateway(backend, Budget(limit), metrics), auth


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
