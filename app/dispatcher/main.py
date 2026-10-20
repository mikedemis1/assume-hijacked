"""python -m app.dispatcher.main: the dispatcher. It hands a ticket and a lease to an agent, takes the
agent's reply, checks it again, stores it and ends the lease.

    8081  POST /claim   POST /reply      (this file)
    9000  /healthz /metrics               (app/common/ops.py)

The agent gets no database access and no way to pick its own ticket: the dispatcher decides which
ticket it works on, and the lease it hands out is the only thing that names that ticket for the tools.

POST /claim
    Request   no body (a body is ignored). In Kubernetes the header `Authorization: Bearer <projected
              service account token, audience dispatcher>`.
    200       {"ticket_id": <int>, "lease": "<64 hex>"}   the agent's ticket and its lease. Given once.
    204       no body: nothing for this caller (an unknown pod, or a pod that has already claimed).
    401       {"error": "unauthorized"}                    the caller is not an agent (see below)
    503       {"error": "unavailable"}                     the database did not answer
    The run was made when the dispatcher created the agent's Job; the pod that asks is matched to it
    by its name (the TokenReview names the pod, the Job controller names the pod after the Job), and
    the lease is bound to that pod.

POST /reply
    Request   header `X-Lease: <the lease>` (exactly one); body JSON {"text": "<reply>"} and optionally
              {"events": [{"kind", "tool", "args": [names]}]}, at most 64 KiB, text 1 to 4000
              characters. Nothing else in the body is read. In Kubernetes also the Authorization
              header as above.
              The events are what the agent dropped or refused before the gateway (app/dispatcher/
              events.py): names only, at most 32 events of 16 names, identifiers only. They are
              stored in agent_events for the ticket of the lease, never for one named in the body. A
              list that breaks any rule is rejected whole (reply stored all the same, a security
              event, dispatcher_agent_events_rejected_total). Reported by the agent: a best-effort
              audit, the gateway's own records stay the authority.
    200       {"stored": true}    the reply guard was run again here, the notices added, the reply
                                  stored, the run marked replied and the lease revoked. The answer does
                                  not say whether the agent's text was replaced.
    400       {"error": "bad_request"}      not a JSON object with a text of the right size
    401       {"error": "unauthorized"}
    403       {"error": "lease"}            the lease is unknown, expired, revoked, malformed, or in
                                  Kubernetes bound to another pod. One answer for all of them.
    409       {"error": "already_replied"}  the ticket has a reply (the lease is revoked all the same)
    413       {"error": "too_large"}
    503       {"error": "unavailable"}

Who may call. The projected token is checked with a TokenReview; it must belong to the service
account ah-agent/agent and name a pod (the same check as the tool gateway's). Anything else, or any
failure of the check, is a 401 before the request is read.

Environment: DB_PASSWORD_DISPATCHER, DISPATCH_MODE (k8s, the only mode), AGENT_JOB_TEMPLATE_FILE
(default /etc/ah/agent-job-template/job.json), DISPATCH_MAX_ACTIVE (Jobs running at once, default 3).
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass

import psycopg
import uvicorn
from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

from app import config, db
from app.agent import templates
from app.common.events import security_event
from app.common.ops import Heartbeat, Metrics, start_ops_server
from app.dispatcher import events as agent_events
from app.dispatcher import k8s, replies
from app.dispatcher.store import DispatcherDb
from app.gateway.auth import CallerAuth, CallerError, CallerIdentity

PORT = 8081
BIND_ALL = "0.0.0.0"  # nosec B104 - only reachable on the agent's edge network; see main()
OPS_PORT = 9000
BEAT_SECONDS = 10
DISPATCH_SECONDS = 5
DEFAULT_MAX_ACTIVE = 3
DB_CONNECT_TIMEOUT_S = 3
DB_STATEMENT_TIMEOUT_MS = 5000
MODES = ("k8s",)
AUDIENCE = "dispatcher"
CALLER_SCOPE_KEY = "ah.caller"  # not a header name, so a client cannot set it
LEASE_HEADER = "x-lease"
LEASE_FORMAT = re.compile(r"[0-9a-f]{64}")
MAX_REPLY_BODY_BYTES = 64 * 1024  # 4000 characters of text and 32 events of 16 names
UNAUTHORIZED = {"error": "unauthorized"}
NO_EVENTS = object()  # `events` was not in the body (a null is something sent, and is rejected)

CLAIM_OUTCOMES = ("issued", "none")
REPLY_OUTCOMES = ("stored", "lease", "duplicate", "bad_request", "too_large")
BLOCK_REASONS = ("script_mix", "currency", "number_word", "money_wording", "billing_outcome", "unapproved_number")
TEMPLATE_REASONS = ("effect_ticket",)
REFUSAL_REASONS = (
    "missing", "malformed", "review_failed", "not_authenticated", "wrong_service_account", "no_pod",
)
JOB_OUTCOMES = ("created", "failed", "full")


def init_metrics(metrics: Metrics) -> None:
    """Every series exists at 0 from the start, so a rate or an alert on one is not blind."""
    for outcome in CLAIM_OUTCOMES:
        metrics.inc("dispatcher_claims_total", {"outcome": outcome}, by=0)
    for outcome in REPLY_OUTCOMES:
        metrics.inc("dispatcher_replies_total", {"outcome": outcome}, by=0)
    for reason in BLOCK_REASONS:
        metrics.inc("dispatcher_replies_blocked_total", {"reason": reason}, by=0)
    for reason in TEMPLATE_REASONS:
        metrics.inc("dispatcher_replies_templated_total", {"reason": reason}, by=0)
    for reason in REFUSAL_REASONS:
        metrics.inc("dispatcher_callers_refused_total", {"reason": reason}, by=0)
    for outcome in JOB_OUTCOMES:
        metrics.inc("dispatcher_jobs_total", {"outcome": outcome}, by=0)
    metrics.inc("dispatcher_errors_total", {"stage": "database"}, by=0)
    for kind in agent_events.KINDS:
        metrics.inc("dispatcher_agent_events_total", {"kind": kind}, by=0)
    metrics.inc("dispatcher_agent_events_rejected_total", by=0)


@dataclass(frozen=True)
class Claim:
    ticket_id: int
    lease: str


class Dispatcher:
    """The rules, without HTTP. `mode` is k8s, the only mode."""

    def __init__(self, store: DispatcherDb, mode: str, metrics: Metrics, *, template: dict | None = None, api=None,
                 max_active: int = DEFAULT_MAX_ACTIVE) -> None:
        if mode not in MODES:
            raise ValueError(f"DISPATCH_MODE must be one of {MODES}, got {mode!r}")
        if template is None or api is None:
            raise ValueError("DISPATCH_MODE=k8s needs the agent Job template and the Kubernetes API client")
        self._store, self._mode, self._metrics = store, mode, metrics
        self._template, self._api, self._max_active = template, api, max_active

    # --- POST /claim ---

    def claim(self, caller: CallerIdentity) -> Claim | None:
        job = k8s.run_name_of_pod(caller.pod)
        found = self._store.claim_job(job, caller.pod) if job else None
        if found is None:
            self._metrics.inc("dispatcher_claims_total", {"outcome": "none"})
            return None
        self._metrics.inc("dispatcher_claims_total", {"outcome": "issued"})
        security_event("claim_issued", ticket_id=found[0])
        return Claim(*found)

    # --- POST /reply ---

    def reply(self, caller: CallerIdentity, lease: str, text: str, events: object = NO_EVENTS) -> str:
        """'stored', 'lease' (refused: the lease is not live for this caller) or 'duplicate'.
        `events` is the agent's list as it came in (NO_EVENTS: none sent); it is checked here."""
        outcome = self._reply(caller, lease, text, events)
        self._metrics.inc("dispatcher_replies_total", {"outcome": outcome})
        return outcome

    def _reply(self, caller: CallerIdentity, lease: str, text: str, events: object) -> str:
        if not LEASE_FORMAT.fullmatch(lease):
            return "lease"
        listed = None if events is NO_EVENTS else agent_events.checked(events)
        outcome, ticket_id, blocked, kind, written = self._store.finish_reply(lease, caller.pod, text, listed or None)
        if outcome == "lease":
            security_event("reply_refused", reason="lease")
            return "lease"
        if events is not NO_EVENTS and (listed is None or (listed and written is None)):
            self._metrics.inc("dispatcher_agent_events_rejected_total")
            security_event("agent_events_rejected", ticket_id=ticket_id)
        elif written:
            for event in listed:
                self._metrics.inc("dispatcher_agent_events_total", {"kind": event["kind"]})
            security_event("agent_events_stored", ticket_id=ticket_id, count=written)
        if kind == "template":
            self._metrics.inc("dispatcher_replies_templated_total", {"reason": "effect_ticket"})
            security_event("reply_templated", ticket_id=ticket_id, reason="effect_ticket")
        if blocked:
            self._metrics.inc("dispatcher_replies_blocked_total", {"reason": blocked})
            security_event("reply_blocked", ticket_id=ticket_id, reason=blocked, where="dispatcher")
        security_event("reply_duplicate" if outcome == "duplicate" else "reply_stored", ticket_id=ticket_id)
        return outcome

    # --- Jobs (Kubernetes) ---

    def dispatch_once(self) -> int:
        """Start agent Jobs for open tickets without a run, up to the number allowed at once.
        Returns how many Jobs were created. A Job that cannot be created leaves its run `failed`
        (nobody retries it; a person looks at the ticket)."""
        if self._mode != "k8s":
            return 0
        created = 0
        while self._store.active_runs() < self._max_active:
            started = self._store.start_next_run(templates.job_name)
            if started is None:
                break
            ticket_id, name = started
            try:
                k8s.create_agent_job(ticket_id, self._template, self._api, name)
            except (k8s.KubeError, templates.TemplateError) as err:
                self._store.fail_run(name)
                self._metrics.inc("dispatcher_jobs_total", {"outcome": "failed"})
                security_event("job_failed", ticket_id=ticket_id, error=type(err).__name__)
                continue
            created += 1
            self._metrics.inc("dispatcher_jobs_total", {"outcome": "created"})
            security_event("job_created", ticket_id=ticket_id)
        else:
            self._metrics.inc("dispatcher_jobs_total", {"outcome": "full"})
        return created


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
                self._metrics.inc("dispatcher_callers_refused_total", {"reason": refused.reason})
            answer = JSONResponse(UNAUTHORIZED, status_code=401, headers={"WWW-Authenticate": "Bearer"})
            await answer(scope, receive, send)
            return
        await self.app({**scope, CALLER_SCOPE_KEY: caller}, receive, send)


FAILED = object()  # what `guarded` returns when the work failed (a database or network error)


def _error(status: int, name: str) -> JSONResponse:
    return JSONResponse({"error": name}, status_code=status)


async def _read_capped(request: Request, limit: int) -> bytes | None:
    """The body, or None if it is over `limit` (declared or actually sent)."""
    declared = request.headers.get("content-length")
    if declared is not None:
        if not declared.isdigit() or int(declared) > limit:
            return None
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > limit:
            return None
    return bytes(body)


def build_app(dispatcher: Dispatcher, auth: CallerAuth, metrics: Metrics | None = None) -> AuthenticateCaller:
    metrics = metrics or Metrics()

    async def guarded(work, *args):
        """Run blocking work in a thread; a database or other failure is a 503 with no details."""
        try:
            return await run_in_threadpool(work, *args)
        except (psycopg.Error, OSError, RuntimeError) as err:
            metrics.inc("dispatcher_errors_total", {"stage": "database"})
            security_event("dispatcher_error", error=type(err).__name__)
            return FAILED

    async def claim(request: Request) -> Response:
        caller = request.scope[CALLER_SCOPE_KEY]
        found = await guarded(dispatcher.claim, caller)
        if found is FAILED:
            return _error(503, "unavailable")
        if found is None:
            return Response(status_code=204)
        return JSONResponse({"ticket_id": found.ticket_id, "lease": found.lease})

    async def reply(request: Request) -> Response:
        caller = request.scope[CALLER_SCOPE_KEY]
        leases = request.headers.getlist(LEASE_HEADER)
        lease = leases[0] if len(leases) == 1 else ""  # two that could disagree are no lease
        body = await _read_capped(request, MAX_REPLY_BODY_BYTES)
        if body is None:
            metrics.inc("dispatcher_replies_total", {"outcome": "too_large"})
            return _error(413, "too_large")
        text = _text_of(body)
        if text is None:
            metrics.inc("dispatcher_replies_total", {"outcome": "bad_request"})
            return _error(400, "bad_request")
        outcome = await guarded(dispatcher.reply, caller, lease, text, _events_of(body))
        if outcome is FAILED:
            return _error(503, "unavailable")
        if outcome == "stored":
            return JSONResponse({"stored": True})
        if outcome == "duplicate":
            return _error(409, "already_replied")
        return _error(403, "lease")

    inner = Starlette(routes=[Route("/claim", claim, methods=["POST"]), Route("/reply", reply, methods=["POST"])])
    return AuthenticateCaller(inner, auth, metrics)


def _text_of(body: bytes) -> str | None:
    try:
        data = json.loads(body)
    except (ValueError, RecursionError):
        return None
    text = data.get("text") if isinstance(data, dict) else None
    if not isinstance(text, str) or not 1 <= len(text) <= replies.MAX_TEXT_CHARS:
        return None
    return text


def _events_of(body: bytes) -> object:
    """The `events` member as sent (checked later), or NO_EVENTS. _text_of has already shown that the
    body is a JSON object."""
    return json.loads(body).get("events", NO_EVENTS)


# --- the process ---


def dispatch_mode(env: Mapping[str, str], caller_auth: str) -> str:
    mode = env.get("DISPATCH_MODE", "").strip() or caller_auth
    if mode not in MODES:
        raise SystemExit(f"DISPATCH_MODE must be one of {MODES}, got {mode!r}")
    if mode != caller_auth:
        # A claim needs the pod name from a TokenReview; any other caller mode is a mistake.
        raise SystemExit(f"DISPATCH_MODE={mode} does not match CALLER_AUTH={caller_auth}")
    return mode


def caller_auth(mode: str, reviewer=None) -> CallerAuth:
    """Who may call: the service account ah-agent/agent with a token for the audience `dispatcher`.
    Raises ValueError for any mode but k8s: a dispatcher that would trust anything else does not start."""
    return CallerAuth(mode=mode, audience=AUDIENCE, reviewer=reviewer)


def background(dispatcher: Dispatcher, store: DispatcherDb, heartbeat: Heartbeat, metrics: Metrics) -> None:
    """The database heartbeat and the ops one every BEAT_SECONDS, and the start of
    Jobs every DISPATCH_SECONDS. A database that does not answer leaves both beats to age: /healthz
    turns 503 after 60 s."""
    last_beat = 0.0
    while True:
        try:
            dispatcher.dispatch_once()
            if time.monotonic() - last_beat >= BEAT_SECONDS:
                store.beat()
                heartbeat.beat()
                last_beat = time.monotonic()
        except Exception as err:
            metrics.inc("dispatcher_errors_total", {"stage": "database"})
            security_event("dispatcher_error", stage="background", error=type(err).__name__)
        time.sleep(DISPATCH_SECONDS)


def main() -> None:
    if not os.environ.get("DB_PASSWORD_DISPATCHER"):
        raise SystemExit("DB_PASSWORD_DISPATCHER is not set")
    settings = config.load()
    mode = dispatch_mode(os.environ, settings.caller_auth)
    try:
        auth = caller_auth(settings.caller_auth)
    except ValueError as err:
        raise SystemExit(str(err)) from None
    try:
        template = templates.load_template(os.environ.get("AGENT_JOB_TEMPLATE_FILE") or templates.DEFAULT_TEMPLATE_FILE)
    except templates.TemplateError as err:
        raise SystemExit(f"the agent Job template is not usable: {err}") from None
    api = k8s.KubeApi()
    metrics = Metrics()
    init_metrics(metrics)
    heartbeat = Heartbeat()
    start_ops_server(OPS_PORT, metrics, heartbeat)
    store = DispatcherDb(
        lambda: db.connect(
            settings, "dispatcher", connect_timeout_s=DB_CONNECT_TIMEOUT_S, statement_timeout_ms=DB_STATEMENT_TIMEOUT_MS
        )
    )
    dispatcher = Dispatcher(
        store, mode, metrics, template=template, api=api,
        max_active=int(os.environ.get("DISPATCH_MAX_ACTIVE") or DEFAULT_MAX_ACTIVE),
    )
    threading.Thread(target=background, args=(dispatcher, store, heartbeat, metrics), name="background", daemon=True).start()
    app = build_app(dispatcher, auth, metrics)
    # All interfaces of the container: the agent reaches it from another container or pod. The
    # network and the caller check are the wall (NetworkPolicy and TokenReview); no access log: a
    # request is a lease and a reply text. proxy_headers off: no header is trusted.
    uvicorn.run(app, host=BIND_ALL, port=PORT, access_log=False, log_level="warning", proxy_headers=False)


if __name__ == "__main__":
    main()
