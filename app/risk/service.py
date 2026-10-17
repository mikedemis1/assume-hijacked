"""The risk service: the facts from the database, the judgement from rules.py, the verdict back.

Two jobs, one process (app/risk/main.py):

- POST /decide. The tool gateway asks before every tool call: body {"lease": str, "tool": str},
  answer {"decision": "allow|deny|pause", "reasons": [str]}. Every answer is written to
  call_assessments under sha256(lease); "pause" also stops every agent (pause_agents). Anything
  that goes wrong answers deny: a bad body 400, a database error 503. The gateway also denies when
  it gets no answer at all (task A8), so a risk engine that is down or slow stops the tools.
- assess_pending. Every effect request that is still pending and has no assessment gets one
  (risk_assessments). The executor acts on assessed requests only, and the database refuses an
  effect without one (check_approval_floor, db/sql/06-risk.sql).

The lease is a bearer secret. It is hashed as soon as it arrives and never logged, never put in a
metric, never sent to the database: risk_lease_facts takes the hash. Logs and metrics carry
categories and ids only (the rule in app/agent/events.py).
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from collections.abc import Callable
from datetime import datetime, timedelta
from decimal import Decimal

import psycopg
from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from app import db
from app.agent.events import security_event
from app.common.ops import Metrics
from app.config import Settings
from app.risk.rules import ENGINE_VERSION, EFFECT_TOOLS, CallFacts, EffectFacts, assess_call, assess_effect

ROLE = "risk_engine"
MAX_BODY_BYTES = 1024
MAX_LEASE_CHARS = 256
TOOL_NAME = re.compile(r"[a-z_]{1,64}")
DECIDE_ATTEMPTS = 3
EFFECT_TOOL_LIST = sorted(EFFECT_TOOLS)


def connect(settings: Settings) -> psycopg.Connection:
    return db.connect(settings, ROLE)


def _count(metrics: Metrics | None, name: str, labels: dict[str, str]) -> None:
    if metrics is not None:
        metrics.inc(name, labels)


def _error(metrics: Metrics | None, stage: str, exc: BaseException, **ids: int) -> None:
    """One error: a metric and a security log line with the error class and ids only. The message
    is left out on purpose: a driver message can quote the statement or its values."""
    _count(metrics, "risk_errors_total", {"stage": stage})
    security_event("risk_error", stage=stage, error=type(exc).__name__, **ids)


# --- POST /decide ---

def lease_hash(lease: str) -> bytes:
    """sha256 of the lease as UTF-8, the same as leases.token_hash (db/sql/05-lease.sql)."""
    return hashlib.sha256(lease.encode()).digest()


def call_facts(conn: psycopg.Connection, h: bytes, tool: str) -> CallFacts:
    lease = conn.execute(
        "SELECT lease_live, tool_in_lease FROM risk_lease_facts(%s, %s)", (h, tool)
    ).fetchone()
    switch = conn.execute("SELECT paused FROM agent_control WHERE id = 1").fetchone()
    # Counted on this lease: calls that went through, effect calls that went through, and denials
    # the rules gave the lease itself. A denial whose only reason is that every agent was paused
    # is not the lease's doing; counted, it would pause the agents again right after a resume.
    counts = conn.execute(
        "SELECT count(*) FILTER (WHERE decision = 'allow') AS calls, "
        "       count(*) FILTER (WHERE decision = 'allow' AND tool = ANY(%s)) AS effects, "
        "       count(*) FILTER (WHERE decision IN ('deny', 'pause') "
        "                        AND reasons IS DISTINCT FROM ARRAY['paused']) AS denied "
        "FROM call_assessments WHERE lease_hash = %s",
        (EFFECT_TOOL_LIST, h),
    ).fetchone()
    return CallFacts(
        tool=tool,
        lease_live=lease["lease_live"],
        tool_in_lease=lease["tool_in_lease"],
        paused=True if switch is None else switch["paused"],  # no switch row: fail closed
        calls_on_lease=counts["calls"],
        effect_calls_on_lease=counts["effects"],
        denied_on_lease=counts["denied"],
    )


def decide(
    conn: psycopg.Connection, lease: str, tool: str, metrics: Metrics | None = None
) -> tuple[str, tuple[str, ...]]:
    """Judge one tool call and record the verdict. The facts, the row and the pause land in one
    transaction. If another decision on the same lease wrote its effect in between, the unique
    index call_assessments_one_effect_per_lease refuses this one and the call is judged again,
    now seeing that effect."""
    h = lease_hash(lease)
    for attempt in range(DECIDE_ATTEMPTS):
        try:
            with conn.transaction():
                decision, reasons = assess_call(call_facts(conn, h, tool))
                conn.execute(
                    "INSERT INTO call_assessments (lease_hash, tool, decision, reasons) VALUES (%s, %s, %s, %s)",
                    (h, tool, decision, list(reasons)),
                )
                if decision == "pause":
                    conn.execute("SELECT pause_agents(%s)", (reasons[0],))
            break
        except psycopg.errors.UniqueViolation:
            if attempt == DECIDE_ATTEMPTS - 1:
                raise
    _count(metrics, "risk_decisions_total", {"decision": decision})
    return decision, reasons


class Decider:
    """The /decide side of the process: one database connection, one decision at a time.

    One at a time keeps the counts on a lease exact; the unique index is the backstop if a second
    replica ever runs. A lost connection raises once (the caller answers deny) and the next call
    opens a new one, so a database restart does not need a process restart."""

    def __init__(self, connect_fn: Callable[[], psycopg.Connection], metrics: Metrics) -> None:
        self._connect = connect_fn
        self._metrics = metrics
        self._conn: psycopg.Connection | None = None
        self._lock = threading.Lock()

    def decide(self, lease: str, tool: str) -> tuple[str, tuple[str, ...]]:
        with self._lock:
            if self._conn is None or self._conn.closed:
                self._conn = self._connect()
            try:
                return decide(self._conn, lease, tool, self._metrics)
            except psycopg.OperationalError:
                self._drop()
                raise

    def _drop(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            finally:
                self._conn = None

    def close(self) -> None:
        with self._lock:
            self._drop()


def _deny(status: int, reason: str) -> JSONResponse:
    return JSONResponse({"decision": "deny", "reasons": [reason]}, status_code=status)


def _parse(raw: bytes) -> tuple[str, str] | None:
    try:
        body = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(body, dict):
        return None
    lease, tool = body.get("lease"), body.get("tool")
    if not isinstance(lease, str) or not isinstance(tool, str):
        return None
    if not 0 < len(lease) <= MAX_LEASE_CHARS or not TOOL_NAME.fullmatch(tool):
        return None
    return lease, tool


def build_app(decider, metrics: Metrics | None = None) -> Starlette:
    """The HTTP edge. decider has decide(lease, tool) -> (decision, reasons)."""

    async def decide_endpoint(request: Request) -> JSONResponse:
        raw = await request.body()
        if len(raw) > MAX_BODY_BYTES:
            _count(metrics, "risk_decisions_total", {"decision": "deny"})
            return _deny(413, "bad_request")
        parsed = _parse(raw)
        if parsed is None:
            _count(metrics, "risk_decisions_total", {"decision": "deny"})
            return _deny(400, "bad_request")
        try:
            decision, reasons = await run_in_threadpool(decider.decide, *parsed)
        except Exception as exc:  # fail closed, whatever broke
            _error(metrics, "decide", exc)
            _count(metrics, "risk_decisions_total", {"decision": "deny"})
            return _deny(503, "risk_unavailable")
        return JSONResponse({"decision": decision, "reasons": list(reasons)})

    return Starlette(routes=[Route("/decide", decide_endpoint, methods=["POST"])])


# --- assess_pending ---

def effect_facts(conn: psycopg.Connection, req: dict, settings: Settings, now: datetime) -> EffectFacts:
    hour_ago = now - timedelta(hours=1)
    if req["kind"] == "move_out":
        protection = conn.execute("SELECT home_protection(%s) AS p", (req["id"],)).fetchone()["p"]
        # Move-outs filed in the last hour before this one: the first `limit` of a flood pass,
        # the rest are held, whatever order the engine sees them in.
        moveouts = conn.execute(
            "SELECT count(*) AS n FROM action_requests "
            "WHERE kind = 'move_out' AND created_at >= %s AND id < %s",
            (hour_ago, req["id"]),
        ).fetchone()["n"]
    else:
        protection, moveouts = "UNKNOWN", 0  # not looked up: no credit rule reads them
    evidence = False
    if req["kind"] == "credit" and req["amount_eur"] is not None:
        # The same evidence rule as the executor and check_credit (decision 4): a charge on this
        # request's account, a later twin of an earlier charge, and no less than the credit.
        evidence = conn.execute(
            "SELECT EXISTS (SELECT 1 FROM charges c WHERE c.id = %s AND c.account_id = %s "
            "  AND c.amount_eur >= %s AND EXISTS (SELECT 1 FROM charges d WHERE d.account_id = c.account_id "
            "  AND d.period = c.period AND d.amount_eur = c.amount_eur AND d.id < c.id)) AS ok",
            (req["evidence_ref"], req["account_id"], req["amount_eur"]),
        ).fetchone()["ok"]
    refused = conn.execute(
        "SELECT count(*) AS n FROM action_requests WHERE kind = 'credit' AND account_id = %s "
        "AND status IN ('rejected', 'held_global') AND decided_at >= %s",
        (req["account_id"], hour_ago),
    ).fetchone()["n"]
    blocked = conn.execute("SELECT blocked_calls_on_ticket(%s) AS n", (req["ticket_id"],)).fetchone()["n"]
    return EffectFacts(
        kind=req["kind"],
        amount_eur=None if req["amount_eur"] is None else Decimal(req["amount_eur"]),
        reason=req["reason"],
        protection=protection,
        evidence_confirmed=evidence,
        moveouts_last_hour=moveouts,
        refused_credits_last_hour=refused,
        blocked_calls_on_ticket=blocked,
    )


def assess_pending(
    conn: psycopg.Connection, settings: Settings, now: datetime, metrics: Metrics | None = None
) -> int:
    """Assess every pending request that has no assessment yet. Returns how many were written.
    One request per transaction; one that fails is logged and left for the next round."""
    pending = conn.execute(
        "SELECT r.id, r.kind, r.ticket_id, r.account_id, r.amount_eur, r.reason, r.evidence_ref "
        "FROM action_requests r WHERE r.status = 'pending' "
        "AND NOT EXISTS (SELECT 1 FROM risk_assessments a WHERE a.request_id = r.id) ORDER BY r.id"
    ).fetchall()
    auto_max = Decimal(str(settings.credit_auto_max_eur))
    written = 0
    for req in pending:
        try:
            with conn.transaction():
                verdict = assess_effect(effect_facts(conn, req, settings, now), settings.moveout_max_per_hour, auto_max)
                # ON CONFLICT: another engine got there first; its verdict stands (append only).
                done = conn.execute(
                    "INSERT INTO risk_assessments (request_id, tier, score, reasons, engine_version) "
                    "VALUES (%s, %s, %s, %s, %s) ON CONFLICT (request_id) DO NOTHING",
                    (req["id"], verdict.tier, verdict.score, list(verdict.reasons), ENGINE_VERSION),
                )
            if done.rowcount == 1:
                written += 1
                _count(metrics, "risk_tiers_total", {"tier": verdict.tier})
        except Exception as exc:
            _error(metrics, "assess", exc, request=req["id"])
    return written
