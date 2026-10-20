"""The demo UI on 8085, with operational probes on 9000.

A customer chat in front of the agent, and next to it what the walls did for the visitor's own
tickets. Optional: the chart renders it only with demo.enabled, and the security story does not
depend on it. It is a front door, so it is treated as untrusted like the others:

- The customer comes from the visitor's session, never from a request body. The session cookie is
  HttpOnly and SameSite=Strict; every POST needs application/json, the same origin and, once
  signed in, the session's CSRF token.
- It logs in to PostgreSQL as demo_portal (three functions, no table) and demo_ops (audit columns
  only); db/sql/09-demo.sql. The panel reads only the ticket numbers this session created.
- Pages and scripts are its own files, with a Content-Security-Policy that allows nothing else.
- The Host header must be a local name: it is reached with kubectl port-forward only
  (scripts/demo-ui.sh), and this stops a DNS-rebinding page from talking to it.

Dev sign-in: whoever opens the page picks a fictional customer. That is the point of a demo and
the reason it is never exposed.

    GET  /                    the page (static/index.html)
    GET  /static/app.css, /static/app.js
    GET  /api/state           customers, the session, its tickets with replies and timelines
    POST /api/signin          {"customer": 1001}
    POST /api/signout
    POST /api/message         {"text": "..."} with X-CSRF-Token
"""

from __future__ import annotations

import asyncio
import hmac
import json
import os
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit

import psycopg
import uvicorn
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

from app.common.ops import Heartbeat, Metrics, start_ops_server
from app.demo import database, timeline
from app.demo.sessions import MAX_TICKETS, MAX_WAITING, Sessions, Ticket

PORT = 8085
OPS_PORT = 9000
COOKIE = "ah_demo"
MAX_BODY = 8192
MAX_TEXT = 2000
STATIC = Path(__file__).parent / "static"
LOCAL_HOSTS = {"localhost", "127.0.0.1", "[::1]"}

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
}


def backend_info() -> dict:
    """Which model answers, from the chart's llm settings (DEMO_LLM_BACKEND, DEMO_LLM_MODEL)."""
    if os.environ.get("DEMO_LLM_BACKEND", "scripted") == "scripted":
        return {"scripted": True, "name": "Scripted model",
                "detail": "plays a fully hijacked model: it obeys every instruction in the message"}
    model = os.environ.get("DEMO_LLM_MODEL", "")
    return {"scripted": False, "name": f"Claude {model}".strip(), "detail": "a real model answers the tickets"}


def allowed_hosts() -> set[str]:
    extra = {h.strip().lower() for h in os.environ.get("DEMO_ALLOWED_HOSTS", "").split(",") if h.strip()}
    return LOCAL_HOSTS | extra


def host_name(header: str) -> str:
    """The name in a Host header, without the port: 'localhost:8085' -> 'localhost'."""
    header = header.strip().lower()
    if header.startswith("["):
        return header.split("]", 1)[0] + "]"
    return header.split(":", 1)[0]


def same_origin(request: Request) -> bool:
    """A browser sends Origin on a POST; it must be this page's own. No Origin (curl, a script) passes
    only when the fetch metadata does not say it is cross-site."""
    if request.headers.get("sec-fetch-site", "same-origin") not in ("same-origin", "none"):
        return False
    origin = request.headers.get("origin")
    if origin is None:
        return True
    return urlsplit(origin).netloc.lower() == request.headers.get("host", "").lower()


def error(status: int, code: str) -> JSONResponse:
    return JSONResponse({"error": code}, status_code=status)


async def read_json(request: Request) -> dict | None:
    if request.headers.get("content-type", "").split(";")[0].strip().lower() != "application/json":
        return None
    if int(request.headers.get("content-length") or 0) > MAX_BODY:
        return None
    body = await request.body()
    if len(body) > MAX_BODY:
        return None
    try:
        data = json.loads(body)
    except (ValueError, RecursionError):
        return None
    return data if isinstance(data, dict) else None


def build_app(*, heartbeat: Heartbeat | None = None, sessions: Sessions | None = None,
              hosts: set[str] | None = None) -> Starlette:
    sessions = sessions or Sessions()
    hosts = hosts if hosts is not None else allowed_hosts()
    files = {name: (STATIC / name).read_bytes() for name in ("index.html", "app.css", "app.js")}
    types = {"index.html": "text/html; charset=utf-8", "app.css": "text/css; charset=utf-8",
             "app.js": "text/javascript; charset=utf-8"}
    backend = backend_info()

    def current(request: Request):
        return sessions.get(request.cookies.get(COOKIE))

    async def asset(request: Request):
        name = request.path_params.get("name", "index.html")
        if name not in files:
            return Response(status_code=404)
        return Response(files[name], media_type=types[name])

    async def nothing(request: Request):
        return Response(status_code=204)

    async def state(request: Request):
        session = current(request)
        try:
            people = await run_in_threadpool(database.customers)
            body = {"customers": people, "backend": backend, "limits": {"tickets": MAX_TICKETS}, "customer": None}
            if session is not None:
                body.update(customer=session.customer, csrf=session.csrf, tickets=await tickets_of(session))
        except psycopg.Error:
            return error(503, "database")
        return JSONResponse(body)

    async def tickets_of(session) -> list[dict]:
        ids = [t.id for t in session.tickets]
        texts = await run_in_threadpool(database.replies, session.customer, ids)
        audit = await run_in_threadpool(database.audit, ids)
        out = []
        for ticket in session.tickets:
            data = audit[ticket.id]
            reply = texts.get(ticket.id)
            out.append({
                "id": ticket.id, "text": ticket.text, "filedAt": ticket.filed_at, "reply": reply,
                "replyState": timeline.reply_state(reply),
                "timeline": timeline.build(
                    filed_at=ticket.filed_at, message=ticket.text, run=data["run"], calls=data["calls"],
                    assessments=data["assessments"], requests=data["requests"], reply_at=data["reply_at"],
                    reply_text=reply, scripted=backend["scripted"]),
            })
        return out

    async def signin(request: Request):
        if not same_origin(request):
            return error(403, "origin")
        data = await read_json(request)
        customer = None if data is None else data.get("customer")
        if not isinstance(customer, int) or isinstance(customer, bool):
            return error(400, "bad_request")
        try:
            people = await run_in_threadpool(database.customers)
        except psycopg.Error:
            return error(503, "database")
        if customer not in {p["id"] for p in people}:
            return error(400, "unknown_customer")
        sessions.end(request.cookies.get(COOKIE))
        token, session = sessions.start(customer)
        response = JSONResponse({"customer": customer, "csrf": session.csrf})
        response.set_cookie(COOKIE, token, httponly=True, samesite="strict", path="/", max_age=8 * 3600)
        return response

    async def signout(request: Request):
        if not same_origin(request):
            return error(403, "origin")
        sessions.end(request.cookies.get(COOKIE))
        response = JSONResponse({"customer": None})
        response.delete_cookie(COOKIE, path="/")
        return response

    async def message(request: Request):
        if not same_origin(request):
            return error(403, "origin")
        session = current(request)
        if session is None:
            return error(401, "signin")
        if not hmac.compare_digest(request.headers.get("x-csrf-token", ""), session.csrf):
            return error(403, "csrf")
        data = await read_json(request)
        text = None if data is None else data.get("text")
        if not isinstance(text, str) or not text.strip() or len(text) > MAX_TEXT or "\x00" in text:
            return error(400, "length")
        if len(session.tickets) >= MAX_TICKETS:
            return error(429, "ticket_limit")
        try:
            waiting = [t.id for t in session.tickets]
            answered = await run_in_threadpool(database.replies, session.customer, waiting)
            if len(waiting) - len(answered) >= MAX_WAITING:
                return error(429, "busy")
            if not sessions.allow_message():
                return error(429, "rate")
            ticket_id = await run_in_threadpool(database.open_ticket, session.customer, text)
        except psycopg.Error:
            return error(503, "database")
        session.tickets.append(Ticket(ticket_id, text, timeline.now_iso()))
        return JSONResponse({"ticket": ticket_id})

    @asynccontextmanager
    async def lifespan(_app):
        async def beat():
            while True:
                if heartbeat is not None:
                    heartbeat.beat()
                await asyncio.sleep(10)

        task = asyncio.create_task(beat())
        try:
            yield
        finally:
            task.cancel()

    return Starlette(
        routes=[
            Route("/", asset, name="index"),
            Route("/static/{name}", asset),
            Route("/favicon.ico", nothing),
            Route("/api/state", state),
            Route("/api/signin", signin, methods=["POST"]),
            Route("/api/signout", signout, methods=["POST"]),
            Route("/api/message", message, methods=["POST"]),
        ],
        middleware=[Middleware(Guard, hosts=hosts)],
        lifespan=lifespan,
    )


class Guard:
    """Around every response: only a local Host name is served, and the security headers are added."""

    def __init__(self, app: ASGIApp, hosts: set[str]) -> None:
        self.app = app
        self.hosts = hosts

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        host = dict(scope["headers"]).get(b"host", b"").decode("latin-1")
        if host_name(host) not in self.hosts:
            await Response("Unknown host", status_code=421, headers=SECURITY_HEADERS)(scope, receive, send)
            return

        async def with_headers(event) -> None:
            if event["type"] == "http.response.start":
                event["headers"] = [*event.get("headers", []),
                                    *((k.lower().encode(), v.encode()) for k, v in SECURITY_HEADERS.items())]
            await send(event)

        await self.app(scope, receive, with_headers)


def main() -> None:
    heartbeat = Heartbeat()
    ops = start_ops_server(OPS_PORT, Metrics(), heartbeat)
    try:
        # All interfaces of the container: the Service and kubectl port-forward reach it, nothing else does.
        uvicorn.run(build_app(heartbeat=heartbeat), host="0.0.0.0", port=PORT, access_log=False, log_level="warning")  # nosec B104
    finally:
        ops.shutdown()


if __name__ == "__main__":
    main()
