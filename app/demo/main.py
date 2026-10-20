"""The demo UI on 8085, with operational probes on 9000.

Two pages of one small service. `/` is a fictional supplier's website with a support chat in the
corner: the customer sees their own words and the replies, and nothing else. `/security` is the
security console: what the walls decided for the tickets of this session, read-only, plus one
presenter control. Optional: the chart renders it only with demo.enabled, and the security story
does not depend on it. It is a front door, so it is treated as untrusted like the others:

- The customer comes from the visitor's session, never from a request body. The session cookie is
  HttpOnly and SameSite=Strict; every POST needs application/json, the same origin and, once
  signed in, the session's CSRF token.
- It logs in to PostgreSQL as demo_portal (three functions, no table) and demo_ops (audit columns
  only); db/sql/09-demo.sql. The console reads only the ticket numbers this session created.
- The customer endpoints return the visitor's own messages and replies and no backstage field
  (ruling R14). Everything about the walls is under /api/console.
- Names from the records (tools, arguments) are printed only when they are in the known vocabulary.
- Arming an attack is per session, needs the CSRF token and works once: the next message of that
  session is filed with the attack's CALL/SAY lines after the customer's words. That is only more
  ticket text; the ticket is untrusted input as always and no wall is told anything new.
- Pages and scripts are its own files, with a Content-Security-Policy that allows nothing else.
- The Host header must be a local name: it is reached with kubectl port-forward only
  (scripts/demo-ui.sh), and this stops a DNS-rebinding page from talking to it.

Dev sign-in: whoever opens the page picks a fictional customer. That is the point of a demo and
the reason it is never exposed.

    GET  /                    the website and chat (static/index.html)
    GET  /security            the console (static/security.html)
    GET  /static/...          css, js, the robot, the three portraits
    GET  /api/state           customers, the session, its messages and replies
    POST /api/signin          {"customer": 1001}
    POST /api/signout
    POST /api/message         {"text": "..."} with X-CSRF-Token
    GET  /api/console         counters, the flow, the feed, the attacks to arm
    POST /api/arm             {"attack": "neighbour"} or {"attack": null} with X-CSRF-Token
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
from app.demo import attacks, console, database, timeline
from app.demo.sessions import MAX_TICKETS, MAX_WAITING, Sessions, Ticket

PORT = 8085
OPS_PORT = 9000
COOKIE = "ah_demo"
MAX_BODY = 8192
MAX_TEXT = 2000
STATIC = Path(__file__).parent / "static"
PAGES = {"/": "index.html", "/security": "security.html"}
TYPES = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
         ".js": "text/javascript; charset=utf-8", ".svg": "image/svg+xml", ".jpg": "image/jpeg"}
# The three fictional customers and their portraits (AI-generated people who do not exist, see
# static/avatars/NOTICE).
AVATARS = {1001: "eleni", 1002: "nikos", 1003: "maria"}
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
        return {"scripted": True, "name": "Scripted model", "short": "plays a fully hijacked model",
                "detail": "plays a fully hijacked model: it obeys every instruction in the message"}
    model = os.environ.get("DEMO_LLM_MODEL", "")
    return {"scripted": False, "name": f"Claude {model}".strip(), "short": "a real model", "detail": "a real model answers the tickets"}


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


class BadBody(Exception):
    def __init__(self, status: int, code: str) -> None:
        super().__init__(code)
        self.response = error(status, code)


async def read_json(request: Request) -> dict:
    """The JSON object in the body. The body is read piece by piece and the read stops at MAX_BODY
    bytes, whatever Content-Length says (a chunked request has none), so a big body is never held."""
    if request.headers.get("content-type", "").split(";")[0].strip().lower() != "application/json":
        raise BadBody(400, "bad_request")
    try:
        declared = int(request.headers.get("content-length") or 0)
    except ValueError:
        raise BadBody(400, "bad_request") from None
    if declared > MAX_BODY:
        raise BadBody(413, "too_big")
    body = bytearray()
    async for piece in request.stream():
        body += piece
        if len(body) > MAX_BODY:
            raise BadBody(413, "too_big")
    try:
        data = json.loads(body)
    except (ValueError, RecursionError):
        raise BadBody(400, "bad_request") from None
    if not isinstance(data, dict):
        raise BadBody(400, "bad_request")
    return data


def build_app(*, heartbeat: Heartbeat | None = None, sessions: Sessions | None = None,
              hosts: set[str] | None = None) -> Starlette:
    sessions = sessions or Sessions()
    hosts = hosts if hosts is not None else allowed_hosts()
    files = {path.relative_to(STATIC).as_posix(): path.read_bytes()
             for path in STATIC.rglob("*") if path.is_file() and path.suffix in TYPES}
    backend = backend_info()

    def current(request: Request):
        return sessions.get(request.cookies.get(COOKIE))

    async def asset(request: Request):
        # Only a name in the table is served, so no path can leave the static folder.
        name = PAGES.get(request.url.path) or request.path_params.get("name", "")
        if name not in files or (name.endswith(".html") and request.url.path not in PAGES):
            return Response(status_code=404)
        return Response(files[name], media_type=TYPES[Path(name).suffix])

    async def nothing(request: Request):
        return Response(status_code=204)

    def avatar(customer: int) -> str | None:
        return f"/static/avatars/{AVATARS[customer]}.jpg" if customer in AVATARS else None

    def person(people: list[dict], customer: int) -> dict:
        me = next((c for c in people if c["id"] == customer), None)
        return {"id": customer, "name": me["name"] if me else str(customer), "avatar": avatar(customer)}

    async def state(request: Request):
        """The customer page's data: the visitor's own words and the replies, and nothing about the walls."""
        session = current(request)
        try:
            people = await run_in_threadpool(database.customers)
            body = {"customers": [{"id": p["id"], "name": p["name"], "avatar": avatar(p["id"])} for p in people],
                    "customer": None}
            if session is not None:
                ids = [t.id for t in session.tickets]
                texts = await run_in_threadpool(database.replies, session.customer, ids)
                body.update(customer=session.customer, csrf=session.csrf, messages=[
                    {"id": t.id, "text": t.text, "reply": texts.get(t.id)} for t in session.tickets])
        except psycopg.Error:
            return error(503, "database")
        return JSONResponse(body)

    async def console_state(request: Request):
        """The console's data for this session's tickets, newest first."""
        session = current(request)
        if session is None:
            return error(401, "signin")
        try:
            people = await run_in_threadpool(database.customers)
            ids = [t.id for t in session.tickets]
            texts = await run_in_threadpool(database.replies, session.customer, ids)
            audit = await run_in_threadpool(database.audit, ids)
            paused = await run_in_threadpool(database.kill_switch_on)
        except psycopg.Error:
            return error(503, "database")
        views = [console.view(
            ticket_id=t.id, filed_at=t.filed_at, body=t.body or t.text, attack=attacks.BY_ID.get(t.attack or ""),
            data=audit[t.id], reply=texts.get(t.id), scripted=backend["scripted"])
            for t in reversed(session.tickets)]
        return JSONResponse({
            "customer": person(people, session.customer), "csrf": session.csrf, "backend": backend,
            "summary": console.summary(views, paused), "armed": session.armed, "tickets": views,
            "attacks": [{"id": a.id, "label": a.label, "asi": list(a.asi), "customer": a.customer}
                        for a in attacks.ATTACKS],
        })

    async def arm(request: Request):
        if not same_origin(request):
            return error(403, "origin")
        session = current(request)
        if session is None:
            return error(401, "signin")
        if not hmac.compare_digest(request.headers.get("x-csrf-token", ""), session.csrf):
            return error(403, "csrf")
        try:
            data = await read_json(request)
        except BadBody as bad:
            return bad.response
        choice = data.get("attack")
        if choice is not None and (not isinstance(choice, str) or choice not in attacks.BY_ID):
            return error(400, "bad_request")
        session.armed = choice
        return JSONResponse({"armed": session.armed})

    async def signin(request: Request):
        if not same_origin(request):
            return error(403, "origin")
        try:
            data = await read_json(request)
        except BadBody as bad:
            return bad.response
        customer = data.get("customer")
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
        try:
            data = await read_json(request)
        except BadBody as bad:
            return bad.response
        text = data.get("text")
        if not isinstance(text, str) or not text.strip() or len(text) > MAX_TEXT or "\x00" in text:
            return error(400, "length")
        # One message at a time per session: the checks below and the append at the end have awaits
        # between them, and without this two requests at once could both pass the caps.
        if session.sending:
            return error(429, "busy")
        session.sending = True
        try:
            if len(session.tickets) >= MAX_TICKETS:
                return error(429, "ticket_limit")
            waiting = [t.id for t in session.tickets]
            answered = await run_in_threadpool(database.replies, session.customer, waiting)
            if len(waiting) - len(answered) >= MAX_WAITING:
                return error(429, "busy")
            armed = attacks.BY_ID.get(session.armed or "")
            body = attacks.filed_body(text, armed)
            if len(body) > MAX_TEXT:
                return error(400, "length")
            if not sessions.allow_message():
                return error(429, "rate")
            ticket_id = await run_in_threadpool(database.open_ticket, session.customer, body)
            session.tickets.append(Ticket(ticket_id, text, timeline.now_iso(), body, armed.id if armed else None))
            session.armed = None  # one shot: only the message that was just filed carries the plan
        except psycopg.Error:
            return error(503, "database")
        finally:
            session.sending = False
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
            Route("/security", asset, name="security"),
            Route("/static/{name:path}", asset),
            Route("/favicon.ico", nothing),
            Route("/api/state", state),
            Route("/api/console", console_state),
            Route("/api/arm", arm, methods=["POST"]),
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
