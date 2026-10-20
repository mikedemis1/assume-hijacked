"""The demo UI on 8085, with operational probes on 9000.

Two pages of one small service, both with Eleni Papadopoulou (customer 1001) signed in. `/` is a
fictional supplier's website with the Volt support chat in the corner: the customer sees their own
words and the replies, and nothing else. `/security` is the presenter view: the same chat with a
switch for the model's "brain" (Claude, or a simulated hijacked model with five attacks to type)
and, next to it, what the walls did for each message. Optional: the chart renders it only with
demo.enabled, and the security story does not depend on it. It is a front door, so it is treated
as untrusted like the others:

- The customer comes from the visitor's session, never from a request body, and it is always 1001.
  The session cookie is HttpOnly and SameSite=Strict; every POST needs application/json, the same
  origin and, once signed in, the session's CSRF token.
- It logs in to PostgreSQL as demo_portal (three functions, no table) and demo_ops (audit columns
  only); db/sql/09-demo.sql. The cards read only the ticket numbers this session created.
- The customer endpoint returns the visitor's own messages and replies and no backstage field
  (ruling R14). Everything about the walls is under /api/console, as fixed phrases.
- An attack travels inside the one message that carries it: {"text": ..., "attack": "neighbour"}
  files the words, a marker line and the attack's CALL/SAY lines. That is only more ticket text;
  the ticket is untrusted input as always and no wall is told anything new.
- Pages and scripts are its own files, with a Content-Security-Policy that allows nothing else.
- The Host header must be a local name: it is reached with kubectl port-forward only
  (scripts/demo-ui.sh), and this stops a DNS-rebinding page from talking to it.

The sign-in trusts whoever opens the page. That is acceptable only because the service is reached
with kubectl port-forward on localhost.

    GET  /                    the website and chat (static/index.html)
    GET  /security            the presenter view (static/security.html)
    GET  /static/...          css, js, the robot, the portrait
    GET  /api/state           the session, its messages and replies
    POST /api/signin          {"customer": 1001}
    POST /api/message         {"text": "...", "attack": "neighbour" or absent} with X-CSRF-Token
    GET  /api/console         counters, one card per message, the attacks to type
"""

from __future__ import annotations

import asyncio
import hmac
import json
import os
from contextlib import asynccontextmanager
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlsplit

import psycopg
import uvicorn
from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

from app.common.ops import Heartbeat, Metrics, start_ops_server
from app.demo import attacks, card, console, database
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
# The one customer who is logged in (a person who does not exist, see static/avatars/NOTICE).
# Nikos (1002) and Maria (1003) exist only in the database, as the targets of attacks.
CUSTOMER = {"id": 1001, "name": "Eleni Papadopoulou", "avatar": "/static/avatars/eleni.jpg"}
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


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


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

    async def state(request: Request):
        """The customer page's data: the visitor's own words and the replies, and nothing about the walls."""
        session = current(request)
        body: dict = {"customer": None}
        if session is not None:
            try:
                ids = [t.id for t in session.tickets]
                texts = await run_in_threadpool(database.replies, session.customer, ids)
            except psycopg.Error:
                return error(503, "database")
            body.update(customer=CUSTOMER, csrf=session.csrf, messages=[
                {"id": t.id, "text": t.text, "reply": texts.get(t.id), "card": card.account_card(texts.get(t.id)),
                 "simulated": backend["scripted"] or t.attack is not None}
                for t in session.tickets])
        return JSONResponse(body)

    async def console_state(request: Request):
        """The presenter's data for this session's tickets, newest first."""
        session = current(request)
        if session is None:
            return error(401, "signin")
        try:
            ids = [t.id for t in session.tickets]
            audit = await run_in_threadpool(database.audit, ids)   # first: a reply it shows is surely in the next read
            texts = await run_in_threadpool(database.replies, session.customer, ids)
            paused = await run_in_threadpool(database.kill_switch_on)
        except psycopg.Error:
            return error(503, "database")
        cards = [console.view(
            ticket_id=t.id, attack=attacks.BY_ID.get(t.attack or ""),
            simulated=backend["scripted"] or t.attack is not None, data=audit[t.id], reply=texts.get(t.id))
            for t in reversed(session.tickets)]
        return JSONResponse({
            "backend": backend, "summary": console.summary(cards, paused), "cards": cards,
            "attacks": [{"id": a.id, "typed": a.typed} for a in attacks.ATTACKS],
        })

    async def signin(request: Request):
        if not same_origin(request):
            return error(403, "origin")
        try:
            data = await read_json(request)
        except BadBody as bad:
            return bad.response
        customer = data.get("customer")
        if not isinstance(customer, int) or isinstance(customer, bool) or customer != CUSTOMER["id"]:
            return error(400, "bad_request")
        sessions.end(request.cookies.get(COOKIE))
        token, session = sessions.start(customer)
        response = JSONResponse({"customer": customer, "csrf": session.csrf})
        response.set_cookie(COOKIE, token, httponly=True, samesite="strict", path="/", max_age=8 * 3600)
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
        text, choice = data.get("text"), data.get("attack")
        if not isinstance(text, str) or not text.strip() or len(text) > MAX_TEXT or "\x00" in text:
            return error(400, "length")
        if choice is not None and (not isinstance(choice, str) or choice not in attacks.BY_ID):
            return error(400, "bad_request")
        attack = attacks.BY_ID.get(choice or "")
        body = attacks.filed_body(text, attack)
        if len(body) > MAX_TEXT:
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
            if not sessions.allow_message():
                return error(429, "rate")
            ticket_id = await run_in_threadpool(database.open_ticket, session.customer, body)
            session.tickets.append(Ticket(ticket_id, text, now_iso(), body, attack.id if attack else None))
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
            Route("/api/signin", signin, methods=["POST"]),
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
