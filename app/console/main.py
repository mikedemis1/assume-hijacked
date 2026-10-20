"""Staff console on 8084, with operational probes on 9000."""

from __future__ import annotations

import asyncio
import hmac
from contextlib import asynccontextmanager
from urllib.parse import parse_qs

import httpx2
import psycopg
import uvicorn
from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from starlette.routing import Route

from app import config, db
from app.common.ops import Heartbeat, Metrics, start_ops_server
from app.console import views
from app.console.auth import Auth, FLOW_COOKIE, SESSION_COOKIE


def connect(settings):
    return db.connect(settings,"approver",connect_timeout_s=2,statement_timeout_ms=2000)


def read_queue(settings):
    with connect(settings) as conn:
        return dict(
            requests=conn.execute("SELECT r.id,r.kind,r.status,k.tier,k.reasons FROM action_requests r LEFT JOIN risk_assessments k ON k.request_id=r.id ORDER BY r.id DESC LIMIT 200").fetchall(),
            heartbeats=conn.execute("SELECT component,last_beat FROM heartbeats ORDER BY component").fetchall(),
            alerts=conn.execute("SELECT id,created_at,actor FROM events WHERE kind='ALERT' ORDER BY id DESC LIMIT 100").fetchall(),
            paused=(conn.execute("SELECT paused FROM agent_control").fetchone() or {"paused":True})["paused"],
        )


def mutate(settings, path, request_id, fields, person):
    with connect(settings) as conn, conn.transaction():
        if path == "/agents/resume":
            conn.execute("SELECT resume_agents(%s::uuid)",(person.oid,))
        else:
            row = conn.execute("SELECT r.status,k.tier FROM action_requests r LEFT JOIN risk_assessments k ON k.request_id=r.id WHERE r.id=%s FOR UPDATE OF r",(request_id,)).fetchone()
            if not row or row["status"] != "pending":
                raise ValueError("request unavailable")
            if path.startswith("/approve/"):
                if row["tier"] not in {"T0","T1","T2"}:
                    raise ValueError("request cannot be approved")
                # The database checks the oid against the staff list and sets the role from it.
                conn.execute("SELECT approve_request(%s,%s::uuid)",(request_id,person.oid))
            else:
                conn.execute("UPDATE action_requests SET status='refused',decision_reason='staff_rejected',decided_at=now() WHERE id=%s",(request_id,))


def build_app(settings=None, *, oidc_transport=None, heartbeat=None):
    settings = settings or config.load()
    auth = Auth(oidc_transport)

    def session_cookie(response, key):
        response.set_cookie(SESSION_COOKIE,key,max_age=1800,httponly=True,secure=auth.secure,samesite="strict")
        return response

    async def queue(request: Request):
        session = auth.session(request.cookies.get(SESSION_COOKIE))
        key = None
        if auth.mode == "dev" and "x-dev-user" in request.headers:
            person = auth.users.get(request.headers["x-dev-user"])
            if person is None:
                return PlainTextResponse("Unauthorised",401)
            try:
                key = auth.create_session(person)
            except ValueError:
                return PlainTextResponse("Sign-in unavailable",503)
            auth.sessions.pop(request.cookies.get(SESSION_COOKIE),None)
            session = auth.session(key)
        if session is None or session.identity is None:
            return RedirectResponse("/login",303)
        try:
            data = await asyncio.to_thread(read_queue,settings)
        except psycopg.Error:
            return PlainTextResponse("Database unavailable",503)
        response = HTMLResponse(views.queue(data,session))
        return session_cookie(response,key) if key else response

    async def login(request):
        if auth.mode == "dev":
            try:
                key = auth.create_session(None)
            except ValueError:
                return PlainTextResponse("Sign-in unavailable",503)
            auth.sessions.pop(request.cookies.get(SESSION_COOKIE),None)
            options = "".join(f'<option value="{views.text(oid)}">{views.text(oid)} ({views.text(person.role)})</option>' for oid,person in auth.users.items())
            body = '<p>Local development sign-in</p>'+views.form("/login",auth.sessions[key].csrf,"Sign in",'<label>User <select name="user">'+options+'</select></label>')
            return session_cookie(HTMLResponse(views.PAGE.substitute(body=body)),key)
        try:
            cookie,url = auth.begin()
        except ValueError:
            return PlainTextResponse("Sign-in unavailable",503)
        response = RedirectResponse(url,303)
        # The IdP redirects across sites. Only this correlation cookie is Lax; it grants no access.
        response.set_cookie(FLOW_COOKIE,cookie,max_age=300,httponly=True,secure=auth.secure,samesite="lax",path="/auth/callback")
        return response

    async def callback(request):
        try:
            key = await auth.complete(request.cookies.get(FLOW_COOKIE),request.query_params.get("state"),request.query_params.get("code"))
        except (ValueError,KeyError,TypeError,httpx2.HTTPError):
            response = PlainTextResponse("Sign-in failed",401)
        else:
            auth.sessions.pop(request.cookies.get(SESSION_COOKIE),None)
            # A fresh same-origin navigation sends Strict cookies after the cross-site callback.
            response = session_cookie(HTMLResponse(views.PAGE.substitute(body='<p>Signed in. <a href="/">Continue to approvals</a></p>')),key)
        response.delete_cookie(FLOW_COOKIE,path="/auth/callback",secure=auth.secure,httponly=True,samesite="lax")
        return response

    async def post(request):
        session = auth.session(request.cookies.get(SESSION_COOKIE))
        if session is None:
            return PlainTextResponse("Unauthorised",401)
        if request.headers.get("content-type","").split(";",1)[0] != "application/x-www-form-urlencoded":
            return PlainTextResponse("Invalid form",403)
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body)>8192:
                return PlainTextResponse("Form too large",413)
        try:
            parsed = parse_qs(body.decode("utf-8"),max_num_fields=20,keep_blank_values=True)
        except (UnicodeError,ValueError):
            return PlainTextResponse("Invalid form",400)
        if any(len(values)!=1 for values in parsed.values()):
            return PlainTextResponse("Invalid form",400)
        fields = {name:values[0] for name,values in parsed.items()}
        if not hmac.compare_digest(session.csrf.encode(),fields.get("csrf","").encode()):
            return PlainTextResponse("CSRF verification failed",403)
        path = request.url.path
        if path == "/login" and auth.mode == "dev":
            person = auth.users.get(fields.get("user"))
            if person is None:
                return PlainTextResponse("Unauthorised",401)
            try:
                key = auth.create_session(person)
            except ValueError:
                return PlainTextResponse("Sign-in unavailable",503)
            auth.sessions.pop(request.cookies.get(SESSION_COOKIE),None)
            return session_cookie(RedirectResponse("/",303),key)
        if session.identity is None:
            return PlainTextResponse("Unauthorised",401)
        if path == "/agents/resume" and session.identity.role != "SeniorApprover":
            return PlainTextResponse("SeniorApprover required",403)
        if path == "/logout":
            auth.sessions.pop(request.cookies.get(SESSION_COOKIE),None)
            response = RedirectResponse("/login",303)
            response.delete_cookie(SESSION_COOKIE,httponly=True,secure=auth.secure,samesite="strict")
            return response
        try:
            await asyncio.to_thread(mutate,settings,path,request.path_params.get("id"),fields,session.identity)
        except (psycopg.Error,ValueError):
            return PlainTextResponse("Action refused",409)
        return RedirectResponse("/",303)

    @asynccontextmanager
    async def lifespan(app):
        async def pulse():
            while True:
                if heartbeat:
                    heartbeat.beat()
                await asyncio.sleep(10)
        task=asyncio.create_task(pulse())
        try:
            yield
        finally:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    app=Starlette(routes=[Route("/",queue),Route("/login",login),Route("/login",post,methods=["POST"]),Route("/auth/callback",callback),
                         Route("/approve/{id:int}",post,methods=["POST"]),Route("/reject/{id:int}",post,methods=["POST"]),
                         Route("/agents/resume",post,methods=["POST"]),Route("/logout",post,methods=["POST"])],lifespan=lifespan)
    app.state.auth=auth

    async def headers(request,call_next):
        response=await call_next(request)
        response.headers["Content-Security-Policy"]="default-src 'self'; frame-ancestors 'none'"
        response.headers["Cache-Control"]="no-store"
        response.headers["Referrer-Policy"]="no-referrer"
        response.headers["X-Content-Type-Options"]="nosniff"
        return response
    app.add_middleware(BaseHTTPMiddleware,dispatch=headers)
    return app


def main():
    heartbeat=Heartbeat()
    app=build_app(heartbeat=heartbeat)
    ops=start_ops_server(9000,Metrics(),heartbeat)
    try:
        # Listen on the container's staff network; the Kubernetes Service decides who reaches it.
        uvicorn.run(app,host="0.0.0.0",port=8084,access_log=False,log_level="warning")  # nosec B104
    finally:
        ops.shutdown()


if __name__ == "__main__":
    main()
