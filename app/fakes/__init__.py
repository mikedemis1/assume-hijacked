"""Fakes of the systems outside the supplier, so the stack runs end to end without them:

  fake           port  route             caller          the real system
  fake-register  8090  GET /protected    register-sync   the state register of homes with
                                                         life-support equipment
  fake-dso       8091  POST /orders      executor        the grid operator, who disconnects
  fake-sms       8092  POST /messages    executor        the SMS provider, who tells the occupier

Each records the calls it accepted, in memory (GET /calls), so tests can see what the system did
to the outside world. Each accepts only its one caller:
  compose  the network is the wall (one internal edge network per caller, compose.yaml).
  k8s      every request carries the caller's projected service account token with the audience
           fake-<name>; a TokenReview says whose it is, and only the expected service account
           passes. The token is checked from the headers, before the body is read.
GET /calls answers the container itself (loopback) or the caller, nobody else.

Logs and metrics carry names, outcomes and the caller only. Never a body: an order or a notice
names a home, and the real ones would carry an address or a phone number.
"""

from __future__ import annotations

import ipaddress
import json
import os
import ssl
import threading
import time
import urllib.request
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from app.agent.events import security_event
from app.common.calls import MODES, caller_auth_mode
from app.common.ops import Heartbeat, Metrics, start_ops_server

OPS_PORT = 9000
MAX_BODY_BYTES = 16 * 1024
DRAIN_BYTES = 64 * 1024  # a refused request's body is read and dropped up to this size
MAX_CALLS = 1000
BEAT_SECONDS = 5
SERVICE_ACCOUNT = "system:serviceaccount:ah-core:{}"  # the callers run in ah-core

# token, audience -> the caller's username, or None when the token is not valid for the audience.
Verifier = Callable[[str, str], "str | None"]


@dataclass(frozen=True)
class Route:
    method: str
    path: str
    fields: Mapping[str, type] | None  # a POST body has exactly these fields, of these types
    answer: Callable[[], dict]
    status: int


@dataclass(frozen=True)
class Fake:
    name: str
    port: int
    caller: str  # the Kubernetes username of the one service account allowed to call
    route: Route

    @property
    def audience(self) -> str:
        return f"fake-{self.name}"


def _protected_homes() -> dict:
    """The register's list: FAKE_REGISTER_PROTECTED (comma separated), by default the seeded
    life-support home SP-1003."""
    listed = os.environ.get("FAKE_REGISTER_PROTECTED", "SP-1003")
    return {"protected": [sp.strip() for sp in listed.split(",") if sp.strip()]}


FAKES = {
    "register": Fake("register", 8090, SERVICE_ACCOUNT.format("register-sync"),
                     Route("GET", "/protected", None, _protected_homes, 200)),
    "dso": Fake("dso", 8091, SERVICE_ACCOUNT.format("executor"),
                Route("POST", "/orders", {"request_id": int, "order_id": int, "supply_point_id": str},
                      lambda: {"accepted": True}, 202)),
    "sms": Fake("sms", 8092, SERVICE_ACCOUNT.format("executor"),
                Route("POST", "/messages", {"request_id": int, "notice_id": int, "supply_point_id": str},
                      lambda: {"accepted": True}, 202)),
}


class TokenReviewVerifier:
    """Asks the Kubernetes API whose token this is, for one audience (authentication.k8s.io/v1
    TokenReview). Anything but a clear "authenticated, for this audience" is None: fail closed.
    The pod needs its API token mounted and RBAC `create` on tokenreviews."""

    def __init__(
        self,
        api_url: str | None = None,
        sa_dir: str = "/var/run/secrets/kubernetes.io/serviceaccount",
        post: Callable[[dict], object] | None = None,
        timeout_s: float = 3,
    ) -> None:
        host, port = os.environ.get("KUBERNETES_SERVICE_HOST"), os.environ.get("KUBERNETES_SERVICE_PORT", "443")
        self.api_url = api_url or (f"https://{host}:{port}" if host else "https://kubernetes.default.svc")
        self.sa_dir = Path(sa_dir)
        self.timeout_s = timeout_s
        self._post = post or self._post_to_api

    def __call__(self, token: str, audience: str) -> str | None:
        if not token:
            return None
        body = {"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview",
                "spec": {"token": token, "audiences": [audience]}}
        try:
            answer = self._post(body)
        except Exception:  # an API server that is down or odd means "not verified"
            return None
        status = answer.get("status") if isinstance(answer, dict) else None
        if not isinstance(status, dict) or status.get("authenticated") is not True:
            return None
        if audience not in (status.get("audiences") or []):
            return None
        user = status.get("user")
        username = user.get("username") if isinstance(user, dict) else None
        return username if isinstance(username, str) and username else None

    def _post_to_api(self, body: dict) -> object:
        own_token = (self.sa_dir / "token").read_text(encoding="utf-8").strip()
        context = ssl.create_default_context(cafile=str(self.sa_dir / "ca.crt"))
        request = urllib.request.Request(
            f"{self.api_url}/apis/authentication.k8s.io/v1/tokenreviews",
            data=json.dumps(body).encode(), method="POST",
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {own_token}"},
        )
        # The API server's https URL from the pod's own environment, its CA from the mounted bundle.
        with urllib.request.urlopen(request, timeout=self.timeout_s, context=context) as answer:  # nosec B310
            return json.loads(answer.read(64 * 1024))


def _is_loopback(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    mapped = getattr(ip, "ipv4_mapped", None)
    return (mapped or ip).is_loopback


class FakeServer(threading.Thread):
    """One fake's HTTP server thread. `port` is the bound port; calls() what it recorded."""

    def __init__(self, fake: Fake, mode: str, verifier: Verifier | None, max_calls: int = MAX_CALLS) -> None:
        super().__init__(name=f"fake-{fake.name}", daemon=True)
        self.fake = fake
        self.mode = mode
        self.verifier = verifier
        self.max_calls = max_calls
        self._calls: deque = deque(maxlen=max_calls)
        self._lock = threading.Lock()
        self._httpd: ThreadingHTTPServer | None = None
        self.port = 0

    def run(self) -> None:
        self._httpd.serve_forever(poll_interval=0.1)

    def shutdown(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()

    def record(self, call: dict) -> None:
        with self._lock:
            self._calls.append(call)

    def calls(self) -> list[dict]:
        with self._lock:
            return list(self._calls)

    def caller(self, token: str | None) -> tuple[str | None, int]:
        """(who is calling, 0) or (None, the refusal status)."""
        if self.mode == "compose":
            return "network", 0
        if not token:
            return None, 401
        user = self.verifier(token, self.fake.audience)
        if user is None:
            return None, 401
        if user != self.fake.caller:
            return user, 403
        return user, 0

    def allows_calls_list(self, client_ip: str, token: str | None) -> bool:
        if _is_loopback(client_ip):
            return True  # the fake's own container or pod (docker exec, kubectl exec)
        _, refused = self.caller(token)
        return refused == 0


def _make_handler(server: FakeServer, metrics: Metrics | None, request_timeout_s: float):
    fake = server.fake

    class Handler(BaseHTTPRequestHandler):
        timeout = request_timeout_s  # a client that never finishes its request is cut off

        def do_GET(self) -> None:  # noqa: N802 (name fixed by http.server)
            self._handle("GET")

        def do_POST(self) -> None:  # noqa: N802
            self._handle("POST")

        def _handle(self, method: str) -> None:
            self._body_read = False
            path = urlsplit(self.path).path
            token = self._bearer()
            if path == "/calls":
                if method != "GET":
                    return self._refuse(405, "calls", "bad_request")
                if not server.allows_calls_list(self.client_address[0], token):
                    return self._refuse(403, "calls", "forbidden")
                return self._json(200, {"calls": server.calls()})
            route = fake.route
            if path != route.path:
                return self._refuse(404, "other", "not_found")
            if method != route.method:
                return self._refuse(405, route.path, "bad_request")
            caller, refused = server.caller(token)
            if refused:
                outcome = "forbidden" if refused == 403 else "unauthenticated"
                return self._refuse(refused, route.path, outcome, caller)
            body = None
            if route.fields is not None:
                body, refused = self._body(route.fields)
                if refused:
                    return self._refuse(refused, route.path, "bad_request", caller)
            server.record({"method": method, "path": route.path, "caller": caller, "body": body})
            self._done(route.path, "accepted", caller)
            return self._json(route.status, route.answer())

        def _bearer(self) -> str | None:
            value = self.headers.get("Authorization", "")
            scheme, _, token = value.partition(" ")
            return (token.strip() or None) if scheme.lower() == "bearer" else None

        def _body(self, fields: Mapping[str, type]) -> tuple[dict | None, int]:
            length = self.headers.get("Content-Length")
            if length is None:
                return None, 411
            try:
                size = int(length)
            except ValueError:
                return None, 400
            if size < 0:
                return None, 400
            if size > MAX_BODY_BYTES:
                return None, 413
            self._body_read = True
            try:
                body = json.loads(self.rfile.read(size))
            except ValueError:
                return None, 400
            if not isinstance(body, dict) or set(body) != set(fields):
                return None, 400
            # type() and not isinstance(): True is an int to isinstance.
            if any(type(body[name]) is not kind for name, kind in fields.items()):
                return None, 400
            return body, 0

        def _done(self, route: str, outcome: str, caller: str | None = None) -> None:
            if metrics is not None:
                metrics.inc("fake_requests_total", {"fake": fake.name, "outcome": outcome})
            security_event("fake_call", fake=fake.name, route=route, outcome=outcome, caller=caller or "none")

        def _refuse(self, status: int, route: str, outcome: str, caller: str | None = None) -> None:
            self._done(route, outcome, caller)
            self._drop_unread_body()
            self._json(status, {"error": outcome})

        def _drop_unread_body(self) -> None:
            """Read a refused request's body and throw it away, never parsed: a socket closed with
            unread data is reset, and the client would see the reset instead of the answer."""
            if self._body_read:
                return
            try:
                size = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                return
            if 0 < size <= DRAIN_BYTES:
                self.rfile.read(size)

        def _json(self, status: int, payload: dict) -> None:
            data = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, format: str, *args) -> None:  # noqa: A002
            pass  # the request line could carry anything; the security event above is the log

    return Handler


class _QuietServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64


def start_fake(
    fake: Fake,
    port: int | None = None,
    mode: str = "compose",
    verifier: Verifier | None = None,
    metrics: Metrics | None = None,
    host: str = "0.0.0.0",  # nosec B104 - see below
    request_timeout_s: float = 10,
    max_calls: int = MAX_CALLS,
) -> FakeServer:
    # All interfaces of the container: the caller is another container or pod. The wall is the
    # network (compose) or the caller token (k8s), checked on every request.
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}, got {mode!r}")
    if mode == "k8s" and verifier is None:
        raise ValueError("k8s mode needs a token verifier")
    server = FakeServer(fake, mode, verifier, max_calls)
    handler = _make_handler(server, metrics, request_timeout_s)
    server._httpd = _QuietServer((host, fake.port if port is None else port), handler)
    server.port = server._httpd.server_address[1]
    server.start()
    return server


def _forever(server: threading.Thread, heartbeat: Heartbeat, sleep: Callable[[float], None] = time.sleep) -> None:
    """/healthz stays 200 while the HTTP thread lives. If it dies, the process exits and Compose or
    Kubernetes starts a new one."""
    while server.is_alive():
        heartbeat.beat()
        sleep(BEAT_SECONDS)
    raise SystemExit("the fake's HTTP server stopped")


def run(fake: Fake, port: int | None = None, ops_port: int = OPS_PORT, block: bool = True):
    """The process of one fake: its HTTP server and ops (/healthz, /metrics) on 9000."""
    mode = caller_auth_mode()
    verifier = TokenReviewVerifier() if mode == "k8s" else None
    metrics, heartbeat = Metrics(), Heartbeat()
    ops = start_ops_server(ops_port, metrics, heartbeat)
    server = start_fake(fake, port=port, mode=mode, verifier=verifier, metrics=metrics)
    if not block:
        return server, ops
    _forever(server, heartbeat)
