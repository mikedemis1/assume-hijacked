"""Ops endpoints every long-running service serves on its own port (9000):
GET /healthz (200, or 503 when the service's heartbeat is stale) and GET /metrics (Prometheus
text format, written by hand: https://prometheus.io/docs/instrumenting/exposition_formats/).

Metric names, label names and label values are names, ids and categories only. Never ticket text,
argument values, health data or tokens (the rule in app/common/events.py).
"""

from __future__ import annotations

import re
import sys
import threading
import time
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

_NAME = re.compile(r"[a-zA-Z_:][a-zA-Z0-9_:]*")
_LABEL_NAME = re.compile(r"[a-zA-Z_][a-zA-Z0-9_]*")
_CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _number(value: float) -> str:
    return str(int(value)) if float(value).is_integer() else repr(float(value))


class Metrics:
    """Counters and gauges, safe to update from several threads."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._kinds: dict[str, str] = {}
        self._samples: dict[str, dict[tuple[tuple[str, str], ...], float]] = {}

    def _slot(self, name: str, kind: str, labels: dict[str, str] | None):
        if not _NAME.fullmatch(name):
            raise ValueError(f"bad metric name {name!r}")
        for label in labels or {}:
            if not _LABEL_NAME.fullmatch(label):
                raise ValueError(f"bad label name {label!r}")
        if self._kinds.setdefault(name, kind) != kind:
            raise ValueError(f"{name} is a {self._kinds[name]}, not a {kind}")
        key = tuple(sorted((k, str(v)) for k, v in (labels or {}).items()))
        return self._samples.setdefault(name, {}), key

    def inc(self, name: str, labels: dict[str, str] | None = None, by: float = 1) -> None:
        if by < 0:
            raise ValueError("a counter only goes up")
        with self._lock:
            samples, key = self._slot(name, "counter", labels)
            samples[key] = samples.get(key, 0) + by

    def set(self, name: str, value: float, labels: dict[str, str] | None = None) -> None:
        with self._lock:
            samples, key = self._slot(name, "gauge", labels)
            samples[key] = value

    def render(self) -> str:
        lines = []
        with self._lock:
            for name in sorted(self._samples):
                lines.append(f"# TYPE {name} {self._kinds[name]}")
                for key, value in sorted(self._samples[name].items()):
                    labels = ",".join(f'{k}="{_escape(v)}"' for k, v in key)
                    lines.append(f"{name}{{{labels}}} {_number(value)}" if labels else f"{name} {_number(value)}")
        return "\n".join(lines) + "\n"


class Heartbeat:
    """A service calls beat() each time round its main loop. It is alive while the last beat is at
    most max_age_s old. Starting counts as the first beat, so a service stuck before its first loop
    also goes stale."""

    def __init__(self, max_age_s: float = 60, clock: Callable[[], float] = time.monotonic) -> None:
        self.max_age_s = max_age_s
        self.clock = clock
        self._last = clock()

    def beat(self) -> None:
        self._last = self.clock()

    def alive(self, now: float) -> bool:
        return now - self._last <= self.max_age_s


class OpsServer(threading.Thread):
    """The thread that serves the ops endpoints. `port` is the bound port (useful with port 0)."""

    def __init__(self, httpd: ThreadingHTTPServer, request_timeout_s: float) -> None:
        super().__init__(name="ops-server", daemon=True)
        self._httpd = httpd
        self.port = httpd.server_address[1]
        self.request_timeout_s = request_timeout_s

    def run(self) -> None:
        self._httpd.serve_forever()

    def shutdown(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()


class _QuietServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address) -> None:
        # A client that timed out or hung up is not worth a traceback on stderr; a bug still is.
        if not isinstance(sys.exc_info()[1], (TimeoutError, ConnectionError)):
            super().handle_error(request, client_address)


def start_ops_server(
    port: int,
    metrics: Metrics,
    heartbeat: Heartbeat,
    host: str = "0.0.0.0",  # nosec B104 - see below
    request_timeout_s: float = 10,
) -> OpsServer:
    # All interfaces of the container, like app/tools/serve.py: Prometheus reaches /metrics from
    # another container or pod. The network is the wall (NetworkPolicy),
    # and both endpoints carry no content beyond counts and names.
    class Handler(BaseHTTPRequestHandler):
        # A socket timeout per connection: a client that sends half a request and waits would
        # otherwise hold a server thread for good, and enough of them would starve the probes.
        timeout = request_timeout_s

        def do_GET(self) -> None:  # noqa: N802 (name fixed by http.server)
            path = urlsplit(self.path).path  # /metrics?x=1 is /metrics
            if path == "/healthz":
                if heartbeat.alive(heartbeat.clock()):
                    self._send(200, "ok\n")
                else:
                    self._send(503, "stale\n")
            elif path == "/metrics":
                self._send(200, metrics.render())
            else:
                self._send(404, "not found\n")

        def _send(self, status: int, body: str) -> None:
            data = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", _CONTENT_TYPE)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, format: str, *args) -> None:  # noqa: A002
            pass  # one line per probe would drown the service's own security log

    server = OpsServer(_QuietServer((host, port), Handler), request_timeout_s)
    server.start()
    return server
