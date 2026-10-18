# Temporary stand-in for a component whose code is not in this tree yet. Delete this file and
# values-kind-stubs.yaml once the application code is merged: then every component runs its own
# entry point.
#
# It serves what the cluster needs from every long-running component, on port 9000 only:
#   GET /healthz  200 (the liveness and readiness probes)
#   GET /metrics  Prometheus text: ah_stub_up{component="<name>"} 1
# and nothing else. The chart runs it as `python -c <this file> <component>`.
import re
import signal
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 9000
COMPONENT = sys.argv[1] if len(sys.argv) > 1 else ""
if not re.fullmatch(r"[a-z][a-z0-9-]{0,62}", COMPONENT):
    sys.exit("usage: python -c <ops-stub.py> <component name>")
METRICS = f'# TYPE ah_stub_up gauge\nah_stub_up{{component="{COMPONENT}"}} 1\n'.encode()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/healthz":
            self._answer(200, b"ok\n", "text/plain; charset=utf-8")
        elif self.path == "/metrics":
            self._answer(200, METRICS, "text/plain; version=0.0.4; charset=utf-8")
        else:
            self._answer(404, b"not found\n", "text/plain; charset=utf-8")

    def _answer(self, status, body, content_type):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def stop(*_):
    # PID 1 ignores SIGTERM unless it handles it: without this a pod waits out its grace period.
    sys.exit(0)


signal.signal(signal.SIGTERM, stop)
print(f"ops stand-in for {COMPONENT} on :{PORT}", flush=True)
ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()  # nosec B104: the pod's own port
