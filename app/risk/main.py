"""Risk engine process: POST /decide on port 8082, the effect loop, ops on port 9000.

The loop runs in the main thread: if it dies, the process exits and Compose (restart:
unless-stopped) or Kubernetes starts a new one. /decide runs in a daemon thread with its own
database connection, so a slow assessment never holds up a tool call.
"""

from __future__ import annotations

import threading
import time
from datetime import datetime, timezone

import uvicorn

from app import config
from app.common.ops import Heartbeat, Metrics, start_ops_server
from app.risk import service

POLL_SECONDS = 2
DECIDE_PORT = 8082
OPS_PORT = 9000


def poll(conn, settings, now: datetime, metrics: Metrics, heartbeat: Heartbeat) -> None:
    """One trip round the loop. Both beats come after the work, so a hung database call turns
    /healthz into 503 and leaves the database heartbeat to age."""
    service.assess_pending(conn, settings, now, metrics)
    conn.execute("SELECT beat('risk-engine')")
    metrics.set("risk_last_assess_timestamp_seconds", now.timestamp())
    heartbeat.beat()


def serve_decide(app, port: int = DECIDE_PORT) -> threading.Thread:
    # All interfaces of the container: the gateway calls it from another container. The network is
    # the wall (edge_gateway_risk in compose.yaml; NetworkPolicy in Kubernetes). No access log: the body
    # carries the lease, and the path alone tells nobody anything.
    server = uvicorn.Server(
        uvicorn.Config(app, host="0.0.0.0", port=port, access_log=False, log_level="warning")  # nosec B104
    )
    thread = threading.Thread(target=server.run, name="decide", daemon=True)
    thread.start()
    return thread


def main() -> None:
    settings = config.load()
    metrics = Metrics()
    heartbeat = Heartbeat()
    start_ops_server(OPS_PORT, metrics, heartbeat)
    decide = serve_decide(service.build_app(service.Decider(lambda: service.connect_for_decide(settings), metrics), metrics))
    with service.connect(settings) as conn:
        while True:
            if not decide.is_alive():  # exit, so the process is restarted with /decide up again
                raise SystemExit("the /decide server stopped")
            poll(conn, settings, datetime.now(timezone.utc), metrics, heartbeat)
            time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
