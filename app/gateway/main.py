"""python -m app.gateway.main: the tool gateway process.

    8080  /mcp     the MCP endpoint the agent calls (app/gateway/server.py)
    9000  /healthz /metrics   ops (app/common/ops.py)

Environment: GATEWAY_SIGNING_KEY_FILE (EC P-256 private key, PEM: the only copy of the key the
tools check), RISK_URL (http://risk-engine:8082), TOOL_URL_<TOOL> for each of the five tools,
DB_PASSWORD_GATEWAY, CALLER_AUTH (k8s, the only mode), CAPABILITIES_DIR (the reviewed manifests; default:
security/capabilities next to the code).

It does not start without any of these: a gateway that cannot sign, cannot ask the risk engine or
has no reviewed description to compare would have to let calls through or refuse all of them.
"""

from __future__ import annotations

import os
import threading
import time
from collections.abc import Mapping
from pathlib import Path

import uvicorn

from app import config, db
from app.common.events import security_event
from app.common.ops import Heartbeat, Metrics, start_ops_server
from app.gateway import manifest
from app.gateway.auth import CallerAuth
from app.gateway.proxy import Gateway, GatewayDb, RiskClient, ToolClient, init_metrics
from app.gateway.server import build_app
from app.security.tokens import load_private_key
from app.tools.serve import TOOLS

PORT = 8080
OPS_PORT = 9000
BEAT_SECONDS = 10
DB_CONNECT_TIMEOUT_S = 2
DB_STATEMENT_TIMEOUT_MS = 2000


def tool_urls(env: Mapping[str, str]) -> dict[str, str]:
    urls = {}
    for tool in TOOLS:
        name = f"TOOL_URL_{tool.upper()}"
        if not env.get(name):
            raise SystemExit(f"{name} is not set: the gateway needs the address of every tool")
        urls[tool] = env[name]
    return urls


def beat_loop(db_: GatewayDb, heartbeat: Heartbeat, metrics: Metrics) -> None:
    """The database heartbeat (heartbeats table) and the ops one, every BEAT_SECONDS. A database that
    does not answer leaves both to age: /healthz turns 503 after 60 s."""
    while True:
        try:
            db_.beat()
            heartbeat.beat()
        except Exception as err:
            metrics.inc("gateway_errors_total", {"stage": "heartbeat"})
            security_event("gateway_error", stage="heartbeat", error=type(err).__name__)
        time.sleep(BEAT_SECONDS)


def main() -> None:
    key_file = os.environ.get("GATEWAY_SIGNING_KEY_FILE", "")
    if not key_file:
        raise SystemExit("GATEWAY_SIGNING_KEY_FILE is not set: the gateway signs the tokens the tools check")
    risk_url = os.environ.get("RISK_URL", "")
    if not risk_url:
        raise SystemExit("RISK_URL is not set: the gateway asks the risk engine about every call")
    signing_key = load_private_key(key_file)
    urls = tool_urls(os.environ)
    if not os.environ.get("DB_PASSWORD_GATEWAY"):
        raise SystemExit("DB_PASSWORD_GATEWAY is not set")
    settings = config.load()
    try:
        specs = manifest.load_manifests(Path(os.environ["CAPABILITIES_DIR"]) if os.environ.get("CAPABILITIES_DIR") else None)
    except manifest.ManifestError as err:
        raise SystemExit(f"the capability manifests are not usable: {err}") from None

    try:
        auth = CallerAuth(mode=settings.caller_auth)
    except ValueError as err:
        raise SystemExit(str(err)) from None

    metrics = Metrics()
    init_metrics(metrics, specs)
    heartbeat = Heartbeat()
    start_ops_server(OPS_PORT, metrics, heartbeat)
    database = GatewayDb(
        lambda: db.connect(
            settings, "gateway", connect_timeout_s=DB_CONNECT_TIMEOUT_S, statement_timeout_ms=DB_STATEMENT_TIMEOUT_MS
        )
    )
    threading.Thread(target=beat_loop, args=(database, heartbeat, metrics), name="beat", daemon=True).start()
    gateway = Gateway(
        db=database,
        risk=RiskClient(risk_url),
        tools=ToolClient(urls, signing_key),
        specs=specs,
        metrics=metrics,
    )
    app = build_app(gateway, auth)
    # All interfaces of the container: the agent reaches it from another container or pod. The
    # network limits reachability, and the caller check verifies the projected token. No access
    # log: only the process's security events are written. proxy_headers off: no header is trusted.
    uvicorn.run(
        app, host="0.0.0.0", port=PORT, access_log=False, log_level="warning", proxy_headers=False  # nosec B104 - container network and caller authentication restrict access
    )


if __name__ == "__main__":
    main()
