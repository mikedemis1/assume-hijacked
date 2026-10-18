"""python -m app.agent.main <ticket_id>: answer one ticket using the tool servers.

The lease for the ticket comes from AGENT_LEASE: whoever starts the agent opens it first
(tests/test_smoke.py does it as the database admin). The agent never puts the lease in a tool
argument; the tool client sends it to the tool gateway in a header (app/agent/gateway.py).

GATEWAY_URL is the tool gateway's MCP endpoint, the agent's only way to a tool. The agent holds no
key: the gateway signs the tokens the tools check, and in Kubernetes the agent proves who it is with
its projected service account token (CALLER_AUTH=k8s).
"""

from __future__ import annotations

import logging
import os
import sys

from app import config
from app.agent.core import Agent
from app.agent.events import LOGGER
from app.agent.gateway import ToolGateway
from app.agent.llm import ScriptedLLM
from app.common.calls import auth_headers


def main() -> None:
    # Security events are one JSON line each on stderr. Stdout carries only the reply, so a model
    # that writes a fake event line into its reply cannot pass it off as one.
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(message)s"))
    LOGGER.addHandler(handler)
    LOGGER.setLevel(logging.INFO)
    LOGGER.propagate = False
    ticket_id = int(sys.argv[1])
    lease = os.environ.get("AGENT_LEASE", "")
    if not lease:
        sys.exit("AGENT_LEASE is not set: open a lease for the ticket first (SELECT open_lease(...)).")
    url = os.environ.get("GATEWAY_URL", "")
    if not url:
        sys.exit("GATEWAY_URL is not set: the agent calls the tools only through the tool gateway.")
    settings = config.load()
    gateway = ToolGateway(url, lambda: auth_headers("tool-gateway", settings.caller_auth))
    agent = Agent(ScriptedLLM(), gateway, vulnerable=settings.vulnerable)
    print(agent.handle_ticket(ticket_id, lease))


if __name__ == "__main__":
    main()
