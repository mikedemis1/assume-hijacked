"""python -m app.agent.main <ticket_id>: answer one ticket using the tool servers.

The lease for the ticket comes from AGENT_LEASE: whoever starts the agent opens it first
(tests/test_smoke.py does it as the database admin). The agent never puts the lease in a tool
argument; the tool client signs a token with it for each request (app/agent/gateway.py).

GATEWAY_SIGNING_KEY_FILE is the key that signs those tokens. It is here only because the agent
calls the tools itself; the tool gateway is the only component that should hold it.
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
from app.security.tokens import load_private_key
from app.tools.serve import TOOLS


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
    key_file = os.environ.get("GATEWAY_SIGNING_KEY_FILE", "")
    if not key_file:
        sys.exit("GATEWAY_SIGNING_KEY_FILE is not set: the tools accept only calls signed with the gateway key.")
    signing_key = load_private_key(key_file)
    settings = config.load()
    targets = {tool: os.environ[f"TOOL_URL_{tool.upper()}"] for tool in TOOLS}
    agent = Agent(ScriptedLLM(), ToolGateway(targets, signing_key), vulnerable=settings.vulnerable)
    print(agent.handle_ticket(ticket_id, lease))


if __name__ == "__main__":
    main()
