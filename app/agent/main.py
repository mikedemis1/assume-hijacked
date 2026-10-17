"""python -m app.agent.main <ticket_id>: answer one ticket using the tool servers.

The lease for the ticket comes from AGENT_LEASE. Until the dispatcher exists (task A9), whoever
starts the agent opens the lease first (tests/test_smoke.py does it as the database admin).
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
    settings = config.load()
    targets = {tool: os.environ[f"TOOL_URL_{tool.upper()}"] for tool in TOOLS}
    agent = Agent(ScriptedLLM(), ToolGateway(targets), vulnerable=settings.vulnerable)
    print(agent.handle_ticket(ticket_id, lease))


if __name__ == "__main__":
    main()
