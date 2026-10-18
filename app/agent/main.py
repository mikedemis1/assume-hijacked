"""python -m app.agent.main: one run. Claim a ticket, work on it, send the reply, exit.

    1. POST /claim to the dispatcher: the ticket and the lease the run works under. Nothing to claim
       is a quiet exit. The agent never chooses its ticket (it takes no argument and reads no ticket
       number or lease from its environment).
    2. The loop (app/agent/core.py): the model is the LLM gateway, every tool call goes through the
       tool gateway with the lease in the header X-Lease.
    3. POST /reply to the dispatcher with the text. The dispatcher runs the reply guard again, adds
       the credit notice and the medical question itself, stores the reply and ends the lease.

GATEWAY_URL is the tool gateway's MCP endpoint, LLM_GATEWAY_URL the LLM gateway, DISPATCHER_URL the
dispatcher. Those are the agent's three edges and the only addresses it knows. The agent holds no
database password, no signing key and no model key; in Kubernetes it proves who it is to each of the
three with its own projected service account token for that peer's audience (CALLER_AUTH=k8s).

Exit code 0: the reply was stored, or there was nothing to claim. 1: the claim or the reply failed
(a category in the security log; the Job is not restarted, a person looks at the ticket).
"""

from __future__ import annotations

import logging
import os
import sys
from collections.abc import Callable

from app import config
from app.agent.core import Agent
from app.agent.dispatcher_client import DispatcherClient, DispatcherError
from app.agent.events import LOGGER, security_event
from app.agent.gateway import ToolGateway
from app.agent.llm_client import LlmGatewayClient
from app.common.calls import auth_headers


def run(dispatcher, llm_for: Callable[[str], object], tools, vulnerable: bool) -> int:
    """One run. `dispatcher` has claim() and reply(lease, text); `llm_for(lease)` builds the model
    client for the lease just handed out; `tools` has call(name, args)."""
    try:
        claim = dispatcher.claim()
    except DispatcherError as err:
        security_event("claim_failed", category=err.category)
        return 1
    if claim is None:
        security_event("no_ticket")
        return 0
    agent = Agent(llm_for(claim.lease), tools, vulnerable=vulnerable)
    text = agent.handle_ticket(claim.ticket_id, claim.lease)
    try:
        dispatcher.reply(claim.lease, text)
    except DispatcherError as err:
        security_event("reply_failed", ticket_id=claim.ticket_id, category=err.category)
        return 1
    security_event("reply_sent", ticket_id=claim.ticket_id)
    return 0


def _address(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        sys.exit(f"{name} is not set: the agent talks only to the dispatcher, the LLM gateway and the tool gateway.")
    return value


def main() -> None:
    # Security events are one JSON line each on stderr. Stdout stays empty: the reply goes to the
    # dispatcher, and a model that writes a fake event line into its reply cannot pass it off as one.
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(message)s"))
    LOGGER.addHandler(handler)
    LOGGER.setLevel(logging.INFO)
    LOGGER.propagate = False
    if len(sys.argv) > 1:
        sys.exit("the agent takes no ticket number: the dispatcher decides which ticket this run is for.")
    tool_url, llm_url, dispatcher_url = _address("GATEWAY_URL"), _address("LLM_GATEWAY_URL"), _address("DISPATCHER_URL")
    settings = config.load()
    mode = settings.caller_auth
    dispatcher = DispatcherClient(dispatcher_url, lambda: auth_headers("dispatcher", mode))
    tools = ToolGateway(tool_url, lambda: auth_headers("tool-gateway", mode))

    def llm_for(lease: str) -> LlmGatewayClient:
        return LlmGatewayClient(llm_url, lease, lambda: auth_headers("llm-gateway", mode))

    sys.exit(run(dispatcher, llm_for, tools, settings.vulnerable))


if __name__ == "__main__":
    main()
