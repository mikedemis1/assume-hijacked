"""DEMO ONLY, never part of the image or the chart: answers the demo UI's tickets on a PC without a
cluster. On kind the dispatcher starts an agent Job per ticket; here the same dispatcher, the real
tool gateway, the real risk engine and the scripted agent run in this process (the way
tests/unit/test_agent.py runs them), against the test database.

    sh scripts/test-db.sh start
    DB_NAME=supplier_test .venv/Scripts/python -m app.demo.main            # the page, on :8085
    .venv/Scripts/python -m tests.demo_local                                # the answers

It also runs the risk engine's and the executor's rounds for the effect requests, so the panel can
show a credit waiting for an approval. Stop it with Ctrl-C.
"""

from __future__ import annotations

import dataclasses
import json
import time
from datetime import datetime, timezone

from app import config, db
from app.agent.core import Agent
from app.agent.llm import ScriptedLLM
from app.executor.main import run_once
from app.risk.service import assess_pending
from tests.conftest import TEST_DB_NAME
from tests.dispatcherharness import Harness, pod_of, post
from tests.gatewayharness import AppGatewayClient, RealRisk, agent_auth, build

POLL_SECONDS = 0.5


def main() -> None:
    settings = dataclasses.replace(config.load(), db_name=TEST_DB_NAME)

    def as_role(role: str):
        return db.connect(settings, role)

    harness = Harness(settings, as_role, max_active=10)
    risk = RealRisk(settings)
    built = build(settings, as_role, risk=risk)  # one gateway connection for every ticket
    risk_conn, executor_conn = as_role("risk_engine"), as_role("executor")
    handled = 0
    print(f"demo_local: answering tickets in {settings.db_name} on port {settings.db_port}; Ctrl-C to stop", flush=True)
    while True:
        harness.dispatcher.dispatch_once()
        jobs = [job["metadata"]["name"] for job in harness.kube.created]
        for job in jobs[handled:]:
            pod = pod_of(job)
            claimed = post(harness.app, "/claim", headers=harness.agent(pod))
            if claimed.status_code != 200:
                print(f"demo_local: claim for {job} answered {claimed.status_code}", flush=True)
                continue
            ticket, lease = claimed.json()["ticket_id"], claimed.json()["lease"]
            gateway = AppGatewayClient(built, auth=agent_auth(pod=pod))
            agent = Agent(ScriptedLLM(), gateway)
            text = agent.handle_ticket(ticket, lease)
            # The real agent sends its own drops (names only) with the reply: the panel reads them from agent_events.
            answer = post(harness.app, "/reply", lease=lease, headers=harness.agent(pod),
                          body={"text": text, "events": agent.events})
            print(f"demo_local: ticket {ticket} answered ({answer.status_code}) {json.dumps(answer.json())[:40]}", flush=True)
        handled = len(jobs)
        assess_pending(risk_conn, settings, datetime.now(timezone.utc))
        run_once(executor_conn, settings, datetime.now(timezone.utc))
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
