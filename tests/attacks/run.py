"""python -m attacks.run <command>: the attack suite's entry point (in the repository: python -m tests.attacks.run).

  serve PORT[,PORT...]   listen on these TCP ports and accept every connection, until stopped.
                         A stand-in for a component that is not deployed, so a probe aimed at
                         it connects when the walls let it through.
  probe                  read {"probes": [...], "addresses": {...}} (JSON) on stdin, run every
                         probe at once, print {"results": [...]} on stdout. Exit 1 on a mismatch.
  suite SOURCE           the in-cluster run (the chart's attack-suite test pods): every probe of
                         the matrix whose source is SOURCE, against the real Services. One JSON
                         line per probe on stdout. Exit 1 on a mismatch.
  replay                 attack tickets 1-11 against the dispatcher and the tool gateway
                         (DISPATCHER_URL, GATEWAY_URL). One JSON line per ticket. Exit 1 when
                         one fails.
"""

from __future__ import annotations

import json
import secrets
import socket
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

from . import probes, tickets


def serve(ports: list[int]) -> None:
    def accept_forever(server: socket.socket) -> None:
        while True:
            conn, _ = server.accept()
            conn.close()

    for port in ports:
        server = socket.create_server(("", port))
        threading.Thread(target=accept_forever, args=(server,), daemon=True).start()
    print(json.dumps({"listening": ports}), flush=True)
    threading.Event().wait()


def run_probes(plan: list[probes.Probe], addresses: dict[str, str]) -> list[dict]:
    token = secrets.token_hex(6)
    with ThreadPoolExecutor(max_workers=max(1, len(plan))) as pool:
        return list(pool.map(lambda p: probes.run_probe(p, addresses, token), plan))


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    command, args = argv[0], argv[1:]
    if command == "serve":
        serve([int(p) for p in ",".join(args).split(",") if p])
        return 0
    if command == "probe":
        request = json.load(sys.stdin)
        plan = [probes.Probe.from_json(p) for p in request["probes"]]
        results = run_probes(plan, request.get("addresses", {}))
        print(json.dumps({"results": results}))
        return 1 if probes.mismatches(results) else 0
    if command == "suite":
        if len(args) != 1 or args[0] not in probes.COMPONENTS:
            print(f"suite needs one source of {sorted(probes.COMPONENTS)}", file=sys.stderr)
            return 2
        plan = [p for p in probes.matrix() if p.source == args[0]]
        results = run_probes(plan, probes.service_addresses())
        for result in results:
            print(json.dumps(result))
        return 1 if probes.mismatches(results) else 0
    if command == "replay":
        report = tickets.replay_all(tickets.HttpAgentApi.from_env())
        for line in report:
            print(json.dumps(line))
        return 0 if all(line["passed"] for line in report) else 1
    print(f"unknown command {command!r}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
