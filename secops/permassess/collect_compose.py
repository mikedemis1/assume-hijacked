"""Docker Compose: which services can reach which, from the rendered configuration.

Two containers on the same Docker network can connect to each other on any port, and Docker
resolves a service name only on a network both share. So an edge here is a pair of services
that share at least one network (undirected: the network does not say who calls whom). A
network that is not `internal: true` also routes to the outside: `<service> -> internet`.
https://docs.docker.com/compose/how-tos/networking/
https://docs.docker.com/reference/compose-file/networks/#internal

The configuration comes from `docker compose config --format json` (no YAML parser needed),
with every profile and without interpolation, so no secret from .env is read or printed:
https://docs.docker.com/reference/cli/docker/compose/config/
"""
from __future__ import annotations

import json
from itertools import combinations
from pathlib import Path

from secops.permassess import CollectorError, PlaneResult, Runner, run_command

INTERNET = "internet"


def render(compose_file: str = "compose.yaml", run: Runner = run_command) -> dict:
    out = run(["docker", "compose", "-f", compose_file, "--profile", "*", "config",
               "--no-interpolate", "--format", "json"])
    return _parse(out, "docker compose config")


def load(path: Path) -> dict:
    """A configuration rendered earlier (the CI job has no Docker CLI, see ci/permissions.sh)."""
    try:
        return _parse(path.read_text(encoding="utf-8"), str(path))
    except OSError as exc:
        raise CollectorError(f"cannot read {path}: {exc.strerror}") from exc


def _parse(text: str, where: str) -> dict:
    try:
        config = json.loads(text)
    except json.JSONDecodeError as exc:
        raise CollectorError(f"{where}: not JSON ({exc.msg})") from exc
    if not isinstance(config, dict) or not isinstance(config.get("services"), dict):
        raise CollectorError(f"{where}: no services")
    return config


def pair(a: str, b: str) -> str:
    x, y = sorted((a, b))
    return f"compose {x} <-> {y}"


def egress(service: str) -> str:
    return f"compose {service} -> {INTERNET}"


def collect(config: dict) -> PlaneResult:
    services: dict = config["services"]
    networks: dict = config.get("networks") or {}
    member: dict[str, set[str]] = {}
    info: list[str] = []
    host_mode: set[str] = set()
    for name, svc in services.items():
        mode = (svc or {}).get("network_mode")
        nets = (svc or {}).get("networks")
        if mode == "host":
            host_mode.add(name)
            member[name] = set()
            info.append(f"compose {name}: network_mode host (the host's network, no isolation)")
        elif mode == "none":
            member[name] = set()
        elif mode and mode.startswith(("service:", "container:")):
            member[name] = set()  # filled in below, from the service whose namespace it joins
        else:
            member[name] = set(nets or {"default": None})
    for name, svc in services.items():
        mode = (svc or {}).get("network_mode") or ""
        if mode.startswith("service:"):
            other = mode.split(":", 1)[1]
            member[name] = set(member.get(other, set()))
            info.append(f"compose {name}: shares the network namespace of {other}")

    lines: set[str] = set()
    shared: dict[str, set[str]] = {}
    by_network: dict[str, list[str]] = {}
    for name, nets in member.items():
        for net in nets:
            by_network.setdefault(net, []).append(name)
    for net, names in sorted(by_network.items()):
        for a, b in combinations(sorted(names), 2):
            lines.add(pair(a, b))
            shared.setdefault(pair(a, b), set()).add(net)
        internal = bool((networks.get(net) or {}).get("internal"))
        if not internal:
            lines.update(egress(n) for n in names)
            info.append(f"compose network {net}: not internal, routes out ({', '.join(sorted(names))})")
    for name in sorted(host_mode):
        lines.add(egress(name))
    for name, svc in services.items():
        mode = (svc or {}).get("network_mode") or ""
        if mode.startswith("service:"):
            lines.add(pair(name, mode.split(":", 1)[1]))
    info.extend(f"{line}: via {', '.join(sorted(nets))}" for line, nets in sorted(shared.items()))
    return PlaneResult(lines=sorted(lines), scope={"services": set(services)}, info=info)
