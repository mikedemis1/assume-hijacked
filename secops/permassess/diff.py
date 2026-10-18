"""Compare collected lines with the expected file, plane by plane.

pg       every expected line against every collected line: the database is one plane with
         every role in it, so an expected role that is not there is missing.
compose  the expected network edges become undirected pairs (`compose a <-> b`) when both ends
         are Compose services, and `compose a -> internet` when a declares egress to internet.
         An edge to a name that is not a service here (a cloud endpoint, a component this
         Compose file does not run) is listed as not deployed, not as missing.
k8s      directed edges between the components found in the cluster; the rest is not
         deployed. Every RBAC line of the manifests is compared, found or not: a declared
         service account that is missing, or that has a pod at no time (the agent's), is
         still checked.
azure    the lines of the identities found in the subscription.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from secops.permassess import PlaneResult, canon
from secops.permassess.collect_compose import INTERNET, egress, pair


@dataclass
class PlaneDiff:
    plane: str
    extra: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    not_deployed: list[str] = field(default_factory=list)
    skipped: str | None = None

    @property
    def equal(self) -> bool:
        return not self.extra and not self.missing


def expected_lines(plane: str, expected: dict, result: PlaneResult) -> tuple[list[str], list[str]]:
    """(lines to compare, expected lines outside what this plane runs)."""
    if plane == "pg":
        return sorted(expected["pg"]), []
    lines, elsewhere = set(), set()
    if plane == "compose":
        services = result.scope.get("services", set())
        for e in expected["edges"]:
            a, b = canon.split_edge(e)
            if a in services and b == INTERNET:
                lines.add(egress(a))
            elif a in services and b in services and a != b:
                lines.add(pair(a, b))
            else:
                elsewhere.add(e)
    elif plane == "k8s":
        comps = result.scope.get("components", set())
        for e in expected["edges"]:
            a, b = canon.split_edge(e)
            (lines if a in comps and b in comps else elsewhere).add(f"k8s {a} -> {b}")
        lines.update(expected["k8s"])
    elif plane == "azure":
        identities = result.scope.get("identities", set())
        for line in expected["azure"]:
            ident = line.split(" ", 3)[2].rstrip(":")
            (lines if ident in identities else elsewhere).add(line)
    else:
        raise ValueError(f"unknown plane {plane}")
    return sorted(lines), sorted(elsewhere)


def compare(plane: str, expected: dict, result: PlaneResult) -> PlaneDiff:
    if result.skipped:
        return PlaneDiff(plane, skipped=result.skipped)
    want, elsewhere = expected_lines(plane, expected, result)
    have = set(result.lines)
    return PlaneDiff(plane, extra=sorted(have - set(want)), missing=sorted(set(want) - have),
                     not_deployed=elsewhere)


def load_tool_calls(path: Path) -> list[dict]:
    """A tool_calls export: a JSON array, or one JSON object per line."""
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return []
    if text.startswith("["):
        return json.loads(text)
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def unused_warnings(expected: dict, calls: list[dict]) -> list[str]:
    """Granted but never used: a component's tool that no call in the log reached.

    A warning, never a failure: a quiet day is not a misconfiguration. It points at a grant
    to take away if the tool is really not needed.
    """
    used = {c.get("tool") for c in calls}
    out = []
    for name, comp in expected["components"].items():
        for tool in comp.get("mcp_tools") or []:
            if tool not in used:
                grants = [ln.split(": ", 1)[1] for ln in expected["pg"]
                          if any(ln.startswith(f"pg role {r}: EXECUTE ") for r in comp["db_roles"])
                          and not ln.endswith(canon.VIA_PUBLIC)]
                held = f" (holds {', '.join(grants)})" if grants else ""
                out.append(f"warning: {name} is granted tool {tool}{held}, but no call in the "
                           "tool_calls log used it")
    return out
