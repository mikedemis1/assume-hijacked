"""Azure: the role assignments of the workload identities (user-assigned managed identities).

    az account show                 logged in? If not, the plane is skipped with a message.
                                    This tool never logs in.
    az identity list                principal id -> identity name
    az role assignment list --all   every assignment in the subscription
    az resource list                scope id -> logical name: the resource's `workload` tag
                                    (set by infra/base on the Key Vaults), else its name

https://learn.microsoft.com/cli/azure/role/assignment#az-role-assignment-list
Read-only: every command is a list or show.
"""
from __future__ import annotations

import json
import re

from secops.permassess import CollectorError, CommandMissing, PlaneResult, Runner, run_command

_RG = re.compile(r"^/subscriptions/[^/]+/resourcegroups/([^/]+)$", re.IGNORECASE)
_SUB = re.compile(r"^/subscriptions/[^/]+$", re.IGNORECASE)


def _json(run: Runner, args: list[str]) -> list | dict:
    out = run(["az", *args, "-o", "json"])
    try:
        return json.loads(out)
    except json.JSONDecodeError as exc:
        raise CollectorError(f"az {' '.join(args[:2])}: not JSON ({exc.msg})") from exc


def scope_name(scope: str, resources: dict[str, str]) -> str:
    key = scope.rstrip("/").lower()
    if key in resources:
        return resources[key]
    if m := _RG.match(scope.rstrip("/")):
        return f"resource group {m.group(1)}"
    if _SUB.match(scope.rstrip("/")):
        return "subscription"
    return scope.rstrip("/").rsplit("/", 1)[-1]


def collect(run: Runner = run_command) -> PlaneResult:
    try:
        _json(run, ["account", "show"])
    except CommandMissing:
        return PlaneResult(skipped="azure: the az CLI is not installed; plane skipped")
    except CollectorError:
        return PlaneResult(skipped="azure: not logged in (az account show failed); plane skipped. "
                                   "Log in yourself with az login to include it; this tool "
                                   "never logs in")
    identities = {i["principalId"]: i["name"] for i in _json(run, ["identity", "list"])
                  if i.get("principalId")}
    resources = {r["id"].lower(): ((r.get("tags") or {}).get("workload") or r["name"])
                 for r in _json(run, ["resource", "list"])}
    lines = set()
    for a in _json(run, ["role", "assignment", "list", "--all"]):
        name = identities.get(a.get("principalId"))
        if name is None:
            continue
        lines.add(f"azure identity {name}: {a.get('roleDefinitionName')} on "
                  f"{scope_name(a.get('scope', ''), resources)}")
    return PlaneResult(lines=sorted(lines), scope={"identities": set(identities.values())})
