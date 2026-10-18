"""Permission assessment: who can do what, compared with what each component declares.

The collectors read the live state of one plane each and turn it into plain text lines, one
permission per line:

    pg       PostgreSQL catalogs: role attributes, memberships, database, schema, table, column
             and function privileges (PUBLIC expanded to every role), ownership and SECURITY
             DEFINER owners, row-level security and policies, default privileges
    compose  `docker compose config`: services that share a network, and networks with a route out
    k8s      `kubectl auth can-i --list` per workload service account, NetworkPolicy edges
    azure    `az role assignment list` for the workload identities

The expected lines are generated from the capability manifests (security/capabilities/*.json)
by secops.permassess.expected. Any extra or missing line fails the assessment.

    python -m secops.permassess --planes pg,compose --out reports/permissions
    python -m secops.permassess.expected --capabilities security/capabilities --out security/expected-permissions.json
    python -m secops.permassess.report --out docs/permission-matrix.md
"""
from __future__ import annotations

import subprocess  # nosec B404 - runs docker, kubectl and az with fixed argument lists
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field


class CollectorError(Exception):
    """A plane could not be read (tool missing, command failed, database unreachable)."""


class CommandMissing(CollectorError):
    """The command-line tool for a plane is not installed."""


Runner = Callable[[Sequence[str]], str]


def run_command(args: Sequence[str], timeout: int = 120) -> str:
    """Run a command without a shell and return its standard output.

    Only the first line of standard error goes into the error: enough to see why, short enough
    that a long tool message (which could echo configuration) does not end up in a report.
    """
    try:
        done = subprocess.run(  # nosec B603 - fixed argument lists, never a shell
            list(args), capture_output=True, text=True, timeout=timeout, check=False,
            encoding="utf-8", errors="replace",
        )
    except FileNotFoundError as exc:
        raise CommandMissing(f"{args[0]} is not installed") from exc
    except subprocess.TimeoutExpired as exc:
        raise CollectorError(f"{' '.join(args[:3])} did not finish in {timeout} s") from exc
    if done.returncode != 0:
        first = (done.stderr or "").strip().splitlines()[:1]
        reason = first[0] if first else f"exit code {done.returncode}"
        raise CollectorError(f"{' '.join(args[:3])} failed: {reason}")
    return done.stdout


@dataclass
class PlaneResult:
    """What one collector found.

    lines    the permissions, one per line, compared with the expected file
    scope    names this plane knows (services, components, service accounts, identities); the
             expected lines of names outside it are reported as not deployed here, not as missing
    info     context for the report that is not compared (network names, unevaluated objects)
    skipped  set when the plane could not be assessed for an expected reason (not logged in)
    """

    lines: list[str] = field(default_factory=list)
    scope: dict[str, set[str]] = field(default_factory=dict)
    info: list[str] = field(default_factory=list)
    skipped: str | None = None
