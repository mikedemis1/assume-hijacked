"""python -m secops.permassess --planes pg,compose[,k8s][,azure] --out reports/permissions

Exit codes: 0 every assessed plane matches the expected file, 1 at least one extra or missing
line, 2 a plane could not be read (any exception in a collector), the expected file is not usable
(stale, unreadable), or every requested plane was skipped, so nothing was assessed.
A skipped plane (Azure while not logged in) is reported; next to an assessed plane it does not
change the exit code. The report files are written in every case except a bad command line or
an unusable expected file.

PostgreSQL connection: DB_HOST (127.0.0.1), DB_PORT (5432), DB_NAME (supplier),
PERMASSESS_DB_USER (postgres) and POSTGRES_PASSWORD. Only catalog SELECTs are run, in a
read-only session.

Writes to --out: actual.json (what was found), diff.json and summary.txt (the differences),
matrix.md (the blast radius of what was found).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Callable
from pathlib import Path

from secops.permassess import (CollectorError, PlaneResult, Runner, collect_azure,
                               collect_compose, collect_k8s, diff, expected, report, run_command)

PLANES = ("pg", "compose", "k8s", "azure")
CAPABILITIES = "security/capabilities"


def _connect_pg(env: dict[str, str]):
    import psycopg

    try:
        conn = psycopg.connect(
            host=env.get("DB_HOST", "127.0.0.1"), port=int(env.get("DB_PORT", "5432")),
            dbname=env.get("DB_NAME", "supplier"), user=env.get("PERMASSESS_DB_USER", "postgres"),
            password=env.get("POSTGRES_PASSWORD", ""), connect_timeout=10)
    except psycopg.Error as exc:
        # The first line only: libpq messages name host and port, never the password.
        raise CollectorError(f"cannot connect to PostgreSQL: {_first_line(exc)}") from exc
    # It logs in as a superuser to read every catalog; the server refuses any write it might try.
    conn.read_only = True
    return conn


def _first_line(exc: BaseException) -> str:
    lines = str(exc).strip().splitlines()
    return lines[0] if lines else "(no message)"


def collect_plane(plane: str, args: argparse.Namespace, env: dict[str, str], run: Runner,
                  connect: Callable) -> PlaneResult:
    if plane == "pg":
        from secops.permassess import collect_pg

        conn = connect(env)
        try:
            return PlaneResult(lines=collect_pg.collect(conn))
        finally:
            conn.close()
    if plane == "compose":
        config = (collect_compose.load(args.compose_json) if args.compose_json
                  else collect_compose.render(args.compose_file, run))
        return collect_compose.collect(config)
    if plane == "k8s":
        return collect_k8s.collect(run, args.k8s_namespace_prefix, set(args.k8s_exclude_namespace))
    return collect_azure.collect(run)


def source_problem(doc: dict, expected_path: Path) -> str | None:
    """The expected file must be what its manifests give, and come from the real manifests
    once they exist, so nobody can make the check pass by editing the expected file."""
    source = Path(doc.get("source", ""))
    if Path(CAPABILITIES).is_dir() and doc.get("source") != CAPABILITIES:
        return (f"{expected_path} was built from {doc.get('source')}, but {CAPABILITIES} exists; "
                f"run python -m secops.permassess.expected --capabilities {CAPABILITIES}")
    try:
        rebuilt = expected.build_expected(expected.load_manifests(source), doc.get("source", ""))
    except expected.ManifestError as exc:
        return f"cannot rebuild {expected_path} from its source: {exc}"
    if rebuilt != doc:
        return (f"{expected_path} is not what {doc.get('source')} produces; run "
                f"{rebuilt['generated_by']}")
    return None


def _actual_doc(expected_doc: dict, results: dict[str, PlaneResult]) -> dict:
    edges = set()
    for line in results.get("compose", PlaneResult()).lines:
        body = line[len("compose "):]
        if " <-> " in body:
            a, b = body.split(" <-> ")
            edges.update({f"{a} -> {b}", f"{b} -> {a}"})
        else:
            edges.add(body)
    for line in results.get("k8s", PlaneResult()).lines:
        if " -> " in line and not line.startswith("k8s serviceaccount "):
            edges.add(line[len("k8s "):])
    return {
        "source": "collected",
        "components": expected_doc.get("components", {}),
        "pg": results.get("pg", PlaneResult()).lines,
        "edges": sorted(edges),
        "k8s": [ln for ln in results.get("k8s", PlaneResult()).lines
                if ln.startswith("k8s serviceaccount ")],
        "azure": results.get("azure", PlaneResult()).lines,
    }


def main(argv: list[str] | None = None, env: dict[str, str] | None = None,
         run: Runner = run_command, connect: Callable = _connect_pg) -> int:
    parser = argparse.ArgumentParser(prog="python -m secops.permassess",
                                     description="Compare live permissions with the expected file.")
    parser.add_argument("--planes", default="pg,compose",
                        help=f"comma-separated, from {', '.join(PLANES)}")
    parser.add_argument("--out", type=Path, default=Path("reports/permissions"))
    parser.add_argument("--expected", type=Path, default=Path("security/expected-permissions.json"))
    parser.add_argument("--compose-file", default="compose.yaml")
    parser.add_argument("--compose-json", type=Path,
                        help="a configuration rendered earlier with docker compose config --format json")
    parser.add_argument("--k8s-namespace-prefix", default="ah-")
    parser.add_argument("--k8s-exclude-namespace", action="append", default=[],
                        help="explicitly exclude a namespace and record it in report info (repeatable)")
    parser.add_argument("--tool-calls", type=Path,
                        help="tool_calls rows as JSON: warn about tools granted but never called")
    parser.add_argument("--no-source-check", action="store_true",
                        help="skip rebuilding the expected file from its manifests (tests only)")
    args = parser.parse_args(argv)
    env = dict(os.environ) if env is None else env

    planes = [p.strip() for p in args.planes.split(",") if p.strip()]
    unknown = [p for p in planes if p not in PLANES]
    if unknown or not planes:
        print(f"permassess: unknown plane(s) {', '.join(unknown) or '(none)'}; "
              f"choose from {', '.join(PLANES)}", file=sys.stderr)
        return 2
    try:
        doc = json.loads(args.expected.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"permassess: cannot read {args.expected}: {exc}", file=sys.stderr)
        return 2
    if not args.no_source_check and (problem := source_problem(doc, args.expected)):
        print(f"permassess: {problem}", file=sys.stderr)
        return 2

    results: dict[str, PlaneResult] = {}
    errors: dict[str, str] = {}
    diffs: dict[str, diff.PlaneDiff] = {}
    for plane in planes:
        try:
            results[plane] = collect_plane(plane, args, env, run, connect)
        except CollectorError as exc:
            errors[plane] = str(exc)
            continue
        except Exception as exc:  # noqa: BLE001 - any failure must end as exit 2 with reports
            errors[plane] = f"{type(exc).__name__}: {_first_line(exc)}"
            continue
        diffs[plane] = diff.compare(plane, doc, results[plane])

    warnings = []
    if args.tool_calls:
        try:
            warnings = diff.unused_warnings(doc, diff.load_tool_calls(args.tool_calls))
        except Exception as exc:  # noqa: BLE001 - unreadable or malformed log: exit 2
            errors["tool_calls"] = (f"cannot read {args.tool_calls}: "
                                    f"{type(exc).__name__}: {_first_line(exc)}")

    summary = []
    for plane in planes:
        if plane in errors:
            summary.append(f"{plane}: ERROR {errors[plane]}")
            continue
        d = diffs[plane]
        if d.skipped:
            summary.append(f"{plane}: skipped. {d.skipped}")
            continue
        state = "equal" if d.equal else f"{len(d.extra)} extra, {len(d.missing)} missing"
        summary.append(f"{plane}: {state} ({len(results[plane].lines)} lines collected)")
        summary += [f"  + {ln}" for ln in d.extra] + [f"  - {ln}" for ln in d.missing]
        if d.not_deployed:
            summary.append(f"  ({len(d.not_deployed)} expected lines are about names this plane "
                           "does not run; see diff.json not_deployed)")
    if "tool_calls" in errors:
        summary.append(f"tool_calls: ERROR {errors['tool_calls']}")
    summary += warnings
    assessed = [p for p, d in diffs.items() if not d.skipped]
    if not errors and not assessed:
        errors["planes"] = "every requested plane was skipped: nothing was assessed"
        summary.append(f"planes: ERROR {errors['planes']}")
    code = 2 if errors else (1 if any(not d.equal for d in diffs.values()) else 0)
    summary.append({0: "result: equal", 1: "result: DIFFERENT (+ extra, - missing)",
                    2: "result: ERROR (a plane could not be read, or none was assessed)"}[code])

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "actual.json").write_text(json.dumps(
        {p: {"lines": r.lines, "info": r.info, "skipped": r.skipped} for p, r in results.items()},
        indent=1) + "\n", encoding="utf-8")
    (args.out / "diff.json").write_text(json.dumps({
        "planes": {p: {"extra": d.extra, "missing": d.missing, "not_deployed": d.not_deployed,
                       "skipped": d.skipped} for p, d in diffs.items()},
        "errors": errors, "warnings": warnings, "exit_code": code}, indent=1) + "\n",
        encoding="utf-8")
    (args.out / "summary.txt").write_text("\n".join(summary) + "\n", encoding="utf-8")
    (args.out / "matrix.md").write_text(report.render(
        _actual_doc(doc, results), "Permission matrix (collected)",
        f"What the collectors found for planes {', '.join(planes)}, grouped by the components of "
        f"`{args.expected.as_posix()}`."), encoding="utf-8")
    print("\n".join(summary))
    return code


if __name__ == "__main__":
    sys.exit(main())
