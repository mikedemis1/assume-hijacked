"""The evidence report: one static HTML page built from the JSON reports of a run.

    python -m secops.evidence --reports reports --out reports/evidence.html

Sections and the files they read (paths relative to --reports):

  permissions  permissions/diff.json (+ summary.txt, matrix.md), from python -m secops.permassess
  probes       k8s-probe-matrix.json, the network probe matrix (tests/k8s/test_walls.py): a list
               of {edge, source, kind, expected, observed, detail, why}
  attacks      attack-replay.json, the attack ticket replay (python -m attacks.run replay): one
               JSON object per line, or a JSON list, of {ticket, name, passed, failures}
  images       image-digests.json: {"images": [{"reference", "sources"}]}, written by
               --collect-images from the files that name images, or by a deploy step
  kql          kql/*.json, optional (Azure sessions only): one file per Log Analytics query,
               each the JSON list of rows that `az monitor log-analytics query` prints

Rules:
  - A missing file is a "not run" section. A report with a section not run is never a pass.
  - Every section judges the data again instead of trusting a flag in it: a probe passes only
    with the wall's own signature, an attack only with passed == true and no failure, a
    permission diff only with no extra or missing line and no error.
  - An unreadable or malformed file is an error section, never a crash.
  - Every value from a report is escaped (html.escape) before it goes into the page, and the
    page loads nothing and runs nothing (Content-Security-Policy default-src 'none').

Only the standard library: HTML through html.escape and string.Template, no template engine.
"""
from __future__ import annotations

import html
import json
import re
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from string import Template

PASS = "pass"
FAIL = "fail"
ERROR = "error"
NOT_RUN = "not run"

OVERALL_PASS = "PASS"
OVERALL_FAIL = "FAIL"
OVERALL_INCOMPLETE = "INCOMPLETE"

# A probe's deny must carry the wall's signature (attacks/probes.py DENY_DETAIL): Cilium drops a
# denied connection (timeout) and its DNS proxy answers REFUSED.
DENY_DETAIL = {"tcp": "timeout", "dns": "REFUSED", "resolve": "REFUSED"}
DIGEST_REF = re.compile(r"[A-Za-z0-9][\w.\-/:]*@sha256:[0-9a-f]{64}")
KQL_MAX_ROWS = 50


class ReportError(ValueError):
    """A report file that is there but cannot be used."""


@dataclass(frozen=True)
class Section:
    key: str
    title: str
    status: str
    summary: str
    body: str  # HTML; every value in it is escaped where it is built
    source: str
    required: bool = True


@dataclass(frozen=True)
class Report:
    generated: str
    commit: str
    sections: tuple[Section, ...]

    @property
    def overall(self) -> str:
        statuses = [s.status for s in self.sections if s.required or s.status != NOT_RUN]
        if any(s in (FAIL, ERROR) for s in statuses):
            return OVERALL_FAIL
        if any(s.status != PASS for s in self.sections if s.required):
            return OVERALL_INCOMPLETE
        return OVERALL_PASS


def e(value: object) -> str:
    """The one way a value from a report reaches the page."""
    return html.escape(str(value), quote=True)


# --- reading -------------------------------------------------------------------------------------

def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise  # the section was not run
    except (OSError, UnicodeDecodeError) as exc:
        raise ReportError(f"cannot read {path.name}: {type(exc).__name__}") from exc


def _read_json(path: Path) -> object:
    try:
        return json.loads(_read_text(path))
    except json.JSONDecodeError as exc:
        raise ReportError(f"{path.name} is not JSON (line {exc.lineno}, column {exc.colno})") from exc


def _read_json_lines(path: Path) -> object:
    """A JSON list, or one JSON value per line (what a command printing JSON lines writes)."""
    text = _read_text(path)
    stripped = text.strip()
    if stripped.startswith("["):
        return _read_json(path)
    rows = []
    for number, line in enumerate(text.splitlines(), 1):
        if line.strip():
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ReportError(f"{path.name} line {number} is not JSON") from exc
    return rows


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise ReportError(message)


def _strings(value: object, what: str) -> list[str]:
    _need(isinstance(value, list) and all(isinstance(v, str) for v in value),
          f"{what} must be a list of strings")
    return value  # type: ignore[return-value]


# --- HTML pieces ---------------------------------------------------------------------------------

def _table(headers: list[str], rows: list[list[str]], classes: list[str] | None = None) -> str:
    """A table of escaped cells. classes, one per row, come from this module, never from data."""
    head = "".join(f"<th>{e(h)}</th>" for h in headers)
    body = []
    for i, row in enumerate(rows):
        cls = f' class="{classes[i]}"' if classes and classes[i] else ""
        body.append(f"<tr{cls}>" + "".join(f"<td>{e(c)}</td>" for c in row) + "</tr>")
    return f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(body)}</tbody></table>"


def _list(items: list[str]) -> str:
    return "<ul>" + "".join(f"<li><code>{e(i)}</code></li>" for i in items) + "</ul>"


def _pre(title: str, text: str) -> str:
    return f"<details><summary>{e(title)}</summary><pre>{e(text)}</pre></details>"


def _p(text: str) -> str:
    return f"<p>{e(text)}</p>"


# --- sections ------------------------------------------------------------------------------------

def permissions_section(folder: Path) -> tuple[str, str, str]:
    doc = _read_json(folder / "permissions" / "diff.json")
    _need(isinstance(doc, dict), "diff.json must be a JSON object")
    planes = doc.get("planes")
    errors = doc.get("errors", {})
    _need(isinstance(planes, dict), "diff.json has no planes object")
    _need(isinstance(errors, dict) and all(isinstance(v, str) for v in errors.values()),
          "diff.json errors must map names to messages")
    warnings = _strings(doc.get("warnings", []), "diff.json warnings")
    rows, classes, details, assessed, different = [], [], [], 0, False
    for name, plane in planes.items():
        _need(isinstance(plane, dict), f"plane {name} must be an object")
        extra = _strings(plane.get("extra", []), f"plane {name} extra")
        missing = _strings(plane.get("missing", []), f"plane {name} missing")
        not_deployed = _strings(plane.get("not_deployed", []), f"plane {name} not_deployed")
        skipped = plane.get("skipped")
        if skipped:
            state, cls = f"skipped: {skipped}", "skip"
        elif extra or missing:
            state, cls, different = "different", "bad", True
            assessed += 1
        else:
            state, cls = "equal", "ok"
            assessed += 1
        rows.append([name, state, str(len(extra)), str(len(missing)), str(len(not_deployed))])
        classes.append(cls)
        if extra:
            details.append(f"<h4>{e(name)}: extra (granted, not expected)</h4>{_list(extra)}")
        if missing:
            details.append(f"<h4>{e(name)}: missing (expected, not granted)</h4>{_list(missing)}")
    body = [_table(["Plane", "Result", "Extra", "Missing", "Not deployed here"], rows, classes)]
    body += details
    if errors:
        body.append("<h4>Errors</h4>" + _list([f"{k}: {v}" for k, v in errors.items()]))
    if warnings:
        body.append("<h4>Warnings (not a failure)</h4>" + _list(warnings))
    for extra_file, title in (("summary.txt", "summary.txt"),
                              ("matrix.md", "Blast radius per component (matrix.md)")):
        path = folder / "permissions" / extra_file
        if path.is_file():
            body.append(_pre(title, _read_text(path)))

    code = 2 if errors or not assessed else (1 if different else 0)
    stated = doc.get("exit_code")
    if errors or not assessed:
        status = ERROR
        summary = "a plane could not be read" if errors else "every plane was skipped: nothing was assessed"
    elif different:
        status, summary = FAIL, "the live permissions differ from the expected file"
    else:
        status, summary = PASS, f"{assessed} plane(s) equal to the expected file"
    if stated != code:
        status = ERROR
        summary = f"diff.json says exit code {stated!r} but its contents give {code}"
    return status, summary, "".join(body)


def probe_passed(result: dict) -> bool:
    """The live test's rule (tests/k8s/test_walls.py), applied again to the saved result."""
    kind, expected, observed = result.get("kind"), result.get("expected"), result.get("observed")
    detail = str(result.get("detail", ""))
    if kind not in DENY_DETAIL or expected not in ("allow", "deny") or observed != expected:
        return False
    return observed == "allow" or detail.startswith(DENY_DETAIL[kind])


def probes_section(folder: Path) -> tuple[str, str, str]:
    results = _read_json(folder / "k8s-probe-matrix.json")
    _need(isinstance(results, list), "k8s-probe-matrix.json must be a JSON list of results")
    keys = ("edge", "source", "kind", "expected", "observed", "detail", "why")
    for i, r in enumerate(results):
        _need(isinstance(r, dict) and all(k in r for k in keys),
              f"probe result {i + 1} must be an object with {', '.join(keys)}")
    if not results:
        return FAIL, "the file holds no probe result: nothing was probed", _p("No probe results.")
    verdicts = [probe_passed(r) for r in results]
    failed = verdicts.count(False)
    per_source: dict[str, Counter] = {}
    for r, ok in zip(results, verdicts):
        per_source.setdefault(str(r["source"]), Counter())[ok] += 1
    sources = _table(["Source", "Probes", "Passed", "Failed"],
                     [[s, str(c[True] + c[False]), str(c[True]), str(c[False])]
                      for s, c in per_source.items()],
                     ["bad" if c[False] else "ok" for c in per_source.values()])
    rows = [[str(r["edge"]), str(r["expected"]), str(r["observed"]), str(r["detail"]),
             str(r["why"]), "pass" if ok else "FAIL"] for r, ok in zip(results, verdicts)]
    order = sorted(range(len(rows)), key=lambda i: verdicts[i])  # failures first
    table = _table(["Edge", "Expected", "Observed", "Detail", "Wall", "Verdict"],
                   [rows[i] for i in order], ["ok" if verdicts[i] else "bad" for i in order])
    summary = (f"{failed} of {len(results)} failed" if failed
               else f"all {len(results)} probes match, every deny with the wall's signature")
    return (FAIL if failed else PASS), summary, sources + table


def attacks_section(folder: Path) -> tuple[str, str, str]:
    lines = _read_json_lines(folder / "attack-replay.json")
    _need(isinstance(lines, list), "attack-replay.json must hold a list of results")
    rows, classes, failed = [], [], 0
    for i, line in enumerate(lines):
        _need(isinstance(line, dict) and isinstance(line.get("ticket"), int)
              and isinstance(line.get("name"), str), f"result {i + 1} needs an int ticket and a name")
        failures = _strings(line.get("failures", []), f"ticket {line['ticket']} failures")
        ok = line.get("passed") is True and not failures
        failed += not ok
        rows.append([str(line["ticket"]), line["name"], "pass" if ok else "FAIL",
                     "; ".join(failures) or ("" if ok else "passed is not true")])
        classes.append("ok" if ok else "bad")
    if not rows:
        return FAIL, "the file holds no ticket: nothing was replayed", _p("No attack results.")
    table = _table(["Ticket (row in docs/attacks.md)", "Attack", "Verdict", "Failed checks"],
                   rows, classes)
    summary = (f"{failed} of {len(rows)} attack tickets got through a wall" if failed
               else f"all {len(rows)} attack tickets stopped")
    return (FAIL if failed else PASS), summary, table


def images_section(folder: Path) -> tuple[str, str, str]:
    doc = _read_json(folder / "image-digests.json")
    _need(isinstance(doc, dict) and isinstance(doc.get("images"), list),
          'image-digests.json must be {"images": [...]}')
    rows, classes, unpinned = [], [], 0
    for i, image in enumerate(doc["images"]):
        _need(isinstance(image, dict) and isinstance(image.get("reference"), str),
              f"image {i + 1} needs a reference string")
        sources = _strings(image.get("sources", []), f"image {i + 1} sources")
        pinned = bool(DIGEST_REF.fullmatch(image["reference"]))
        unpinned += not pinned
        rows.append([image["reference"], ", ".join(sources), "digest" if pinned else "NO DIGEST"])
        classes.append("ok" if pinned else "bad")
    if not rows:
        return FAIL, "the file lists no image", _p("No images.")
    summary = (f"{unpinned} of {len(rows)} image references have no digest" if unpinned
               else f"all {len(rows)} image references are pinned by digest")
    return (FAIL if unpinned else PASS), summary, _table(["Image", "Named in", "Pinned"], rows, classes)


def kql_section(folder: Path) -> tuple[str, str, str]:
    files = sorted((folder / "kql").glob("*.json"))
    if not files:
        raise FileNotFoundError("kql/*.json")
    body, total = [], 0
    for path in files:
        rows = _read_json(path)
        _need(isinstance(rows, list) and all(isinstance(r, dict) for r in rows),
              f"{path.name} must be a JSON list of row objects")
        total += len(rows)
        columns = list(dict.fromkeys(k for r in rows for k in r))
        shown = rows[:KQL_MAX_ROWS]
        more = f" (first {KQL_MAX_ROWS} of {len(rows)})" if len(rows) > KQL_MAX_ROWS else ""
        body.append(f"<h4>{e(path.stem)}: {len(rows)} row(s){e(more)}</h4>")
        body.append(_table(columns, [[_cell(r.get(c, "")) for c in columns] for r in shown])
                    if rows else _p("No rows."))
    return PASS, f"{len(files)} query result(s), {total} row(s)", "".join(body)


def _cell(value: object) -> str:
    return value if isinstance(value, str) else json.dumps(value)


SECTIONS: tuple[tuple[str, str, str, bool, Callable[[Path], tuple[str, str, str]]], ...] = (
    ("permissions", "Permission assessment", "permissions/diff.json", True, permissions_section),
    ("probes", "Network probe matrix", "k8s-probe-matrix.json", True, probes_section),
    ("attacks", "Attack ticket replay", "attack-replay.json", True, attacks_section),
    ("images", "Image digests", "image-digests.json", True, images_section),
    ("kql", "Log Analytics queries (optional)", "kql/*.json", False, kql_section),
)


def build(folder: Path, generated: str, commit: str | None = None) -> Report:
    sections = []
    for key, title, source, required, read in SECTIONS:
        try:
            status, summary, body = read(folder)
        except FileNotFoundError:
            status, summary = NOT_RUN, f"not run: no {source}"
            body = _p(f"{source} is not in the reports folder, so this part was not run "
                      "or its report was not kept. Nothing here counts as a pass.")
        except ReportError as exc:
            status, summary, body = ERROR, str(exc), _p(f"The report is not usable: {exc}")
        except Exception as exc:  # noqa: BLE001 - a bad file must give an error section, not a crash
            status, summary = ERROR, f"{type(exc).__name__} while reading {source}"
            body = _p(summary)
        sections.append(Section(key, title, status, summary, body, source, required))
    return Report(generated, commit or "not given", tuple(sections))


# --- the page ------------------------------------------------------------------------------------

PAGE = Template("""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Evidence report</title>
<style>
:root { --bg: #fafaf8; --ink: #1d1d1f; --muted: #5f6368; --line: #dcdcd7;
        --ok: #1a7f37; --bad: #c62828; --warn: #9a5b00; --row-bad: #fdecea; }
@media (prefers-color-scheme: dark) {
  :root { --bg: #141416; --ink: #ececec; --muted: #a0a0a8; --line: #34343a;
          --ok: #3fb950; --bad: #ff6b6b; --warn: #e3a341; --row-bad: #3a1d1d; }
}
body { margin: 0; background: var(--bg); color: var(--ink);
       font: 15px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
main { max-width: 1100px; margin: 0 auto; padding: 24px 16px 64px; }
h1 { margin: 0 0 4px; } .meta { color: var(--muted); margin: 0 0 16px; }
section { border-top: 1px solid var(--line); padding: 12px 0; }
table { border-collapse: collapse; width: 100%; margin: 8px 0; display: block; overflow-x: auto; }
th, td { border: 1px solid var(--line); padding: 4px 8px; text-align: left; vertical-align: top; }
tr.bad td { background: var(--row-bad); } tr.skip td { color: var(--muted); }
code, pre { font-family: ui-monospace, Consolas, monospace; font-size: 13px; }
pre { white-space: pre-wrap; overflow-wrap: anywhere; }
.status { font-weight: 600; text-transform: uppercase; }
.pass { color: var(--ok); } .fail, .error { color: var(--bad); } .not-run { color: var(--warn); }
.overall { font-size: 1.3rem; }
</style>
</head>
<body>
<main>
<h1>Evidence report</h1>
<p class="meta">Generated $generated, commit <code>$commit</code>.</p>
<p class="overall">Result: <span class="status $overall_class">$overall</span></p>
$summary
$sections
</main>
</body>
</html>
""")

_CLASSES = {PASS: "pass", FAIL: "fail", ERROR: "error", NOT_RUN: "not-run",
            OVERALL_PASS: "pass", OVERALL_FAIL: "fail", OVERALL_INCOMPLETE: "not-run"}


def _badge(status: str) -> str:
    return f'<span class="status {_CLASSES[status]}">{e(status)}</span>'


def render(report: Report) -> str:
    rows = "".join(
        f'<tr><td><a href="#{s.key}">{e(s.title)}</a></td><td>{_badge(s.status)}</td>'
        f"<td>{e(s.summary)}</td><td><code>{e(s.source)}</code></td></tr>"
        for s in report.sections)
    summary = ("<table><thead><tr><th>Section</th><th>Status</th><th>Summary</th>"
               f"<th>Read from</th></tr></thead><tbody>{rows}</tbody></table>")
    sections = "".join(
        f'<section id="{s.key}"><h2>{e(s.title)} {_badge(s.status)}</h2>'
        f"{_p(s.summary)}{s.body}</section>" for s in report.sections)
    return PAGE.substitute(generated=e(report.generated), commit=e(report.commit),
                           overall=e(report.overall), overall_class=_CLASSES[report.overall],
                           summary=summary, sections=sections)


# --- image references ----------------------------------------------------------------------------

# Files that name images, relative to the repository root; globs allowed.
IMAGE_FILES = ("Dockerfile", "ci/*.Dockerfile", "compose.yaml", ".gitlab-ci.yml", "ci/lib.sh",
               "deploy/**/*.yaml", "deploy/**/*.json", "scripts/*.sh")
# A line that names one image without a digest: `image: x` (Compose, CI) or `FROM x`.
_UNPINNED_LINE = re.compile(r"""^\s*(?:-\s*)?(?:image:\s*|FROM\s+)["']?(?P<ref>[A-Za-z0-9][\w.\-/:]*)""")


def collect_images(root: Path) -> dict:
    """Every pinned image reference in the files that name images, and every `image:` or
    `FROM` line whose reference has no digest (it would fail the images section)."""
    found: dict[str, list[str]] = {}
    for pattern in IMAGE_FILES:
        for path in sorted(root.glob(pattern)):
            if not path.is_file():
                continue
            name = path.relative_to(root).as_posix()
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                refs = DIGEST_REF.findall(line)
                if not refs and "$" not in line and "{{" not in line:
                    m = _UNPINNED_LINE.match(line)
                    refs = [m["ref"]] if m and (":" in m["ref"] or "/" in m["ref"]) else []  # not a build stage name
                for ref in refs:
                    sources = found.setdefault(ref, [])
                    if name not in sources:
                        sources.append(name)
    return {"generated_by": "python -m secops.evidence --collect-images",
            "images": [{"reference": r, "sources": s} for r, s in sorted(found.items())]}
