"""The evidence report: one static HTML page built from the JSON reports of a run.

    python -m secops.evidence --reports reports --out reports/evidence.html

Sections and the files they read (paths relative to --reports):

  permissions  permissions/diff.json (+ summary.txt, matrix.md), from python -m secops.permassess
  probes       k8s-probe-matrix.json, the network probe matrix (tests/k8s/test_walls.py): a list
               of {edge, source, kind, expected, observed, detail, why}
  attacks      attack-replay.json, the attack ticket replay (python -m attacks.run replay): one
               JSON object per line, or a JSON list, of {ticket, name, passed, failures}
  images       image-digests.json: {"images": [{"reference", "sources"}]}, written by
               --collect-images from the files that name images, or by a deploy step. Pinned
               means name:tag@sha256:<64 hex>; an all-zero digest is a placeholder
  kql          kql/*.json, optional (Azure sessions only): one file per Log Analytics query,
               each the JSON list of rows that `az monitor log-analytics query` prints

Rules:
  - A missing file is a "not run" section. A report with a section not run is never a pass.
  - A report must be complete: every probe edge of the matrix and every attack ticket of the
    suite (attacks/probes.py, attacks/tickets.py), no more and no fewer. Without those lists the
    sections are "partial", never a pass. A permission plane that was skipped, or an image
    with a placeholder digest, also makes its section "partial", and the skipped planes are
    named in the summary.
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
PARTIAL = "partial"  # what is there passed, but part of it is missing or skipped: not a pass

OVERALL_PASS = "PASS"
OVERALL_FAIL = "FAIL"
OVERALL_INCOMPLETE = "INCOMPLETE"

# A probe's deny must carry the wall's signature (attacks/probes.py DENY_DETAIL): Cilium drops a
# denied connection (timeout) and its DNS proxy answers REFUSED.
DENY_DETAIL = {"tcp": "timeout", "dns": "REFUSED", "resolve": "REFUSED"}
# Any reference that carries a sha256 digest, found anywhere on a line.
DIGEST_REF = re.compile(r"[A-Za-z0-9][\w.\-/:]*@sha256:[0-9a-f]{64}")
_TAG = re.compile(r"[\w][\w.\-]{0,127}")
KQL_MAX_ROWS = 50


class ReportError(ValueError):
    """A report file that is there but cannot be used."""


@dataclass(frozen=True)
class Expected:
    """What a complete report holds. None: not known, so completeness cannot be shown.
    problem: the lists could not be read; the probe and attack sections are then errors."""
    probe_edges: tuple[str, ...] | None
    attack_tickets: tuple[int, ...] | None
    problem: str | None = None


def load_expected() -> Expected:
    """The probe matrix and the attack tickets from the attack suite in this repository.
    Never raises: without the suite nothing is expected (partial sections), and a suite that
    fails or answers nonsense is a problem the two sections report as errors."""
    try:
        from attacks import probes, tickets
    except ImportError:
        return Expected(None, None)
    try:
        edges = tuple(p.edge for p in probes.matrix())
        numbers = tuple(t.number for t in tickets.ATTACK_TICKETS)
        if not all(isinstance(x, str) for x in edges) or not all(
                isinstance(n, int) and not isinstance(n, bool) for n in numbers):
            raise TypeError("probe edges must be strings and ticket numbers integers")
        return Expected(edges, numbers)
    except Exception as exc:  # noqa: BLE001 - a broken suite must give error sections, not a crash
        return Expected(None, None, f"cannot read the expected lists from attacks/: {type(exc).__name__}")


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

def permissions_section(folder: Path, expected: Expected) -> tuple[str, str, str]:
    doc = _read_json(folder / "permissions" / "diff.json")
    _need(isinstance(doc, dict), "diff.json must be a JSON object")
    planes = doc.get("planes")
    errors = doc.get("errors", {})
    _need(isinstance(planes, dict), "diff.json has no planes object")
    _need(isinstance(errors, dict) and all(isinstance(v, str) for v in errors.values()),
          "diff.json errors must map names to messages")
    warnings = _strings(doc.get("warnings", []), "diff.json warnings")
    rows, classes, details, assessed, different, skipped_planes = [], [], [], 0, False, []
    for name, plane in planes.items():
        _need(isinstance(plane, dict), f"plane {name} must be an object")
        extra = _strings(plane.get("extra", []), f"plane {name} extra")
        missing = _strings(plane.get("missing", []), f"plane {name} missing")
        not_deployed = _strings(plane.get("not_deployed", []), f"plane {name} not_deployed")
        skipped = plane.get("skipped")
        if skipped:
            state, cls = f"skipped: {skipped}", "skip"
            skipped_planes.append(str(name))
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
    elif skipped_planes:
        status = PARTIAL
        summary = (f"{assessed} plane(s) equal to the expected file; "
                   f"skipped: {', '.join(skipped_planes)} (not assessed)")
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


def _completeness(found: list, wanted: tuple | None, what: str) -> tuple[list, list, str]:
    """(missing, unexpected, text) for a report against the list it should hold."""
    if wanted is None:
        return [], [], f"found {len(found)}; the expected list of {what} is not available"
    missing = [w for w in wanted if w not in set(found)]
    unexpected = [f for f in found if f not in set(wanted)]
    return missing, unexpected, f"expected {len(wanted)}, found {len(found)}"


def probes_section(folder: Path, expected: Expected) -> tuple[str, str, str]:
    results = _read_json(folder / "k8s-probe-matrix.json")
    _need(isinstance(results, list), "k8s-probe-matrix.json must be a JSON list of results")
    keys = ("edge", "source", "kind", "expected", "observed", "detail", "why")
    for i, r in enumerate(results):
        _need(isinstance(r, dict) and all(k in r for k in keys),
              f"probe result {i + 1} must be an object with {', '.join(keys)}")
    edges = [str(r["edge"]) for r in results]
    _need(len(edges) == len(set(edges)), "k8s-probe-matrix.json reports an edge more than once")
    _need(expected.problem is None, str(expected.problem))
    missing, unexpected, count = _completeness(edges, expected.probe_edges, "probe edges")
    if not results:
        return FAIL, f"the file holds no probe result: nothing was probed ({count})", _p("No probe results.")
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
    gaps = ""
    if missing:
        gaps += f"<h4>Missing from the report ({len(missing)})</h4>" + _list(missing)
    if unexpected:
        gaps += f"<h4>Not in the probe matrix ({len(unexpected)})</h4>" + _list(unexpected)
    body = _p(count) + gaps + sources + table
    if failed or missing or unexpected:
        parts = [f"{failed} of {len(results)} failed"] if failed else []
        parts += [f"{len(missing)} missing"] if missing else []
        parts += [f"{len(unexpected)} not in the matrix"] if unexpected else []
        return FAIL, f"{', '.join(parts)} ({count})", body
    if expected.probe_edges is None:
        return PARTIAL, f"all {len(results)} probes match, but completeness is unknown ({count})", body
    return PASS, f"all probes match, every deny with the wall's signature ({count})", body


def attacks_section(folder: Path, expected: Expected) -> tuple[str, str, str]:
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
    numbers = [line["ticket"] for line in lines]
    _need(len(numbers) == len(set(numbers)), "attack-replay.json reports a ticket more than once")
    _need(expected.problem is None, str(expected.problem))
    missing, unexpected, count = _completeness(numbers, expected.attack_tickets, "attack tickets")
    if not rows:
        return FAIL, f"the file holds no ticket: nothing was replayed ({count})", _p("No attack results.")
    table = _table(["Ticket (row in docs/attacks.md)", "Attack", "Verdict", "Failed checks"],
                   rows, classes)
    body = _p(count) + table
    if failed or missing or unexpected:
        parts = [f"{failed} of {len(rows)} attack tickets got through a wall"] if failed else []
        parts += [f"missing tickets: {', '.join(map(str, missing))}"] if missing else []
        parts += [f"tickets not in the suite: {', '.join(map(str, unexpected))}"] if unexpected else []
        return FAIL, f"{'; '.join(parts)} ({count})", body
    if expected.attack_tickets is None:
        return PARTIAL, f"all {len(rows)} attack tickets stopped, but completeness is unknown ({count})", body
    return PASS, f"every attack ticket stopped ({count})", body


def pin_state(ref: str) -> str:
    """pinned (name:tag@sha256:<64 hex>), placeholder (all-zero digest), no tag, or no digest."""
    name, at, digest = ref.partition("@sha256:")
    if not at or not re.fullmatch(r"[0-9a-f]{64}", digest) or not name:
        return "no digest"
    if set(digest) == {"0"}:
        return "placeholder"
    last = name.rsplit("/", 1)[-1]
    if ":" not in last or not _TAG.fullmatch(last.rsplit(":", 1)[1]):
        return "no tag"
    return "pinned"


_PIN_LABELS = {"pinned": "tag and digest", "placeholder": "PLACEHOLDER (all-zero digest, replaced at deploy)",
               "no tag": "NO TAG (digest only)", "no digest": "NO DIGEST"}


def images_section(folder: Path, expected: Expected) -> tuple[str, str, str]:
    doc = _read_json(folder / "image-digests.json")
    _need(isinstance(doc, dict) and isinstance(doc.get("images"), list),
          'image-digests.json must be {"images": [...]}')
    rows, classes, states = [], [], Counter()
    for i, image in enumerate(doc["images"]):
        _need(isinstance(image, dict) and isinstance(image.get("reference"), str),
              f"image {i + 1} needs a reference string")
        sources = _strings(image.get("sources", []), f"image {i + 1} sources")
        state = pin_state(image["reference"])
        states[state] += 1
        rows.append([image["reference"], ", ".join(sources), _PIN_LABELS[state]])
        classes.append({"pinned": "ok", "placeholder": "skip"}.get(state, "bad"))
    if not rows:
        return FAIL, "the file lists no image", _p("No images.")
    table = _table(["Image", "Named in", "Pinned"], rows, classes)
    bad = states["no tag"] + states["no digest"]
    if bad:
        return FAIL, (f"{bad} of {len(rows)} image references are not pinned by tag and digest "
                      f"({states['no tag']} no tag, {states['no digest']} no digest)"), table
    if states["placeholder"]:
        return PARTIAL, (f"{states['pinned']} pinned by tag and digest, {states['placeholder']} "
                         "placeholder(s) with an all-zero digest, not pinned"), table
    return PASS, f"all {len(rows)} image references are pinned by tag and digest", table


def kql_section(folder: Path, expected: Expected) -> tuple[str, str, str]:
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


SECTIONS: tuple[tuple[str, str, str, bool, Callable[[Path, Expected], tuple[str, str, str]]], ...] = (
    ("permissions", "Permission assessment", "permissions/diff.json", True, permissions_section),
    ("probes", "Network probe matrix", "k8s-probe-matrix.json", True, probes_section),
    ("attacks", "Attack ticket replay", "attack-replay.json", True, attacks_section),
    ("images", "Image digests", "image-digests.json", True, images_section),
    ("kql", "Log Analytics queries (optional)", "kql/*.json", False, kql_section),
)


def build(folder: Path, generated: str, commit: str | None = None,
          expected: Expected | None = None) -> Report:
    expected = load_expected() if expected is None else expected
    sections = []
    for key, title, source, required, read in SECTIONS:
        try:
            status, summary, body = read(folder, expected)
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
.pass { color: var(--ok); } .fail, .error { color: var(--bad); } .not-run, .partial { color: var(--warn); }
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

_CLASSES = {PASS: "pass", FAIL: "fail", ERROR: "error", NOT_RUN: "not-run", PARTIAL: "partial",
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
IMAGE_FILES = ("**/Dockerfile", "**/*.Dockerfile", "compose.yaml", ".gitlab-ci.yml", "ci/*.sh",
               "deploy/**/*.yaml", "deploy/**/*.yml", "deploy/**/*.json", "scripts/*.sh")
_SKIP_DIRS = {".git", ".venv", "venv", "mutants", ".terraform", "reports", "node_modules"}
_FROM = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(?P<ref>\S+)", re.IGNORECASE)
_SHELL_IMAGE = re.compile(r"""^\s*(?:export\s+)?[A-Z_]*IMAGE=["']?(?P<ref>[^"'\s]+)""")
_YAML_KEY = re.compile(r"""^(?P<indent>\s*)(?:-\s+)?(?P<key>[\w.\-]+):\s*(?P<value>.*?)\s*$""")


def _ref_like(value: str) -> bool:
    """A value that names an image: has a tag, digest or path, no template, no build stage name."""
    value = value.strip("\"'")
    if not value or any(c in value for c in "${} ") or value.lower() == "scratch":
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9][\w.\-/:@]*", value)) and any(c in value for c in ":/@")


def _yaml_refs(lines: list[str]) -> list[str]:
    """Image references in YAML without a YAML parser: `image: x`, `name: x` under `image:`,
    every value of an `images:` map (Helm values), and split `image: {tag, sha}` blocks (the
    repository then comes from the chart's default; the path to the block stands for it)."""
    refs: list[str] = []
    stack: list[tuple[int, str]] = []  # (indent, key) of the open parents
    split: dict[tuple[str, ...], dict[str, str]] = {}
    for raw in lines:
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        m = _YAML_KEY.match(raw.split(" #", 1)[0])
        if not m:
            continue
        indent = len(m["indent"]) + (2 if raw.lstrip().startswith("- ") else 0)
        while stack and stack[-1][0] >= indent:
            stack.pop()
        key, value = m["key"], m["value"].strip("\"'")
        parent = stack[-1][1] if stack else ""
        if not m["value"]:
            stack.append((indent, key))
            continue
        path = tuple(k for _, k in stack)
        if key == "image" or (key == "name" and parent in ("image", "services")):
            if _ref_like(value):
                refs.append(value)
        elif parent == "images" and _ref_like(value):
            refs.append(value)
        elif (parent == "image" or parent.endswith("Image")) and key in ("tag", "sha", "digest", "repository"):
            split.setdefault(path, {})[key] = value
    for path, fields in split.items():
        if "tag" not in fields and "sha" not in fields and "digest" not in fields:
            continue
        name = fields.get("repository") or ".".join(path)
        ref = f"{name}:{fields['tag']}" if "tag" in fields else name
        digest = fields.get("sha") or fields.get("digest", "")
        digest = digest.removeprefix("sha256:")
        refs.append(f"{ref}@sha256:{digest}" if digest else ref)
    return refs


def collect_images(root: Path) -> dict:
    """Every image reference in the files that name images, pinned or not: Dockerfile `FROM`,
    shell `*IMAGE=` variables, YAML `image:` keys, Helm `images:` maps and split tag/sha blocks,
    and any reference with a sha256 digest anywhere else in those files."""
    found: dict[str, list[str]] = {}
    seen: set[Path] = set()
    for pattern in IMAGE_FILES:
        for path in sorted(root.glob(pattern)):
            rel = path.relative_to(root)
            if not path.is_file() or path in seen or _SKIP_DIRS & set(rel.parts):
                continue
            seen.add(path)
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            refs = [r for line in lines for r in DIGEST_REF.findall(line)]
            if path.name.endswith("Dockerfile"):
                refs += [m["ref"] for line in lines if (m := _FROM.match(line)) and _ref_like(m["ref"])]
            elif path.suffix == ".sh":
                refs += [m["ref"] for line in lines if (m := _SHELL_IMAGE.match(line)) and _ref_like(m["ref"])]
            elif path.suffix in (".yaml", ".yml"):
                refs += _yaml_refs(lines)
            for ref in refs:
                sources = found.setdefault(ref, [])
                if rel.as_posix() not in sources:
                    sources.append(rel.as_posix())
    return {"generated_by": "python -m secops.evidence --collect-images",
            "images": [{"reference": r, "sources": s} for r, s in sorted(found.items())]}
