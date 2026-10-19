"""The evidence report (secops/evidence): one static HTML page from the JSON reports.

The fixtures in tests/fixtures/evidence are a complete, passing reports folder. Each test copies
it to a temporary folder and removes or rewrites the files it is about, so a test can never
pass by reading a report another test left behind.
"""
from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

import pytest

from secops import evidence
from secops.evidence import __main__ as cli

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures" / "evidence"
NOW = "2026-10-18T10:00:00Z"
HOSTILE = '<script>alert(1)</script>"><img src=x onerror=alert(2)> $title ${sections} &amp;'
REQUIRED = ("permissions", "probes", "attacks", "images")


@pytest.fixture(autouse=True)
def fresh_db():
    """Replaces the autouse fixture of tests/conftest.py for this module: nothing here reads a
    database, so these tests need none and never touch the test database."""


@pytest.fixture
def reports(tmp_path) -> Path:
    folder = tmp_path / "reports"
    shutil.copytree(FIXTURES, folder)
    return folder


# What the fixtures cover: the probe edges and attack tickets the reports must hold.
FIXTURE_EXPECTED = evidence.Expected(
    probe_edges=("agent -> tool-gateway:8080", "agent -> postgres:5432",
                 "agent dns {random}.exfil.example.", "agent resolve kubernetes.default",
                 "tool-lookup-account -> imds:80"),
    attack_tickets=(1, 4, 9))


def build(folder: Path, expected: evidence.Expected = FIXTURE_EXPECTED) -> evidence.Report:
    return evidence.build(folder, generated=NOW, commit="0123abcd", expected=expected)


def section(report: evidence.Report, key: str) -> evidence.Section:
    return {s.key: s for s in report.sections}[key]


def write(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")


# --- complete reports -------------------------------------------------------------------------

def test_complete_reports_pass_every_section(reports):
    report = build(reports)
    assert {s.key: s.status for s in report.sections} == {
        "permissions": evidence.PASS, "probes": evidence.PASS, "attacks": evidence.PASS,
        "images": evidence.PASS, "kql": evidence.PASS}
    assert report.overall == evidence.OVERALL_PASS
    html = evidence.render(report)
    assert "agent -&gt; postgres:5432" in html and "another customer&#x27;s account" in html
    assert "0123abcd" in html and NOW in html


# --- missing reports: "not run", never a pass ---------------------------------------------------

def test_an_empty_reports_folder_renders_every_section_as_not_run(tmp_path):
    report = build(tmp_path / "nothing-here")
    for key in REQUIRED:
        assert section(report, key).status == evidence.NOT_RUN, key
    assert section(report, "kql").status == evidence.NOT_RUN
    assert report.overall == evidence.OVERALL_INCOMPLETE
    html = evidence.render(report)
    assert "not run" in html
    assert evidence.OVERALL_PASS not in html


@pytest.mark.parametrize("missing", ["permissions/diff.json", "k8s-probe-matrix.json",
                                     "attack-replay.json", "image-digests.json"])
def test_one_missing_report_makes_the_whole_report_incomplete(reports, missing):
    (reports / missing).unlink()
    report = build(reports)
    not_run = [s.key for s in report.sections if s.status == evidence.NOT_RUN]
    assert len(not_run) == 1 and not_run[0] in REQUIRED
    assert report.overall == evidence.OVERALL_INCOMPLETE


def test_the_optional_kql_section_does_not_change_the_overall_result(reports):
    shutil.rmtree(reports / "kql")
    report = build(reports)
    assert section(report, "kql").status == evidence.NOT_RUN
    assert report.overall == evidence.OVERALL_PASS


def test_a_failure_beats_a_missing_report(reports):
    (reports / "image-digests.json").unlink()
    write(reports / "attack-replay.json", [{"ticket": 5, "name": "flood", "passed": False,
                                            "failures": ["effects: 2 effect calls succeeded"]}])
    assert build(reports).overall == evidence.OVERALL_FAIL


# --- each section judges its own data -----------------------------------------------------------

def test_permission_differences_and_errors_fail(reports):
    diff = json.loads((reports / "permissions" / "diff.json").read_text(encoding="utf-8"))
    diff["planes"]["pg"]["extra"] = ["pg role tool_lookup_account: SELECT (phone) ON public.customers"]
    diff["exit_code"] = 1
    write(reports / "permissions" / "diff.json", diff)
    s = section(build(reports), "permissions")
    assert s.status == evidence.FAIL
    assert "SELECT (phone) ON public.customers" in s.body

    diff["planes"]["pg"]["extra"] = []
    diff["errors"] = {"k8s": "kubectl is not installed"}
    diff["exit_code"] = 2
    write(reports / "permissions" / "diff.json", diff)
    s = section(build(reports), "permissions")
    assert s.status == evidence.ERROR and "kubectl is not installed" in s.body


def test_permissions_with_every_plane_skipped_assessed_nothing(reports):
    write(reports / "permissions" / "diff.json", {
        "planes": {"azure": {"extra": [], "missing": [], "not_deployed": [],
                             "skipped": "not logged in to Azure"}},
        "errors": {}, "warnings": [], "exit_code": 0})
    assert section(build(reports), "permissions").status == evidence.ERROR


def test_permissions_exit_code_must_agree_with_the_differences(reports):
    diff = json.loads((reports / "permissions" / "diff.json").read_text(encoding="utf-8"))
    diff["planes"]["compose"]["missing"] = ["agent -> tool-gateway"]
    diff["exit_code"] = 0  # a hand-edited or truncated file
    write(reports / "permissions" / "diff.json", diff)
    assert section(build(reports), "permissions").status == evidence.ERROR

    diff["planes"]["compose"]["missing"] = []
    diff["exit_code"] = 1  # the run failed, but the file no longer says why
    write(reports / "permissions" / "diff.json", diff)
    assert section(build(reports), "permissions").status == evidence.ERROR


@pytest.mark.parametrize("result, verdict", [
    ({"kind": "tcp", "expected": "deny", "observed": "deny", "detail": "timeout"}, True),
    ({"kind": "dns", "expected": "deny", "observed": "deny", "detail": "REFUSED"}, True),
    ({"kind": "tcp", "expected": "allow", "observed": "allow", "detail": "connected"}, True),
    # A deny without the wall's signature is a probe that could not run, not a wall.
    ({"kind": "tcp", "expected": "deny", "observed": "deny", "detail": "name lookup failed"}, False),
    ({"kind": "dns", "expected": "deny", "observed": "deny", "detail": "timeout (no answer)"}, False),
    ({"kind": "tcp", "expected": "deny", "observed": "error", "detail": "unreachable"}, False),
    ({"kind": "tcp", "expected": "deny", "observed": "allow", "detail": "connected"}, False),
    ({"kind": "tcp", "expected": "allow", "observed": "deny", "detail": "timeout"}, False),
    ({"kind": "smtp", "expected": "deny", "observed": "deny", "detail": "timeout"}, False),
])
def test_each_probe_result_is_judged_again(result, verdict):
    assert evidence.probe_passed(result) is verdict


def test_one_failed_probe_fails_the_matrix_and_is_listed(reports):
    results = json.loads((reports / "k8s-probe-matrix.json").read_text(encoding="utf-8"))
    results[1]["observed"], results[1]["detail"] = "allow", "connected"
    write(reports / "k8s-probe-matrix.json", results)
    s = section(build(reports), "probes")
    assert s.status == evidence.FAIL
    assert "1 of 5 failed" in s.summary


def test_an_empty_probe_matrix_is_not_a_pass(reports):
    write(reports / "k8s-probe-matrix.json", [])
    assert section(build(reports), "probes").status == evidence.FAIL


@pytest.mark.parametrize("line", [
    {"ticket": 3, "name": "flag changed", "passed": True, "failures": ["refused_tools: a call to set_flag succeeded"]},
    {"ticket": 3, "name": "flag changed", "passed": "true", "failures": []},
    {"ticket": 3, "name": "flag changed", "passed": 1, "failures": []},
    {"ticket": 3, "name": "flag changed", "failures": []},
])
def test_an_attack_passes_only_when_passed_is_true_and_nothing_failed(reports, line):
    # The suite expects ticket 3 only, so completeness cannot be what fails these.
    only_3 = evidence.Expected(FIXTURE_EXPECTED.probe_edges, (3,))
    write(reports / "attack-replay.json", json.dumps(line) + "\n")
    assert section(build(reports, expected=only_3), "attacks").status == evidence.FAIL
    control = {"ticket": 3, "name": "flag changed", "passed": True, "failures": []}
    write(reports / "attack-replay.json", json.dumps(control) + "\n")
    assert section(build(reports, expected=only_3), "attacks").status == evidence.PASS


def test_attack_results_read_as_a_json_list_too(reports):
    write(reports / "attack-replay.json", [{"ticket": 1, "name": "x", "passed": True, "failures": []}])
    one = evidence.Expected(FIXTURE_EXPECTED.probe_edges, (1,))
    assert section(build(reports, expected=one), "attacks").status == evidence.PASS


def test_an_empty_attack_report_is_not_a_pass(reports):
    write(reports / "attack-replay.json", "\n")
    assert section(build(reports), "attacks").status == evidence.FAIL


def test_an_image_without_a_digest_fails(reports):
    write(reports / "image-digests.json", {"images": [
        {"reference": "python:3.12-slim", "sources": ["Dockerfile"]}]})
    s = section(build(reports), "images")
    assert s.status == evidence.FAIL and "python:3.12-slim" in s.body


# --- malformed files: an error, never a crash ----------------------------------------------------

@pytest.mark.parametrize("path, content", [
    ("permissions/diff.json", "{not json"),
    ("permissions/diff.json", "[]"),
    ("permissions/diff.json", '{"planes": {"pg": "equal"}}'),
    ("k8s-probe-matrix.json", '{"results": []}'),
    ("k8s-probe-matrix.json", '["agent -> db"]'),
    ("k8s-probe-matrix.json", '[{"edge": "a"}]'),
    ("attack-replay.json", "{broken\n"),
    ("attack-replay.json", '{"ticket": 1, "name": "x", "passed": true, "failures": "none"}\n'),
    ("image-digests.json", '{"images": "python"}'),
    ("image-digests.json", '{"images": [{"reference": 5}]}'),
    ("kql/heartbeat-missing.json", '{"rows": 1}'),
    ("kql/heartbeat-missing.json", "[1, 2]"),
])
def test_a_malformed_report_is_an_error_section(reports, path, content):
    write(reports / path, content)
    report = build(reports)
    statuses = {s.key: s.status for s in report.sections}
    assert evidence.ERROR in statuses.values(), statuses
    assert report.overall == evidence.OVERALL_FAIL
    evidence.render(report)


def test_an_unexpected_exception_in_a_section_is_an_error_section(reports, monkeypatch):
    def broken(folder):
        raise RuntimeError("bug in a reader")

    sections = tuple((k, t, s, r, broken if k == "probes" else f)
                     for k, t, s, r, f in evidence.SECTIONS)
    monkeypatch.setattr(evidence, "SECTIONS", sections)
    report = build(reports)
    assert section(report, "probes").status == evidence.ERROR
    assert report.overall == evidence.OVERALL_FAIL


def test_an_unreadable_file_is_an_error_section(reports):
    (reports / "attack-replay.json").write_bytes(b"\xff\xfe\x00broken")
    assert section(build(reports), "attacks").status == evidence.ERROR


# --- escaping --------------------------------------------------------------------------------

def hostile_reports(folder: Path) -> None:
    write(folder / "permissions" / "diff.json", {
        "planes": {HOSTILE: {"extra": [HOSTILE], "missing": [HOSTILE], "not_deployed": [HOSTILE],
                             "skipped": None}},
        "errors": {}, "warnings": [HOSTILE], "exit_code": 1})
    write(folder / "permissions" / "summary.txt", HOSTILE)
    write(folder / "permissions" / "matrix.md", HOSTILE)
    write(folder / "k8s-probe-matrix.json", [{"edge": HOSTILE, "source": HOSTILE, "kind": "tcp",
                                              "expected": HOSTILE, "observed": HOSTILE,
                                              "detail": HOSTILE, "why": HOSTILE}])
    write(folder / "attack-replay.json", [{"ticket": 1, "name": HOSTILE, "passed": False,
                                           "failures": [HOSTILE]}])
    write(folder / "image-digests.json", {"images": [{"reference": HOSTILE, "sources": [HOSTILE]}]})
    write(folder / "kql" / "q.json", [{HOSTILE: HOSTILE}])


def test_every_value_from_a_report_is_escaped(reports):
    hostile_reports(reports)
    report = evidence.build(reports, generated=HOSTILE, commit=HOSTILE, expected=FIXTURE_EXPECTED)
    html = evidence.render(report)
    assert "<script" not in html and "<img" not in html
    # The attack table itself renders the hostile name and failure, escaped.
    attacks = section(report, "attacks")
    assert attacks.status == evidence.FAIL
    assert attacks.body.count("&lt;script&gt;alert(1)&lt;/script&gt;") == 2
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "&quot;&gt;&lt;img src=x onerror=alert(2)&gt;" in html
    assert "&amp;amp;" in html  # an entity in the data stays text


def test_template_placeholders_in_the_data_are_not_expanded(reports):
    hostile_reports(reports)
    html = evidence.render(build(reports))
    assert "$title ${sections}" in html
    assert html.count("<title>") == 1


def test_a_kql_file_name_is_escaped(reports):
    write(reports / "kql" / "a&b'x.json", [{"n": 1}])  # < > " are not allowed in Windows names
    html = evidence.render(build(reports))
    assert "a&amp;b&#x27;x" in html and "a&b'x" not in html


def test_the_page_loads_nothing_and_runs_nothing():
    html = evidence.render(build(FIXTURES))
    assert "Content-Security-Policy" in html and "default-src 'none'" in html
    assert "<script" not in html
    assert not re.search(r"""(src|href)\s*=\s*["']?(https?:)?//""", html)


# --- image references ----------------------------------------------------------------------------

def test_collect_images_finds_the_pinned_references_of_this_repository():
    doc = evidence.collect_images(ROOT)
    refs = {i["reference"]: i["sources"] for i in doc["images"]}
    dockerfile = [ln.split()[1] for ln in (ROOT / "Dockerfile").read_text(encoding="utf-8").splitlines()
                  if ln.startswith("FROM ") and "@" in ln]  # not FROM scratch
    assert dockerfile and all(r in refs and "Dockerfile" in refs[r] for r in dockerfile)
    assert all(evidence.DIGEST_REF.fullmatch(r) for r in refs)


def test_collect_images_reports_an_image_line_without_a_digest(tmp_path):
    write(tmp_path / "compose.yaml", "services:\n  db:\n    image: postgres:17-alpine\n")
    doc = evidence.collect_images(tmp_path)
    assert doc["images"] == [{"reference": "postgres:17-alpine", "sources": ["compose.yaml"]}]


def test_a_truncated_image_inventory_cannot_pass(reports, tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    items = json.loads((reports / "image-digests.json").read_text())["images"]
    (root / "Dockerfile").write_text("\n".join("FROM " + i["reference"] for i in items), encoding="utf-8")
    write(reports / "image-digests.json", {"images": items[:1]})
    report = evidence.build(reports, generated=NOW, expected=FIXTURE_EXPECTED, image_root=root)
    assert section(report, "images").status == evidence.FAIL
    write(reports / "image-digests.json", {"images": items})
    assert section(evidence.build(reports, generated=NOW, expected=FIXTURE_EXPECTED, image_root=root), "images").status == evidence.PASS


# --- command line --------------------------------------------------------------------------------

@pytest.fixture
def fixture_expectations(monkeypatch):
    """The CLI asks the attack suite what to expect; the fixtures cover a few edges only."""
    monkeypatch.setattr(evidence, "load_expected", lambda: FIXTURE_EXPECTED)
    monkeypatch.setattr(evidence, "collect_images", lambda root: json.loads((FIXTURES / "image-digests.json").read_text()))


def test_cli_writes_the_page_and_exits_zero_unless_strict(reports, capsys, fixture_expectations):
    out = reports / "evidence.html"
    (reports / "attack-replay.json").unlink()
    assert cli.main(["--reports", str(reports), "--out", str(out)]) == 0
    assert out.read_text(encoding="utf-8").startswith("<!doctype html>")
    assert "attacks: not run" in capsys.readouterr().out
    assert cli.main(["--reports", str(reports), "--out", str(out), "--strict"]) == 1


def test_cli_strict_passes_on_complete_reports(reports, fixture_expectations):
    assert cli.main(["--reports", str(reports), "--out", str(reports / "e.html"), "--strict"]) == 0


def test_cli_collects_images_first_when_asked(tmp_path):
    folder = tmp_path / "reports"
    write(tmp_path / "Dockerfile", "FROM python:3.12-slim@sha256:" + "a" * 64 + "\n")
    assert cli.main(["--reports", str(folder), "--out", str(folder / "e.html"),
                     "--collect-images", str(tmp_path)]) == 0
    doc = json.loads((folder / "image-digests.json").read_text(encoding="utf-8"))
    assert doc["images"][0]["sources"] == ["Dockerfile"]


# --- completeness: a partial report is never a pass ----------------------------------------------

def test_fewer_probe_results_than_the_matrix_fail_and_name_the_missing_edges(reports):
    results = json.loads((reports / "k8s-probe-matrix.json").read_text(encoding="utf-8"))
    write(reports / "k8s-probe-matrix.json", results[:1])
    s = section(build(reports), "probes")
    assert s.status == evidence.FAIL
    assert "expected 5, found 1" in s.summary
    assert "tool-lookup-account -&gt; imds:80" in s.body


def test_a_probe_result_that_is_not_in_the_matrix_fails(reports):
    results = json.loads((reports / "k8s-probe-matrix.json").read_text(encoding="utf-8"))
    results.append(dict(results[0], edge="agent -> somewhere:1"))
    write(reports / "k8s-probe-matrix.json", results)
    s = section(build(reports), "probes")
    assert s.status == evidence.FAIL and "agent -&gt; somewhere:1" in s.body


def test_a_probe_edge_reported_twice_is_an_error(reports):
    results = json.loads((reports / "k8s-probe-matrix.json").read_text(encoding="utf-8"))
    write(reports / "k8s-probe-matrix.json", results + results[:1])
    assert section(build(reports), "probes").status == evidence.ERROR


def test_fewer_attack_tickets_than_the_suite_fail_and_name_the_missing_ones(reports):
    write(reports / "attack-replay.json",
          '{"ticket": 1, "name": "x", "passed": true, "failures": []}\n')
    s = section(build(reports), "attacks")
    assert s.status == evidence.FAIL
    assert "expected 3, found 1" in s.summary and "missing tickets: 4, 9" in s.summary


def test_an_attack_ticket_reported_twice_is_an_error(reports):
    line = '{"ticket": 1, "name": "x", "passed": true, "failures": []}\n'
    write(reports / "attack-replay.json", line * 2 + line.replace("1", "4", 1) + line.replace("1", "9", 1))
    assert section(build(reports), "attacks").status == evidence.ERROR


def test_without_the_expected_lists_probes_and_attacks_are_partial_never_pass(reports):
    report = build(reports, expected=evidence.Expected(probe_edges=None, attack_tickets=None))
    assert section(report, "probes").status == evidence.PARTIAL
    assert section(report, "attacks").status == evidence.PARTIAL
    assert report.overall == evidence.OVERALL_INCOMPLETE


def test_expected_lists_come_from_the_attack_suite(monkeypatch):
    import sys
    import types

    probes = types.ModuleType("attacks.probes")
    probes.matrix = lambda: [types.SimpleNamespace(edge="a -> b:1"), types.SimpleNamespace(edge="a dns x.")]
    tickets = types.ModuleType("attacks.tickets")
    tickets.ATTACK_TICKETS = tuple(types.SimpleNamespace(number=n) for n in (1, 2, 3))
    package = types.ModuleType("attacks")
    package.probes, package.tickets = probes, tickets
    monkeypatch.setitem(sys.modules, "attacks", package)
    monkeypatch.setitem(sys.modules, "attacks.probes", probes)
    monkeypatch.setitem(sys.modules, "attacks.tickets", tickets)
    assert evidence.load_expected() == evidence.Expected(("a -> b:1", "a dns x."), (1, 2, 3))


def test_without_the_attack_suite_nothing_is_expected(monkeypatch):
    import sys

    monkeypatch.setitem(sys.modules, "attacks", None)  # makes the import fail
    assert evidence.load_expected() == evidence.Expected(None, None)


def test_a_skipped_plane_next_to_an_assessed_one_is_partial_and_named(reports):
    diff = json.loads((reports / "permissions" / "diff.json").read_text(encoding="utf-8"))
    diff["planes"]["azure"] = {"extra": [], "missing": [], "not_deployed": [],
                               "skipped": "not logged in to Azure"}
    write(reports / "permissions" / "diff.json", diff)
    report = build(reports)
    s = section(report, "permissions")
    assert s.status == evidence.PARTIAL
    assert "skipped: azure" in s.summary
    assert report.overall == evidence.OVERALL_INCOMPLETE


# --- image pinning -------------------------------------------------------------------------------

DIGEST = "a" * 64


@pytest.mark.parametrize("ref, state", [
    (f"python:3.12-slim@sha256:{DIGEST}", "pinned"),
    (f"ghcr.io/org/tool:v1@sha256:{DIGEST}", "pinned"),
    (f"localhost:5001/app:1.0@sha256:{DIGEST}", "pinned"),
    (f"localhost:5001/assume-hijacked@sha256:{DIGEST}", "no tag"),
    (f"python@sha256:{DIGEST}", "no tag"),
    ("python:3.12-slim@sha256:" + "0" * 64, "placeholder"),
    ("acr.azurecr.io/azure-cli@sha256:" + "0" * 64, "placeholder"),
    ("python:3.12-slim", "no digest"),
    ("localhost:5001/app", "no digest"),
    (f"python:3.12-slim@sha256:{DIGEST[:63]}", "no digest"),
])
def test_image_pin_state(ref, state):
    assert evidence.pin_state(ref) == state


def test_a_reference_without_a_tag_fails(reports):
    write(reports / "image-digests.json", {"images": [
        {"reference": f"localhost:5001/assume-hijacked@sha256:{DIGEST}", "sources": ["values"]}]})
    s = section(build(reports), "images")
    assert s.status == evidence.FAIL and "NO TAG" in s.body


def test_an_all_zero_digest_is_a_labelled_placeholder_never_a_pin(reports):
    doc = json.loads((reports / "image-digests.json").read_text(encoding="utf-8"))
    doc["images"].append({"reference": "acr.azurecr.io/app:1@sha256:" + "0" * 64,
                          "sources": ["values-azure.yaml"]})
    write(reports / "image-digests.json", doc)
    s = section(build(reports), "images")
    assert s.status == evidence.PARTIAL
    assert "PLACEHOLDER" in s.body and "1 placeholder" in s.summary


def test_collect_images_reads_helm_image_maps_split_tags_and_shell_variables(tmp_path):
    write(tmp_path / "deploy" / "helm" / "c" / "values.yaml",
          "images:\n  # a comment\n  app: repo/app:1.0\n  db: postgres:17@sha256:" + DIGEST + "\n"
          'registry: ""\nother:\n  app: not-an-image\n')
    write(tmp_path / "deploy" / "monitoring" / "values.yaml",
          "prometheusOperator:\n  image:\n    tag: v0.94.1\n    sha: " + DIGEST + "\n"
          "alertmanager:\n  spec:\n    image:\n      tag: v0.34.1\n")
    write(tmp_path / "scripts" / "registry.sh", 'IMAGE="registry:3"\n')
    write(tmp_path / "attacks" / "Dockerfile", "FROM scratch AS wheels\nFROM python:3.12-slim\n")
    refs = {i["reference"]: i["sources"] for i in evidence.collect_images(tmp_path)["images"]}
    assert refs["repo/app:1.0"] == ["deploy/helm/c/values.yaml"]
    assert f"postgres:17@sha256:{DIGEST}" in refs
    assert f"prometheusOperator.image:v0.94.1@sha256:{DIGEST}" in refs
    assert "alertmanager.spec.image:v0.34.1" in refs
    assert refs["registry:3"] == ["scripts/registry.sh"]
    assert refs["python:3.12-slim"] == ["attacks/Dockerfile"]
    assert "not-an-image" not in refs and "scratch" not in refs


# --- the command line never echoes control characters ------------------------------------------

def test_cli_output_has_no_control_characters_from_the_reports(reports, capsys, fixture_expectations):
    diff = json.loads((reports / "permissions" / "diff.json").read_text(encoding="utf-8"))
    hostile = "azure\x1b[2J\x1b]0;owned\x07\nresult: PASS\r\x85 "
    diff["planes"][hostile] = {"extra": [], "missing": [], "not_deployed": [], "skipped": "no login"}
    write(reports / "permissions" / "diff.json", diff)
    cli.main(["--reports", str(reports), "--out", str(reports / "e.html")])
    out = capsys.readouterr().out
    assert not any(not c.isprintable() and c != "\n" for c in out)
    assert "skipped: azure" in out and "owned" in out  # the name is shown, made harmless
    assert len(out.split("\n")) == 7  # one line per section, the result line, the final newline


def _fake_suite(monkeypatch, matrix, tickets=(1, 4, 9)):
    import sys
    import types

    probes_mod = types.ModuleType("attacks.probes")
    probes_mod.matrix = matrix
    tickets_mod = types.ModuleType("attacks.tickets")
    tickets_mod.ATTACK_TICKETS = tuple(types.SimpleNamespace(number=n) for n in tickets)
    package = types.ModuleType("attacks")
    package.probes, package.tickets = probes_mod, tickets_mod
    monkeypatch.setitem(sys.modules, "attacks", package)
    monkeypatch.setitem(sys.modules, "attacks.probes", probes_mod)
    monkeypatch.setitem(sys.modules, "attacks.tickets", tickets_mod)


def test_a_broken_attack_suite_gives_error_sections_not_a_crash(reports, monkeypatch):
    def matrix():
        raise RuntimeError("bug in the matrix")

    _fake_suite(monkeypatch, matrix)
    report = evidence.build(reports, generated=NOW)  # expected lists loaded from the suite
    assert section(report, "probes").status == evidence.ERROR
    assert section(report, "attacks").status == evidence.ERROR
    assert "RuntimeError" in section(report, "probes").summary
    assert report.overall == evidence.OVERALL_FAIL
    evidence.render(report)


def test_an_expected_list_of_the_wrong_type_is_an_error(reports, monkeypatch):
    import types

    _fake_suite(monkeypatch, lambda: [types.SimpleNamespace(edge=5)])
    report = evidence.build(reports, generated=NOW)
    assert section(report, "probes").status == evidence.ERROR
    assert section(report, "attacks").status == evidence.ERROR


def test_a_missing_report_stays_not_run_even_with_a_broken_suite(tmp_path, monkeypatch):
    def matrix():
        raise RuntimeError("bug in the matrix")

    _fake_suite(monkeypatch, matrix)
    report = evidence.build(tmp_path / "empty", generated=NOW)
    assert section(report, "probes").status == evidence.NOT_RUN
    assert report.overall == evidence.OVERALL_INCOMPLETE


@pytest.mark.parametrize("probes_source, error", [
    ("raise RuntimeError('broken at import')\n", "RuntimeError"),
    ("import no_such_module_in_this_repository\n", "ModuleNotFoundError"),
    ("from attacks import nothing_here\n", "ImportError"),
    ("def broken(:\n", "SyntaxError"),
])
def test_an_attack_suite_that_fails_to_import_gives_error_sections(reports, tmp_path, monkeypatch,
                                                                    probes_source, error):
    import sys

    package = tmp_path / "suite" / "attacks"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "probes.py").write_text(probes_source, encoding="utf-8")
    (package / "tickets.py").write_text("ATTACK_TICKETS = ()\n", encoding="utf-8")
    saved = {name: module for name, module in sys.modules.items()
             if name == "attacks" or name.startswith("attacks.")}
    try:
        for name in saved:
            sys.modules.pop(name, None)
        monkeypatch.syspath_prepend(str(tmp_path / "suite"))
        expected = evidence.load_expected()
        assert expected.problem and error in expected.problem
        report = evidence.build(reports, generated=NOW)
        assert section(report, "probes").status == evidence.ERROR
        assert section(report, "attacks").status == evidence.ERROR
        assert report.overall == evidence.OVERALL_FAIL
    finally:
        # A failed submodule import still leaves its parent package cached.
        for name in list(sys.modules):
            if name == "attacks" or name.startswith("attacks."):
                sys.modules.pop(name, None)
        sys.modules.update(saved)
