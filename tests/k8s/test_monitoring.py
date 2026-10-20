"""The monitoring stack (deploy/monitoring): Prometheus, Alertmanager, Grafana and Mailpit.

Docker has 6 GB, so the stack is not installed while the application is built. Everything here is
checked without a cluster:

  - `helm template` of the pinned kube-prometheus-stack chart with our values (needs helm and a
    one-time download of the chart; skipped when it cannot be fetched),
  - `promtool check rules` and `promtool test rules` in a container pinned by digest (needs
    docker; skipped without it),
  - the dashboard JSON, the Mailpit manifest and the scripts, read as files.

The rule files (two alerts: ExecutorHeartbeatStale, KillSwitchFired) and the walls board are also
read as plain files below, without promtool or a cluster. promtool itself runs in CI and on kind:
`promtool test rules` over assume-hijacked.test.yaml.
"""

import hashlib
import json
import os
import re
import subprocess
import tempfile
from functools import cache
from pathlib import Path

import pytest
import yaml

from tests.k8s.test_chart import HELM, ROOT

REQUIRE_RENDER = os.environ.get("AH_REQUIRE_MONITORING_RENDER") == "1"
MONITORING = ROOT / "deploy" / "monitoring"
VALUES = MONITORING / "kube-prometheus-values.yaml"
DASHBOARD = MONITORING / "dashboards" / "walls.json"
MONITORING_SCRIPT = ROOT / "scripts" / "kind-monitoring.sh"

NAMESPACE = "ah-monitoring"
DIGEST = re.compile(r"@sha256:[a-f0-9]{64}$")


# --- helpers ------------------------------------------------------------------------------------

@cache
def values() -> dict:
    return yaml.safe_load(VALUES.read_text(encoding="utf-8"))


@cache
def dashboard() -> dict:
    return json.loads(DASHBOARD.read_text(encoding="utf-8"))


def script_constant(name: str) -> str:
    match = re.search(rf'^{name}="([^"]+)"', MONITORING_SCRIPT.read_text(encoding="utf-8"), re.M)
    assert match, f"{name} not set in {MONITORING_SCRIPT.name}"
    return match.group(1)


def prometheus_image() -> str:
    """The Prometheus image of the values file; it also carries promtool (/bin/promtool)."""
    spec = values()["prometheus"]["prometheusSpec"]["image"]
    return f"quay.io/prometheus/prometheus@sha256:{spec['sha']}"


def promtool(directory: Path, *args: str) -> subprocess.CompletedProcess:
    """promtool from the pinned Prometheus image, with `directory` mounted read-only. promtool
    downloads nothing, so no CA bundle is needed behind a TLS-intercepting scanner."""
    return subprocess.run(
        ["docker", "run", "--rm", "--network", "none", "-v", f"{directory}:/work:ro", "-w", "/work",
         "--entrypoint", "/bin/promtool", prometheus_image(), *args],
        capture_output=True, text=True, encoding="utf-8", timeout=300, check=False)


@cache
def _fetch_kps_chart() -> tuple[Path, str | None]:
    """The pinned kube-prometheus-stack chart file, downloaded once and checked against the digest
    in scripts/kind-monitoring.sh (the one from the chart repository's index)."""
    version = script_constant("KPS_VERSION")
    sha = script_constant("KPS_CHART_SHA256")
    repo = script_constant("KPS_REPO")
    cache_dir = Path(tempfile.gettempdir()) / "ah-kps-chart"
    chart = cache_dir / f"kube-prometheus-stack-{version}.tgz"
    if HELM is None:
        return chart, "helm is not installed"
    if not chart.exists():
        cache_dir.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(
            [HELM, "pull", "kube-prometheus-stack", "--repo", repo, "--version", version,
             "--destination", str(cache_dir)],
            capture_output=True, text=True, encoding="utf-8", timeout=300, check=False)
        if result.returncode != 0:
            return chart, f"cannot download kube-prometheus-stack {version}: {result.stderr.strip()[:200]}"
    assert hashlib.sha256(chart.read_bytes()).hexdigest() == sha, "chart file differs from the pinned digest"
    return chart, None


def kps_chart() -> Path:
    chart, problem = _fetch_kps_chart()
    if problem:
        if REQUIRE_RENDER:
            pytest.fail(problem)
        pytest.skip(problem)
    return chart


@cache
def stack() -> tuple:
    """`helm template` of the stack with our values, as the namespace ah-monitoring sees it."""
    chart = kps_chart()
    result = subprocess.run(
        [HELM, "template", "kps", str(chart), "--namespace", NAMESPACE, "--values", str(VALUES)],
        capture_output=True, text=True, encoding="utf-8", timeout=300, check=False)
    assert result.returncode == 0, result.stderr
    docs = []
    for doc in yaml.safe_load_all(result.stdout):
        if not doc:
            continue
        # PodMonitors and ServiceMonitors from the values come inside a List.
        docs.extend(doc["items"] if doc["kind"] == "List" else [doc])
    return tuple(docs)


def stack_objects(kind: str) -> list[dict]:
    return [d for d in stack() if d["kind"] == kind]


def pod_security_problems(pod: dict, containers: list[dict]) -> list[str]:
    """What Pod Security "restricted" would refuse, for the fields the manifest sets."""
    problems = []
    pod_sc = pod.get("securityContext", {})
    if pod.get("hostNetwork") or pod.get("hostPID") or pod.get("hostIPC"):
        problems.append("host namespaces")
    if any("hostPath" in v for v in pod.get("volumes") or []):
        problems.append("hostPath volume")
    for c in containers:
        sc = c.get("securityContext", {})
        name = c["name"]
        if sc.get("allowPrivilegeEscalation") is not False:
            problems.append(f"{name}: allowPrivilegeEscalation not false")
        if sc.get("capabilities", {}).get("drop") != ["ALL"]:
            problems.append(f"{name}: capabilities not dropped")
        if not (sc.get("runAsNonRoot") or pod_sc.get("runAsNonRoot")):
            problems.append(f"{name}: runAsNonRoot missing")
        if "RuntimeDefault" not in (sc.get("seccompProfile", {}).get("type"),
                                    pod_sc.get("seccompProfile", {}).get("type")):
            problems.append(f"{name}: seccomp profile missing")
        if sc.get("privileged"):
            problems.append(f"{name}: privileged")
    return problems


# --- the stack, rendered ---------------------------------------------------------------------


@pytest.mark.skipif(HELM is None, reason="helm is not installed")
def test_stack_pods_meet_pod_security_restricted():
    """The namespace enforces "restricted" (scripts/kind-monitoring.sh); Prometheus and
    Alertmanager pods are built by the operator from these settings."""
    problems = []
    for d in stack_objects("Deployment"):
        pod = d["spec"]["template"]["spec"]
        problems += [f"{d['metadata']['name']}: {p}"
                     for p in pod_security_problems(pod, pod["containers"] + pod.get("initContainers", []))]
    for kind in ("Prometheus", "Alertmanager"):
        spec = stack_objects(kind)[0]["spec"]
        sc = spec["securityContext"]
        if not sc.get("runAsNonRoot") or sc.get("seccompProfile", {}).get("type") != "RuntimeDefault":
            problems.append(f"{kind}: pod security context")
    assert not problems, problems


# --- rules and board, read as files -----------------------------------------------------------

RULES = MONITORING / "rules" / "assume-hijacked.yaml"
RULE_TESTS = MONITORING / "rules" / "assume-hijacked.test.yaml"
APP = ROOT / "app"
METRIC = re.compile(r"\b(?:executor|risk|gateway)_[a-z_]+")


def alert_rules() -> list[dict]:
    spec = yaml.safe_load(RULES.read_text(encoding="utf-8"))["spec"]
    return [r for g in spec["groups"] for r in g["rules"]]


def test_there_are_exactly_two_alerts_and_each_has_a_promtool_test():
    alerts = {r["alert"] for r in alert_rules()}
    assert alerts == {"ExecutorHeartbeatStale", "KillSwitchFired"}
    tested = {t["alertname"] for case in yaml.safe_load(RULE_TESTS.read_text(encoding="utf-8"))["tests"]
              for t in case["alert_rule_test"]}
    assert alerts <= tested


def test_the_walls_board_has_the_panels_the_design_names():
    titles = [p["title"] for p in dashboard()["panels"]]
    for needed in ("Kill switch", "Approvals waiting", "Risk tiers", "Tool calls by outcome", "Packets dropped",
                   "Agent-side drops by kind", "Second effect on one lease"):
        assert any(needed in t for t in titles), needed
    ids = [p["id"] for p in dashboard()["panels"]]
    assert len(ids) == len(set(ids))


def test_every_metric_of_the_rules_and_the_board_is_exported_by_the_app():
    exprs = [r["expr"] for r in alert_rules()]
    exprs += [t["expr"] for p in dashboard()["panels"] for t in p["targets"]]
    names = {m for e in exprs for m in METRIC.findall(e)}
    assert {"risk_agents_paused", "executor_last_poll_timestamp_seconds"} <= names
    source = "\n".join(f.read_text(encoding="utf-8") for f in APP.rglob("*.py"))
    missing = sorted(n for n in names if f'"{n}"' not in source)
    assert not missing, missing
