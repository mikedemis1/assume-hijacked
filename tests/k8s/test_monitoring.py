"""The monitoring stack (deploy/monitoring): Prometheus, Alertmanager, Grafana and Mailpit.

Docker has 6 GB, so the stack is not installed while the application is built. Everything here is
checked without a cluster:

  - `helm template` of the pinned kube-prometheus-stack chart with our values (needs helm and a
    one-time download of the chart; skipped when it cannot be fetched),
  - `promtool check rules` and `promtool test rules` in a container pinned by digest (needs
    docker; skipped without it),
  - the dashboard JSON, the Mailpit manifest and the scripts, read as files.

`test_heartbeat_alert_fires_when_executor_stopped` needs the installed stack
(`sh scripts/kind-monitoring.sh`) next to the installed application chart. It is skipped unless
AH_MONITORING_INSTALLED=1 and runs with `pytest -m k8s tests/k8s/test_monitoring.py`.
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from functools import cache
from pathlib import Path

import pytest
import yaml

from tests.k8s.conftest import run_kubectl
from tests.k8s.test_chart import HELM, ROOT, rendered

MONITORING = ROOT / "deploy" / "monitoring"
VALUES = MONITORING / "kube-prometheus-values.yaml"
RULES = MONITORING / "rules" / "assume-hijacked.yaml"
RULE_TESTS = MONITORING / "rules" / "assume-hijacked.test.yaml"
DASHBOARD = MONITORING / "dashboards" / "walls.json"
MAILPIT = MONITORING / "mailpit.yaml"
MONITORING_SCRIPT = ROOT / "scripts" / "kind-monitoring.sh"
KIND_UP = ROOT / "scripts" / "kind-up.sh"
CILIUM_VALUES = ROOT / "deploy" / "kind" / "cilium-values.yaml"

NAMESPACE = "ah-monitoring"
DIGEST = re.compile(r"@sha256:[a-f0-9]{64}$")
ALERTS = {"ExecutorHeartbeatStale", "RiskEngineDown", "GatewayDenialsBurst"}
# The metric names the application writes (app/common/ops.py renders them; the executor, the risk
# engine and the tool gateway own the ones below) plus the Hubble drop counter and Prometheus's own.
KNOWN_METRICS = {
    "executor_last_poll_timestamp_seconds", "executor_requests_total",
    "risk_decisions_total", "risk_tiers_total", "risk_errors_total",
    "gateway_calls_total", "gateway_denials_total",
    "hubble_drop_total", "up",
}


# --- helpers ------------------------------------------------------------------------------------

@cache
def values() -> dict:
    return yaml.safe_load(VALUES.read_text(encoding="utf-8"))


@cache
def rule_spec() -> dict:
    doc = yaml.safe_load(RULES.read_text(encoding="utf-8"))
    assert doc["kind"] == "PrometheusRule"
    return doc


def alert_rules() -> dict[str, dict]:
    return {r["alert"]: r for g in rule_spec()["spec"]["groups"] for r in g["rules"] if "alert" in r}


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


def docker_works() -> bool:
    if shutil.which("docker") is None:
        return False
    return subprocess.run(["docker", "info"], capture_output=True, check=False, timeout=60).returncode == 0


def promtool(directory: Path, *args: str) -> subprocess.CompletedProcess:
    """promtool from the pinned Prometheus image, with `directory` mounted read-only. promtool
    downloads nothing, so no CA bundle is needed behind a TLS-intercepting scanner."""
    return subprocess.run(
        ["docker", "run", "--rm", "--network", "none", "-v", f"{directory}:/work:ro", "-w", "/work",
         "--entrypoint", "/bin/promtool", prometheus_image(), *args],
        capture_output=True, text=True, encoding="utf-8", timeout=300, check=False)


def promtool_dir(rules_text: str | None = None) -> Path:
    """A directory with the rule file in the plain form promtool wants, and the unit tests."""
    directory = Path(tempfile.mkdtemp(prefix="ah-promtool-"))
    spec = rule_spec()["spec"]
    text = rules_text if rules_text is not None else yaml.safe_dump({"groups": spec["groups"]})
    (directory / "assume-hijacked.rules.yaml").write_text(text, encoding="utf-8")
    shutil.copy(RULE_TESTS, directory / RULE_TESTS.name)
    return directory


@cache
def kps_chart() -> Path:
    """The pinned kube-prometheus-stack chart file, downloaded once and checked against the digest
    in scripts/kind-monitoring.sh (the one from the chart repository's index)."""
    version = script_constant("KPS_VERSION")
    sha = script_constant("KPS_CHART_SHA256")
    repo = script_constant("KPS_REPO")
    cache_dir = Path(tempfile.gettempdir()) / "ah-kps-chart"
    chart = cache_dir / f"kube-prometheus-stack-{version}.tgz"
    if not chart.exists():
        cache_dir.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(
            [HELM, "pull", "kube-prometheus-stack", "--repo", repo, "--version", version,
             "--destination", str(cache_dir)],
            capture_output=True, text=True, encoding="utf-8", timeout=300, check=False)
        if result.returncode != 0:
            pytest.skip(f"cannot download kube-prometheus-stack {version}: {result.stderr.strip()[:200]}")
    assert hashlib.sha256(chart.read_bytes()).hexdigest() == sha, "chart file differs from the pinned digest"
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


def mailpit_docs() -> list[dict]:
    return [d for d in yaml.safe_load_all(MAILPIT.read_text(encoding="utf-8")) if d]


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


# --- the dashboard -----------------------------------------------------------------------------

def test_dashboard_is_valid_json_with_the_expected_panels():
    d = dashboard()
    assert d["title"] == "Walls"
    panels = d["panels"]
    ids = [p["id"] for p in panels]
    assert len(ids) == len(set(ids)), "panel ids must be unique"
    titles = " | ".join(p["title"] for p in panels).lower()
    for wanted in ["heartbeat", "refused", "by outcome", "denials by reason", "risk tiers", "hubble"]:
        assert wanted in titles, f"no panel about {wanted!r}: {titles}"
    # Calls allowed and denied, denials by reason, risk tiers, executor heartbeat, Hubble drops.
    exprs = " ".join(t["expr"] for p in panels for t in p["targets"])
    for metric in ["gateway_calls_total", "gateway_denials_total", "risk_tiers_total",
                   "executor_last_poll_timestamp_seconds", "hubble_drop_total"]:
        assert metric in exprs, metric


def test_dashboard_queries_use_known_metrics_and_the_stack_datasource():
    datasource_uids = {
        ds["uid"]
        for cm in stack_objects("ConfigMap") if cm["metadata"]["name"] == "kps-grafana-datasource"
        for ds in yaml.safe_load(cm["data"]["datasource.yaml"])["datasources"]
    }
    for p in dashboard()["panels"]:
        assert p["datasource"]["type"] == "prometheus", p["title"]
        assert p["datasource"]["uid"] in datasource_uids, (p["title"], datasource_uids)
        assert p["targets"], p["title"]
        for t in p["targets"]:
            assert t["datasource"]["uid"] in datasource_uids
            used = set(re.findall(r"(?:executor|risk|gateway|hubble)_[a-z_]+", t["expr"]))
            assert used <= KNOWN_METRICS, (p["title"], used - KNOWN_METRICS)


def test_dashboard_is_loaded_by_the_grafana_sidecar():
    script = MONITORING_SCRIPT.read_text(encoding="utf-8")
    assert "grafana_dashboard=1" in script
    assert "deploy/monitoring/dashboards/walls.json" in script
    # The label the rendered Grafana sidecar actually watches for (its LABEL env), not a default.
    [grafana] = [d for d in stack_objects("Deployment") if d["metadata"]["name"] == "kps-grafana"]
    sidecars = {c["name"]: {e["name"]: e.get("value") for e in c.get("env", [])}
                for c in grafana["spec"]["template"]["spec"]["containers"]}
    assert sidecars["grafana-sc-dashboard"]["LABEL"] == "grafana_dashboard"
    # ... with the value the script sets (grafana_dashboard=1).
    assert sidecars["grafana-sc-dashboard"]["LABEL_VALUE"] == "1"


def test_components_scraped_panel_counts_the_application_only():
    """The monitoring stack scrapes itself too; the panel counts only the application's targets."""
    [panel] = [p for p in dashboard()["panels"] if p["title"] == "Components scraped"]
    for target in panel["targets"]:
        assert 'namespace=~"ah-.+"' in target["expr"]
        assert 'namespace!="ah-monitoring"' in target["expr"]


# --- the rules ---------------------------------------------------------------------------------

def test_alert_rules_cover_heartbeat_risk_engine_and_denials():
    rules = alert_rules()
    assert set(rules) == ALERTS
    heartbeat = rules["ExecutorHeartbeatStale"]
    assert "time() - executor_last_poll_timestamp_seconds > 60" in heartbeat["expr"]
    assert "absent(executor_last_poll_timestamp_seconds)" in heartbeat["expr"]
    assert heartbeat["for"] == "1m"
    assert 'job="risk-engine"' in rules["RiskEngineDown"]["expr"]
    assert "gateway_denials_total" in rules["GatewayDenialsBurst"]["expr"]
    for name, rule in rules.items():
        assert rule["labels"]["severity"] in {"critical", "warning"}, name
        assert rule["annotations"]["summary"] and rule["annotations"]["description"], name
    spec = rule_spec()
    assert spec["metadata"]["namespace"] == NAMESPACE


@pytest.mark.skipif(not docker_works(), reason="docker is not available (promtool runs in a container)")
def test_promtool_checks_the_rules():
    result = promtool(promtool_dir(), "check", "rules", "assume-hijacked.rules.yaml")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "3 rules found" in result.stdout + result.stderr


@pytest.mark.skipif(not docker_works(), reason="docker is not available (promtool runs in a container)")
def test_promtool_unit_tests_pass():
    result = promtool(promtool_dir(), "test", "rules", RULE_TESTS.name)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "SUCCESS" in result.stdout + result.stderr


def _weaken_threshold(rule: dict) -> None:
    rule["expr"] = rule["expr"].replace("> 60", "> 600")


def _drop_absent(rule: dict) -> None:
    rule["expr"] = rule["expr"].split(" or absent")[0]


def _drop_wait(rule: dict) -> None:
    rule["for"] = "0m"


@pytest.mark.skipif(not docker_works(), reason="docker is not available (promtool runs in a container)")
@pytest.mark.parametrize("weaken", [_weaken_threshold, _drop_absent, _drop_wait],
                         ids=["threshold ten times too high", "no absent() for a stopped executor",
                              "no wait before firing"])
def test_promtool_unit_tests_catch_a_broken_heartbeat_rule(weaken):
    """Control: the same unit tests go red when the heartbeat rule is weakened."""
    groups = json.loads(json.dumps(rule_spec()["spec"]["groups"]))
    heartbeat = next(r for g in groups for r in g["rules"] if r.get("alert") == "ExecutorHeartbeatStale")
    before = json.dumps(heartbeat)
    weaken(heartbeat)
    assert json.dumps(heartbeat) != before
    result = promtool(promtool_dir(yaml.safe_dump({"groups": groups})), "test", "rules", RULE_TESTS.name)
    assert result.returncode != 0, result.stdout


# --- the stack, rendered ---------------------------------------------------------------------

@pytest.mark.skipif(HELM is None, reason="helm is not installed")
def test_chart_renders_and_every_image_is_pinned_by_digest():
    images = []
    for d in stack():
        if d["kind"] in ("Prometheus", "Alertmanager"):
            images.append(d["spec"]["image"])
        if d["kind"] == "Deployment":
            pod = d["spec"]["template"]["spec"]
            images += [c["image"] for c in pod["containers"] + pod.get("initContainers", [])]
            for c in pod["containers"]:
                images += [a.split("=", 1)[1] for a in c.get("args", [])
                           if a.startswith(("--prometheus-config-reloader=", "--thanos-default-base-image="))]
    assert len(images) >= 6, images
    for image in images:
        assert DIGEST.search(image), f"{image} has no digest"


@pytest.mark.skipif(HELM is None, reason="helm is not installed")
def test_stack_runs_only_what_the_walls_need_and_every_pod_has_limits():
    kinds = {d["kind"] for d in stack()}
    assert not kinds & {"DaemonSet", "Job", "PrometheusRule", "ValidatingWebhookConfiguration",
                        "MutatingWebhookConfiguration"}, kinds
    assert {d["metadata"]["name"] for d in stack_objects("Deployment")} == {"kps-operator", "kps-grafana"}
    for d in stack_objects("Deployment"):
        for c in d["spec"]["template"]["spec"]["containers"]:
            assert c["resources"]["limits"]["memory"], (d["metadata"]["name"], c["name"])
    prom = stack_objects("Prometheus")[0]["spec"]
    assert prom["resources"]["limits"]["memory"]
    assert stack_objects("Alertmanager")[0]["spec"]["resources"]["limits"]["memory"]


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


@pytest.mark.skipif(HELM is None, reason="helm is not installed")
def test_prometheus_scrapes_the_ops_port_of_every_component_that_serves_metrics():
    monitors = [m for m in stack_objects("PodMonitor") if m["metadata"]["name"] == "assume-hijacked"]
    assert len(monitors) == 1
    monitor = monitors[0]["spec"]
    assert monitors[0]["metadata"]["namespace"] == NAMESPACE
    assert monitor["jobLabel"] == "app.kubernetes.io/name"
    assert [e["port"] for e in monitor["podMetricsEndpoints"]] == ["ops"]
    assert monitor["podMetricsEndpoints"][0]["path"] == "/metrics"
    selector = monitor["selector"]["matchLabels"]
    # The pods the application chart renders: every one with a port named ops, in these namespaces.
    served = set()
    for d in rendered("kind"):
        if d["kind"] != "Deployment":
            continue
        template = d["spec"]["template"]
        if any(p["name"] == "ops" for c in template["spec"]["containers"] for p in c.get("ports", [])):
            labels = template["metadata"]["labels"]
            assert all(labels.get(k) == v for k, v in selector.items()), d["metadata"]["name"]
            served.add(d["metadata"]["namespace"])
    assert set(monitor["namespaceSelector"]["matchNames"]) == served
    # Prometheus takes monitors and rules of every namespace.
    prom = stack_objects("Prometheus")[0]["spec"]
    assert prom["podMonitorSelector"] == {} and prom["podMonitorNamespaceSelector"] == {}
    assert prom["ruleSelector"] == {}


@pytest.mark.skipif(HELM is None, reason="helm is not installed")
def test_hubble_drops_are_scraped_and_switched_on():
    monitors = [m for m in stack_objects("ServiceMonitor") if m["metadata"]["name"] == "hubble"]
    assert len(monitors) == 1
    spec = monitors[0]["spec"]
    assert spec["namespaceSelector"]["matchNames"] == ["kube-system"]
    assert spec["selector"]["matchLabels"] == {"k8s-app": "hubble"}
    assert spec["endpoints"][0]["port"] == "hubble-metrics"
    cilium = yaml.safe_load(CILIUM_VALUES.read_text(encoding="utf-8"))
    enabled = cilium["hubble"]["metrics"]["enabled"]
    assert len(enabled) == 1 and enabled[0].startswith("drop:")
    assert "source_namespace" in enabled[0] and "destination_namespace" in enabled[0]


@pytest.mark.skipif(HELM is None, reason="helm is not installed")
def test_alertmanager_sends_everything_to_the_mailpit_service():
    config = values()["alertmanager"]["config"]
    assert config["route"]["receiver"] == "mailpit"
    email = config["receivers"][0]["email_configs"][0]
    host, port = email["smarthost"].rsplit(":", 1)
    assert host == f"mailpit.{NAMESPACE}.svc.cluster.local"
    service = next(d for d in mailpit_docs() if d["kind"] == "Service")
    assert service["metadata"]["name"] == "mailpit"
    smtp = next(p for p in service["spec"]["ports"] if p["name"] == "smtp")
    assert smtp["port"] == int(port)
    deployment = next(d for d in mailpit_docs() if d["kind"] == "Deployment")
    container_ports = {p["name"]: p["containerPort"]
                       for p in deployment["spec"]["template"]["spec"]["containers"][0]["ports"]}
    assert container_ports["smtp"] == 1025
    # The operator keeps this config in a Secret and the Alertmanager object points at it.
    names = {d["metadata"]["name"] for d in stack_objects("Secret")}
    assert "alertmanager-kps-alertmanager" in names


@pytest.mark.skipif(HELM is None, reason="helm is not installed")
def test_grafana_has_no_default_password_and_no_telemetry():
    deployment = next(d for d in stack_objects("Deployment") if d["metadata"]["name"] == "kps-grafana")
    env = {e["name"]: e for c in deployment["spec"]["template"]["spec"]["containers"]
           for e in c.get("env", []) if c["name"] == "grafana"}
    assert env["GF_SECURITY_ADMIN_PASSWORD"]["valueFrom"]["secretKeyRef"]["name"] == "grafana-admin"
    assert "grafana-admin" in MONITORING_SCRIPT.read_text(encoding="utf-8")
    # The chart's Secret with the public default password is not rendered.
    assert not [d for d in stack_objects("Secret") if d["metadata"]["name"] == "kps-grafana"], \
        "a Grafana admin Secret with the chart default would be created"


# --- Mailpit -----------------------------------------------------------------------------------

def test_mailpit_is_pinned_unprivileged_and_read_only():
    docs = {d["kind"]: d for d in mailpit_docs()}
    assert set(docs) == {"ServiceAccount", "Deployment", "Service"}
    for d in docs.values():
        assert d["metadata"]["namespace"] == NAMESPACE
    pod = docs["Deployment"]["spec"]["template"]["spec"]
    (container,) = pod["containers"]
    assert DIGEST.search(container["image"]), container["image"]
    assert pod["automountServiceAccountToken"] is False
    assert container["securityContext"]["readOnlyRootFilesystem"] is True
    assert container["securityContext"]["runAsUser"] == 10001
    assert not pod_security_problems(pod, pod["containers"])
    assert container["resources"]["limits"]["memory"]
    # Read-only root: the only writable place is a small volume on /tmp.
    assert [m["mountPath"] for m in container["volumeMounts"]] == ["/tmp"]


# --- scripts -----------------------------------------------------------------------------------

@pytest.mark.parametrize("script", [MONITORING_SCRIPT, KIND_UP])
@pytest.mark.skipif(shutil.which("sh") is None, reason="sh is not installed")
def test_scripts_have_valid_shell_syntax(script):
    result = subprocess.run(["sh", "-n", str(script)], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr


def test_monitoring_script_pins_the_chart_and_installs_with_upgrade():
    script = MONITORING_SCRIPT.read_text(encoding="utf-8")
    assert re.fullmatch(r"[a-f0-9]{64}", script_constant("KPS_CHART_SHA256"))
    assert re.fullmatch(r"\d+\.\d+\.\d+", script_constant("KPS_VERSION"))
    assert "upgrade --install" in script
    assert "pod-security.kubernetes.io/enforce: restricted" in script
    assert "rules/assume-hijacked.yaml" in script and "mailpit.yaml" in script


def test_kind_up_counts_every_failed_wait_and_converges_cilium():
    """The wait for the API server ends even when the same error repeats, and Cilium is applied
    again when its values or version changed, not only when the release is missing."""
    script = KIND_UP.read_text(encoding="utf-8")
    wait = script.split("ensure_api_reachable() {", 1)[1].split("\n}\n", 1)[0]
    assert wait.index("tries=$((tries + 1))") < wait.index('case "$out"'), \
        "the counter must be bumped before the error is looked at"
    assert wait.count("tries=$((tries + 1))") == 1
    # Every failed try waits, whatever the error, so the 60 tries are the 120 s the message says.
    before_case, after_case = wait.split("esac", 1)
    assert "sleep" not in before_case.split('case "$out"', 1)[1]
    assert "sleep 2" in after_case.split("done", 1)[0]
    assert "upgrade --install cilium" in script
    assert 'stamp="$CILIUM_VERSION-$(sha256sum deploy/kind/cilium-values.yaml' in script
    assert 'if [ "$applied" != "$stamp" ]' in script


# --- live: the alert path, end to end ------------------------------------------------------------

LIVE = os.environ.get("AH_MONITORING_INSTALLED") == "1"


def proxy_get(service: str, path: str, namespace: str = NAMESPACE) -> dict | list:
    """GET through the API server's service proxy (no port-forward process to manage)."""
    result = run_kubectl(["get", "--raw", f"/api/v1/namespaces/{namespace}/services/{service}/proxy{path}"])
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def firing(name: str) -> list[dict]:
    alerts = proxy_get("kps-alertmanager:http-web", "/api/v2/alerts?active=true&silenced=false&inhibited=false")
    return [a for a in alerts if a["labels"].get("alertname") == name]


@pytest.mark.k8s
@pytest.mark.skipif(not LIVE, reason="set AH_MONITORING_INSTALLED=1 once the monitoring stack and the "
                                     "application chart are installed in the kind cluster")
def test_heartbeat_alert_fires_when_executor_stopped():
    deployment = ["--namespace", "ah-core", "deployment/executor"]
    replicas = run_kubectl(["get", *deployment, "-o", "jsonpath={.spec.replicas}"])
    assert replicas.returncode == 0, replicas.stderr
    original = int(replicas.stdout or "1")
    # Control: with the executor running, the alert is not firing.
    assert firing("ExecutorHeartbeatStale") == []
    try:
        assert run_kubectl(["scale", *deployment, "--replicas=0"]).returncode == 0
        # Stale after 60 s, one minute of `for`, a scrape and the group wait: about 3 minutes.
        deadline = time.monotonic() + 420
        while time.monotonic() < deadline and not firing("ExecutorHeartbeatStale"):
            time.sleep(10)
        alerts = firing("ExecutorHeartbeatStale")
        assert alerts, "ExecutorHeartbeatStale did not fire within 7 minutes"
        assert alerts[0]["labels"]["severity"] == "critical"
        # Alertmanager sent it on: the mail is in Mailpit.
        deadline = time.monotonic() + 180
        subjects: list[str] = []
        while time.monotonic() < deadline:
            messages = proxy_get("mailpit:http", "/api/v1/messages")["messages"]
            subjects = [m["Subject"] for m in messages]
            if any("ExecutorHeartbeatStale" in s for s in subjects):
                break
            time.sleep(10)
        assert any("ExecutorHeartbeatStale" in s for s in subjects), subjects
    finally:
        run_kubectl(["scale", *deployment, f"--replicas={original}"])
