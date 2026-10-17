"""The network and admission walls on the live kind cluster `ah` (`sh scripts/kind-up.sh`).

The network walls are proved at runtime by the probe matrix (attacks/probes.py, bottom of this
file): probe pods with each component's labels try every forbidden edge and the allowed ones;
the observed matrix is written to reports/k8s-probe-matrix.json.

Admission is checked with server-side dry runs: the API server runs every admission step (Pod
Security, the ValidatingAdmissionPolicies, RBAC for `--as`) and stores nothing, and no image is
pulled. If the chart is not installed (no Helm release owns the namespaces), the session
fixture applies the chart's namespaces, ServiceAccounts, dispatcher RBAC and policies from
`helm template`, and deletes them again at the end.
"""

import json
import os
import shlex
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
import yaml

from attacks import probes
from tests.k8s.conftest import kubectl_json, run_kubectl
from tests.k8s.test_chart import (HELM, NAMESPACES, ROOT, SANDBOX_RUNTIME, agent_job, helm)

pytestmark = [pytest.mark.k8s, pytest.mark.skipif(HELM is None, reason="helm is not installed")]

WALL_KINDS = {"Namespace", "ServiceAccount", "Role", "RoleBinding", "NetworkPolicy", "CiliumNetworkPolicy",
              "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding"}
DISPATCHER = "system:serviceaccount:ah-intake:dispatcher"
PINNED = "localhost:5001/assume-hijacked@sha256:" + "0" * 64


def kubectl(*args: str, stdin: str | None = None) -> subprocess.CompletedProcess:
    return run_kubectl(list(args), stdin=stdin)


def admit(obj: dict, as_user: str | None = None) -> tuple[bool, str]:
    """Server-side dry run of a create. (admitted, error text)."""
    args = ["create", "--dry-run=server", "-f", "-"]
    if as_user:
        args.append(f"--as={as_user}")
    result = kubectl(*args, stdin=json.dumps(obj))
    return result.returncode == 0, result.stderr


def pod(namespace: str, service_account: str, **spec) -> dict:
    """A pod that passes Pod Security "restricted" and every policy, unless spec overrides it."""
    container = {
        "name": "main", "image": PINNED, "command": ["python", "-c", "pass"],
        "securityContext": {"runAsNonRoot": True, "runAsUser": 10001, "allowPrivilegeEscalation": False,
                            "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]},
                            "seccompProfile": {"type": "RuntimeDefault"}},
    }
    container.update(spec.pop("container", {}))
    body = {"serviceAccountName": service_account, "automountServiceAccountToken": False,
            "securityContext": {"runAsNonRoot": True, "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [container]}
    if namespace in ("ah-agent", "ah-tools"):
        body["runtimeClassName"] = SANDBOX_RUNTIME
    body.update(spec)
    body = {k: v for k, v in body.items() if v is not None}
    metadata = {"name": "wall-probe", "namespace": namespace}
    if "ownerReferences" in body:
        metadata["ownerReferences"] = body.pop("ownerReferences")
    return {"apiVersion": "v1", "kind": "Pod", "metadata": metadata, "spec": body}


def ticket_job(ticket: str = "42") -> dict:
    """The agent Job exactly as the dispatcher builds it: the chart template plus name and ticket."""
    job = agent_job("kind")
    job["metadata"]["name"] = f"agent-{ticket}"
    job["metadata"]["labels"]["ah/ticket"] = ticket
    job["spec"]["template"]["metadata"]["labels"]["ah/ticket"] = ticket
    return job


def chart_installed() -> bool:
    result = kubectl("get", "namespace", "ah-agent", "-o", "json")
    if result.returncode != 0:
        return False
    return "meta.helm.sh/release-name" in json.loads(result.stdout)["metadata"].get("annotations", {})


def wait_until(check, seconds: int = 20) -> bool:
    deadline = time.monotonic() + seconds
    while not check():
        if time.monotonic() > deadline:
            return False
        time.sleep(1)
    return True


@pytest.fixture(scope="session", autouse=True)
def walls(tmp_path_factory):
    kubectl_json("get", "nodes")  # fails with a clear message when the cluster is down
    applied = None
    if not chart_installed():
        result = helm("template", "kind")
        assert result.returncode == 0, result.stderr
        docs = [d for d in yaml.safe_load_all(result.stdout) if d and d["kind"] in WALL_KINDS]
        applied = tmp_path_factory.mktemp("walls") / "walls.yaml"
        applied.write_text(yaml.safe_dump_all(docs), encoding="utf-8")
        result = kubectl("apply", "--server-side", "-f", str(applied))
        if result.returncode != 0:
            kubectl("delete", "--wait=true", "--ignore-not-found", "-f", str(applied))
            pytest.fail(f"applying the walls failed: {result.stderr}")
    try:
        # A new policy takes a moment to be enforced: wait until each one refuses its probe. No
        # failure here when one never does: the tests of that policy then fail by name.
        probes = {
            "ah-images-pinned": pod("ah-fakes", "fake-sms", container={"image": "busybox:1.37"}),
            "ah-sandbox-runtime": pod("ah-tools", "tool-read-ticket", runtimeClassName=None),
            "ah-agent-job-template": JOB_CHANGES["run as the llm-gateway ServiceAccount"](ticket_job()),
        }
        for name, probe in probes.items():
            wait_until(lambda p=probe, n=name: n in admit(p)[1])
        yield
    finally:
        if applied is not None:
            kubectl("delete", "--wait=true", "--ignore-not-found", "-f", str(applied))


# --- network walls ------------------------------------------------------------------------------

def test_every_namespace_has_default_deny(get):
    for namespace in NAMESPACES:
        policies = {p["metadata"]["name"]: p["spec"]
                    for p in get("--namespace", namespace, "get", "networkpolicies")["items"]}
        assert policies.get("default-deny") == {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}, namespace
    # Control: the allowed edges are there next to it (both halves of agent -> tool gateway).
    assert get("--namespace", "ah-agent", "get", "networkpolicy", "edge-05-agent-to-tool-gateway-out")
    assert get("--namespace", "ah-gateway", "get", "networkpolicy", "edge-05-agent-to-tool-gateway-in")


def test_cilium_accepted_every_policy(get):
    """Cilium validated each CiliumNetworkPolicy (DNS rules, IMDS deny, API server edges)."""
    expected = {(o["metadata"]["namespace"], o["metadata"]["name"])
                for o in yaml.safe_load_all(helm("template", "kind").stdout)
                if o and o["kind"] == "CiliumNetworkPolicy"}

    def statuses() -> dict:
        seen = {}
        for p in get("get", "ciliumnetworkpolicies", "--all-namespaces")["items"]:
            key = (p["metadata"]["namespace"], p["metadata"]["name"])
            if key in expected:
                seen[key] = {c["type"]: c["status"] for c in p.get("status", {}).get("conditions", [])}
        return seen

    # Cilium writes the status a few seconds after the policies are applied.
    wait_until(lambda: (s := statuses()).keys() == expected and all("Valid" in c for c in s.values()), 60)
    seen = statuses()
    assert set(seen) == expected
    for key, conditions in seen.items():
        assert conditions.get("Valid") == "True", (key, conditions)


# --- admission walls ----------------------------------------------------------------------------

@pytest.mark.parametrize("image", [
    "localhost:5001/assume-hijacked:latest",                         # tag only
    "docker.io/library/busybox@sha256:" + "a" * 64,                  # pinned, other registry
    "localhost:5001/assume-hijacked@sha256:" + "a" * 63,             # digest cut short
    "postgres:17-alpine@sha256:" + "a" * 64,                         # upstream name, other digest
])
def test_admission_rejects_unpinned_image(image):
    admitted, error = admit(pod("ah-fakes", "fake-sms", container={"image": image}))
    assert not admitted
    assert "ah-images-pinned" in error
    # Init containers are checked too.
    init = {"name": "init", "image": image, "securityContext": pod("ah-fakes", "x")["spec"]["containers"][0]["securityContext"]}
    admitted, error = admit(pod("ah-fakes", "fake-sms", initContainers=[init]))
    assert not admitted and "ah-images-pinned" in error


def test_admission_admits_pinned_images():
    """Control: the registry by digest, and on kind the exact upstream Postgres image."""
    assert admit(pod("ah-fakes", "fake-sms")) == (True, "")
    postgres = next(o for o in yaml.safe_load_all(helm("template", "kind").stdout)
                    if o and o["kind"] == "StatefulSet")["spec"]["template"]["spec"]["containers"][0]["image"]
    assert admit(pod("ah-data", "postgres", container={"image": postgres})) == (True, "")


@pytest.mark.parametrize("namespace,service_account", [
    ("ah-tools", "tool-read-ticket"),
    ("ah-agent", "agent"),
])
def test_admission_rejects_tool_pod_without_runtimeclass(namespace, service_account):
    admitted, error = admit(pod(namespace, service_account, runtimeClassName=None))
    assert not admitted
    assert "ah-sandbox-runtime" in error
    # Control: the same pod with the sandbox class is admitted.
    assert admit(pod(namespace, service_account)) == (True, "")


def test_only_the_llm_gateway_deployment_runs_outside_the_sandbox_in_agent_namespace():
    # The LLM gateway's own pods (from its Deployment) are not sandboxed; only pods created by a Job are.
    assert admit(pod("ah-agent", "llm-gateway", runtimeClassName=None)) == (True, "")
    # A pod created by a Job is never exempt, whatever ServiceAccount it names.
    owner = [{"apiVersion": "batch/v1", "kind": "Job", "name": "agent-42",
              "uid": "00000000-0000-0000-0000-000000000042", "controller": True}]
    admitted, error = admit(pod("ah-agent", "llm-gateway", runtimeClassName=None, ownerReferences=owner))
    assert not admitted and "ah-sandbox-runtime" in error


PRIVILEGED = {
    # The API server refuses privileged with allowPrivilegeEscalation false, so both are set.
    "privileged": {"container": {"securityContext": {"privileged": True, "allowPrivilegeEscalation": True}}},
    "escalation": {"container": {"securityContext": {"allowPrivilegeEscalation": True}}},
    "added capability": {"container": {"securityContext": {"capabilities": {"add": ["NET_ADMIN"]}}}},
    "hostNetwork": {"hostNetwork": True},
    "hostPID": {"hostPID": True},
    "hostPath": {"volumes": [{"name": "host", "hostPath": {"path": "/"}}]},
    "hostPort": {"container": {"ports": [{"containerPort": 80, "hostPort": 80}]}},
}


@pytest.mark.parametrize("case", list(PRIVILEGED))
def test_admission_rejects_privileged_pod(case):
    spec = json.loads(json.dumps(PRIVILEGED[case]))
    if "container" in spec:
        base = pod("ah-fakes", "fake-sms")["spec"]["containers"][0]
        sc = {**base["securityContext"], **spec["container"].pop("securityContext", {})}
        spec["container"] = {**spec["container"], "securityContext": sc}
    probe = pod("ah-fakes", "fake-sms", **spec)
    # With Pod Security "restricted" on the namespace (the first wall to answer).
    admitted, error = admit(probe)
    assert not admitted, case
    # With the namespace's Pod Security labels switched to privileged, the policy still refuses.
    set_enforce = lambda level: kubectl("label", "namespace", "ah-fakes", "--overwrite",  # noqa: E731
                                        f"pod-security.kubernetes.io/enforce={level}")
    assert set_enforce("privileged").returncode == 0
    try:
        admitted, error = admit(probe)
        assert not admitted, case
        assert "ah-no-host-access" in error, error
        # Control: an ordinary restricted pod is still admitted.
        assert admit(pod("ah-fakes", "fake-sms")) == (True, "")
    finally:
        assert set_enforce("restricted").returncode == 0


# --- the agent Job template ---------------------------------------------------------------------

def edit(path: str, value=None, delete: bool = False):
    """A change to the Job: path is dotted (no dots inside keys), numbers index lists."""
    def apply(job: dict) -> dict:
        *parents, last = [int(p) if p.isdigit() else p for p in path.split(".")]
        node = job
        for p in parents:
            node = node[p]
        if delete:
            del node[last]
        else:
            node[last] = value
        return job
    return apply


POD = "spec.template.spec"
AGENT = f"{POD}.containers.0"
SECRET_ENV = {"name": "KEY", "valueFrom": {"secretKeyRef": {"name": "llm-gateway-secrets", "key": "anthropic-api-key"}}}
JOB_CHANGES = {
    "run as the llm-gateway ServiceAccount": edit(f"{POD}.serviceAccountName", "llm-gateway"),
    "automount the API token": edit(f"{POD}.automountServiceAccountToken", True),
    "mount the llm-gateway Secret": edit(f"{POD}.volumes", [
        {"name": "ah-tokens", "secret": {"secretName": "llm-gateway-secrets"}}]),
    "add a Secret source to the projected volume": lambda j: (
        j["spec"]["template"]["spec"]["volumes"][0]["projected"]["sources"].append(
            {"secret": {"name": "llm-gateway-secrets"}}) or j),
    "env from a secretKeyRef": lambda j: (
        j["spec"]["template"]["spec"]["containers"][0]["env"].append(SECRET_ENV) or j),
    "envFrom a Secret": edit(f"{AGENT}.envFrom", [{"secretRef": {"name": "llm-gateway-secrets"}}]),
    "a token for another audience": edit(f"{POD}.volumes.0.projected.sources.0.serviceAccountToken.audience",
                                         "risk-engine"),
    "an API server token (no audience)": edit(f"{POD}.volumes.0.projected.sources.0.serviceAccountToken.audience",
                                              delete=True),
    "a longer token": edit(f"{POD}.volumes.0.projected.sources.1.serviceAccountToken.expirationSeconds", 86400),
    "no ticket label": edit("metadata.labels.ah/ticket", ""),
    "pod ticket label differs": edit("spec.template.metadata.labels.ah/ticket", "43"),
    "posing as llm-gateway": lambda j: (
        j["spec"]["template"]["metadata"]["labels"].update({"app.kubernetes.io/name": "llm-gateway"}) or j),
    "another image": edit(f"{AGENT}.image", "localhost:5001/assume-hijacked@sha256:" + "f" * 64),
    "another command": edit(f"{AGENT}.command", ["sh", "-c", "env"]),
    "extra args": edit(f"{AGENT}.args", ["--debug"]),
    "a postStart hook": edit(f"{AGENT}.lifecycle", {"postStart": {"exec": {"command": ["sh"]}}}),
    "another gateway URL": edit(f"{AGENT}.env.2.value", "http://attacker.example/mcp"),
    "outside the sandbox": edit(f"{POD}.runtimeClassName", delete=True),
    "pinned to the system node": edit(f"{POD}.nodeName", "ah-control-plane"),
    "writable root filesystem": edit(f"{AGENT}.securityContext.readOnlyRootFilesystem", False),
    "retries": edit("spec.backoffLimit", 3),
    "no deadline": edit("spec.activeDeadlineSeconds", delete=True),
    # The remaining pod-spec escapes, each tried once live.
    "an init container": lambda j: (j["spec"]["template"]["spec"].update(initContainers=[
        {**j["spec"]["template"]["spec"]["containers"][0], "name": "init", "command": ["sh", "-c", "env"]}]) or j),
    "host aliases (point a service name elsewhere)": edit(f"{POD}.hostAliases", [
        {"ip": "10.0.0.66", "hostnames": ["tool-gateway.ah-gateway.svc.cluster.local"]}]),
    "a custom DNS config": edit(f"{POD}.dnsConfig", {"nameservers": ["1.1.1.1"]}),
    "DNS policy None": lambda j: (j["spec"]["template"]["spec"].update(
        dnsPolicy="None", dnsConfig={"nameservers": ["1.1.1.1"]}) or j),
}


def test_dispatcher_can_create_the_agent_job():
    """Control: the template from the chart, as the dispatcher's ServiceAccount, is admitted."""
    assert admit(ticket_job(), as_user=DISPATCHER) == (True, "")


@pytest.mark.parametrize("change", list(JOB_CHANGES))
def test_admission_rejects_agent_job_off_template(change):
    job = JOB_CHANGES[change](ticket_job())
    admitted, error = admit(job, as_user=DISPATCHER)
    assert not admitted, change
    assert "ah-agent-job-template" in error, error


# --- runtime proof of the network walls: the probe matrix (attacks/probes.py) -------------------
#
# One probe pod per identity of the matrix, from the attack-suite image (attacks/Dockerfile, in
# the local registry): in its component's namespace, with its app.kubernetes.io/name label, so
# the policies select it exactly as they select the component. Each listens on its component's
# ports (a stand-in for a component that is not deployed) and runs the probes whose source it is.
# A probe aims at the target pod's IP, so it needs no Service and no app.
#
# Mutation proofs: AH_WALLS_MUTATION="<kubectl args>" runs one kubectl command once the probe pods
# are up (e.g. "delete networkpolicy default-deny --namespace ah-fakes"); the named edges must go
# red. The walls fixture deletes every wall at the end, so the next run starts from the chart.

PROBE_LABEL = "ah/probe"
EXTRA_NAMESPACES = {"ah-monitoring", probes.OUTSIDE_NAMESPACE}
MATRIX = probes.matrix()
REPORT = ROOT / "reports" / "k8s-probe-matrix.json"


def attack_image() -> str:
    image = os.environ.get("AH_ATTACK_IMAGE")
    if image:
        return image
    sh = shutil.which("sh")
    if sh is None:
        pytest.fail("set AH_ATTACK_IMAGE, or put sh on PATH to run scripts/kind-attack-image.sh")
    result = subprocess.run([sh, "scripts/kind-attack-image.sh"], cwd=ROOT, capture_output=True, text=True,
                            timeout=600, check=False)
    if result.returncode != 0:
        pytest.fail(f"building the attack-suite image failed: {result.stderr}")
    return result.stdout.strip().splitlines()[-1]


def identities() -> list[str]:
    """Every probe source and every component a probe aims at."""
    targets = [p.target for p in MATRIX if p.kind == "tcp" and p.target not in probes.SPECIAL_TARGETS]
    return list(dict.fromkeys([*probes.sources(MATRIX), *targets]))


def probe_pod(name: str, image: str) -> dict:
    namespace, label, ports = probes.placement(name)
    doc = pod(namespace, "default", container={
        "name": "probe", "image": image, "args": ["serve", ",".join(map(str, ports))],
        "resources": {"requests": {"cpu": "5m", "memory": "24Mi"}, "limits": {"cpu": "200m", "memory": "64Mi"}},
        # Never ready: a probe pod carries a component's label, and if the chart is installed a
        # Service would otherwise send real clients to it. Probes aim at pod IPs, which do not
        # depend on readiness.
        "readinessProbe": {"exec": {"command": ["false"]}, "periodSeconds": 60},
    })
    del doc["spec"]["containers"][0]["command"]  # the image's entrypoint: python -m attacks.run
    if namespace not in ("ah-agent", "ah-tools"):
        doc["spec"].pop("runtimeClassName", None)
    doc["metadata"] = {"name": f"probe-{name}", "namespace": namespace,
                       "labels": {"app.kubernetes.io/name": label, PROBE_LABEL: name}}
    return doc


def namespace_doc(name: str) -> dict:
    labels = {f"pod-security.kubernetes.io/{m}": "restricted" for m in ("enforce", "warn", "audit")}
    return {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": name, "labels": labels}}


def exec_probe(namespace: str, pod_name: str, plan: list, addresses: dict) -> list[dict]:
    """Run probes in a probe pod. kubectl exec through the loopback API can drop now and then
    (antivirus on this PC), so a failed exec is retried."""
    request = json.dumps({"probes": [p.to_json() for p in plan], "addresses": addresses})
    for _ in range(3):
        result = kubectl("--namespace", namespace, "exec", "-i", pod_name, "--",
                         "python", "-m", "attacks.run", "probe", stdin=request)
        try:
            return json.loads(result.stdout)["results"]
        except ValueError:
            time.sleep(2)
    raise AssertionError(f"probe exec in {namespace}/{pod_name} failed: {result.stderr}")


def run_matrix(plan: list, pods: dict, addresses: dict) -> list[dict]:
    """Every source's probes at once, one exec per source pod."""
    by_source: dict[str, list] = {}
    for p in plan:
        by_source.setdefault(p.source, []).append(p)
    with ThreadPoolExecutor(max_workers=len(by_source)) as pool:
        futures = [pool.submit(exec_probe, pods[s]["namespace"], pods[s]["name"], ps, addresses)
                   for s, ps in by_source.items()]
        return [r for f in futures for r in f.result()]


@pytest.fixture(scope="session")
def probe_pods(walls):
    image = attack_image()
    created_ns = [n for n in sorted(EXTRA_NAMESPACES) if kubectl("get", "namespace", n).returncode != 0]
    docs = [namespace_doc(n) for n in created_ns] + [probe_pod(n, image) for n in identities()]
    try:
        result = kubectl("apply", "-f", "-", stdin=json.dumps({"apiVersion": "v1", "kind": "List", "items": docs}))
        assert result.returncode == 0, result.stderr
        result = kubectl("wait", "pods", "--all-namespaces", "-l", PROBE_LABEL,
                         "--for=jsonpath={.status.phase}=Running", "--timeout=240s")
        assert result.returncode == 0, result.stderr
        listed = kubectl_json("get", "pods", "--all-namespaces", "-l", PROBE_LABEL)["items"]
        pods = {p["metadata"]["labels"][PROBE_LABEL]: {
            "name": p["metadata"]["name"], "namespace": p["metadata"]["namespace"],
            "ip": p["status"]["podIP"], "node": p["spec"]["nodeName"]} for p in listed}
        mutation = os.environ.get("AH_WALLS_MUTATION")
        if mutation:
            result = kubectl(*shlex.split(mutation))
            assert result.returncode == 0, f"mutation {mutation!r} failed: {result.stderr}"
            time.sleep(5)
        yield pods
    finally:
        kubectl("delete", "pods", "--all-namespaces", "-l", PROBE_LABEL, "--wait=true", "--timeout=120s")
        for n in created_ns:
            kubectl("delete", "namespace", n, "--wait=false")


def api_service_ip() -> str:
    return kubectl_json("--namespace", "default", "get", "service", "kubernetes")["spec"]["clusterIP"]


@pytest.fixture(scope="session")
def addresses(probe_pods) -> dict[str, str]:
    found = {name: pod["ip"] for name, pod in probe_pods.items()}
    found[probes.KUBE_API] = api_service_ip()
    return found


@pytest.fixture(scope="session")
def probe_results(probe_pods, addresses) -> dict[str, dict]:
    results = run_matrix(MATRIX, probe_pods, addresses)
    # A new pod's identity reaches every node's policy maps within a second or two: an allowed
    # edge that timed out right after start-up is tried again. A denied edge is never retried:
    # one connection through is a hole.
    for _ in range(2):
        late = {r["edge"] for r in results if r["expected"] == probes.ALLOW and r["observed"] == probes.DENY}
        if not late:
            break
        time.sleep(3)
        again = {r["edge"]: r for r in run_matrix([p for p in MATRIX if p.edge in late], probe_pods, addresses)}
        results = [again.get(r["edge"], r) for r in results]
    REPORT.parent.mkdir(exist_ok=True)
    REPORT.write_text(json.dumps(results, indent=1), encoding="utf-8")
    return {r["edge"]: r for r in results}


@pytest.mark.parametrize("edge", [p.edge for p in MATRIX])
def test_probe_edge(probe_results, edge):
    r = probe_results[edge]
    assert r["observed"] == r["expected"], (
        f"{edge}: expected {r['expected']}, observed {r['observed']} ({r['detail']}); wall: {r['why']}")
    if r["expected"] == probes.DENY:
        # The wall's own signature: Cilium drops the packets (timeout) or its DNS proxy answers
        # REFUSED. A failed lookup or an unreachable network is an error, never a pass.
        assert r["detail"].startswith(probes.DENY_DETAIL[r["kind"]]), f"{edge}: {r['detail']}"


def test_probe_pods_are_never_ready(probe_pods):
    """So a Service that selects a component's label never sends a real client to a probe pod."""
    for p in kubectl_json("get", "pods", "--all-namespaces", "-l", PROBE_LABEL)["items"]:
        ready = [c["status"] for c in p["status"].get("conditions", []) if c["type"] == "Ready"]
        assert ready == ["False"], p["metadata"]["name"]


@pytest.mark.skip(reason="needs the app deployed: the dispatcher runs the seeded attack tickets "
                         "(attacks.tickets.seed_sql) as real agent Jobs, and the suite judges what "
                         "each agent got back and the reply that was stored (attacks.tickets.judge)")
def test_attack_tickets_replay_through_the_dispatcher():
    """Attack tickets 1-11 through dispatcher -> agent Job -> tool gateway -> tools. Steps once
    the app runs on kind: insert seed_sql() into the database, wait until the dispatcher has run
    an agent Job for each ticket, read each ticket's tool calls and stored reply, build an Outcome
    per ticket and assert judge() finds nothing."""


def hubble(probe_pods: dict, source: str, *filters: str) -> list[dict]:
    """Flows Hubble recorded from a probe pod, read on the node it runs on (egress policy is
    enforced there)."""
    pod_ = probe_pods[source]
    agents = kubectl_json("--namespace", "kube-system", "get", "pods", "-l", "k8s-app=cilium",
                          "--field-selector", f"spec.nodeName={pod_['node']}")["items"]
    result = kubectl("--namespace", "kube-system", "exec", agents[0]["metadata"]["name"], "-c", "cilium-agent", "--",
                     "hubble", "observe", "--last", "4000", "--from-pod", f"{pod_['namespace']}/{pod_['name']}",
                     *filters, "-o", "json")
    assert result.returncode == 0, result.stderr
    return [json.loads(line)["flow"] for line in result.stdout.splitlines() if line.strip()]


def tcp_verdicts(flows: list[dict], ip: str, port: int) -> set[tuple[str, str]]:
    return {(f["verdict"], f.get("drop_reason_desc", "")) for f in flows
            if f.get("IP", {}).get("destination") == ip
            and f.get("l4", {}).get("TCP", {}).get("destination_port") == port}


def test_hubble_shows_policy_drops_for_denied_edges_and_forwards_the_allowed(probe_results, probe_pods, addresses):
    """Evidence for the Walls board: the denied connections are dropped by policy (not lost on
    the way), the allowed one is forwarded."""
    flows = hubble(probe_pods, "agent", "--protocol", "tcp")
    for target, port in (("postgres", 5432), ("tool-read-ticket", 8000), ("risk-engine", 8082)):
        assert tcp_verdicts(flows, addresses[target], port) == {("DROPPED", "POLICY_DENIED")}, target
    assert ("FORWARDED", "") in tcp_verdicts(flows, addresses["tool-gateway"], 8080)


def test_dns_exfiltration_is_answered_by_the_proxy_and_never_forwarded(probe_results, probe_pods):
    """The exfiltration name dies in Cilium's DNS proxy: Hubble shows the query refused there and
    never forwarded to CoreDNS, so no server outside the cluster ever sees it. Control: a cluster
    name from the same pod is forwarded."""
    exfil = probe_results[f"agent dns {probes.EXFIL_NAME}"]["detail"].rsplit("(", 1)[1].rstrip(")")
    assert exfil.endswith(".exfil.example.") and "{" not in exfil
    flows = hubble(probe_pods, "agent", "--protocol", "dns")
    by_query: dict[str, set] = {}
    for f in flows:
        query = f.get("l7", {}).get("dns", {}).get("query")
        if query:
            by_query.setdefault(query, set()).add(f["verdict"])
    assert by_query.get(exfil) and "FORWARDED" not in by_query[exfil], by_query.get(exfil)
    assert "FORWARDED" in by_query.get("kubernetes.default.svc.cluster.local.", set())


def test_probe_pod_search_list_is_the_cluster_suffixes_only(probe_pods):
    """The resolver's search list decides which names a lookup sends (names outside the cluster
    are allowed together with their search forms). On kind it holds the cluster suffixes only;
    on AKS a node search domain may be added, which the DNS rules would then refuse: check there."""
    agent = probe_pods["agent"]
    result = kubectl("--namespace", agent["namespace"], "exec", agent["name"], "--", "cat", "/etc/resolv.conf")
    assert result.returncode == 0, result.stderr
    lines = [line.split() for line in result.stdout.splitlines() if line.strip()]
    search = next(line[1:] for line in lines if line[0] == "search")
    assert search == ["ah-agent.svc.cluster.local", "svc.cluster.local", "cluster.local"]
    assert ["options", "ndots:5"] in lines
    (REPORT.parent / "k8s-probe-resolv-conf.txt").write_text(result.stdout, encoding="utf-8")


ALLOW_ALL = {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
             "metadata": {"name": "probe-allow-all-egress", "namespace": "ah-fakes"},
             "spec": {"podSelector": {"matchLabels": {PROBE_LABEL: "fake-sms"}}, "policyTypes": ["Egress"],
                      "egress": [{}]}}


def test_metadata_endpoint_denied_even_with_an_allow_all_policy(probe_pods, addresses):
    """IMDS (managed identity tokens on Azure) stays shut when someone adds an allow-all egress
    policy next to the walls: the Cilium deny wins over every allow. Control: the same allow-all
    opens the internet, so it is in force."""
    assert kubectl("apply", "-f", "-", stdin=json.dumps(ALLOW_ALL)).returncode == 0
    try:
        plan = [probes.tcp("fake-sms", probes.INTERNET, probes.ALLOW, "control: allow-all is in force"),
                probes.tcp("fake-sms", probes.IMDS, probes.DENY, "deny-instance-metadata beats allow-all")]
        results = {}
        for _ in range(5):  # the new policy takes a moment
            results = {r["edge"]: r for r in run_matrix(plan, probe_pods, addresses)}
            if results["fake-sms -> internet:443"]["observed"] == probes.ALLOW:
                break
            time.sleep(2)
        assert results["fake-sms -> internet:443"]["observed"] == probes.ALLOW, results
        assert results["fake-sms -> imds:80"]["observed"] == probes.DENY, results
        # On kind nothing answers at 169.254.169.254, so a timeout alone proves little: Hubble
        # must show the policy dropped it, and POLICY_DENY (an explicit deny rule) rather than
        # POLICY_DENIED (no allow): the egressDeny did it, not a missing allow.
        verdicts = tcp_verdicts(hubble(probe_pods, "fake-sms", "--to-ip", "169.254.169.254"), "169.254.169.254", 80)
        assert verdicts == {("DROPPED", "POLICY_DENY")}, verdicts
    finally:
        kubectl("delete", "-f", "-", "--ignore-not-found", stdin=json.dumps(ALLOW_ALL))


ANTHROPIC = "api.anthropic.com"


def test_only_the_llm_gateway_reaches_its_llm_api(probe_pods, addresses, probe_results):
    """With llm.backend=anthropic: the LLM gateway resolves and reaches api.anthropic.com on 443,
    nothing else outside, no other port; every other pod is refused the name."""
    result = helm("template", "kind", "--set", "llm.backend=anthropic", "--set", "secrets.anthropicApiKey=test-only")
    assert result.returncode == 0, result.stderr
    [policy] = [o for o in yaml.safe_load_all(result.stdout)
                if o and o["kind"] == "CiliumNetworkPolicy"
                and o["metadata"]["name"] == "edge-19-20-llm-gateway-to-external-names"]
    if kubectl("--namespace", "ah-agent", "get", "ciliumnetworkpolicy", policy["metadata"]["name"]).returncode == 0:
        pytest.skip("the installed chart already has an LLM backend with external names")
    assert kubectl("apply", "-f", "-", stdin=json.dumps(policy)).returncode == 0
    try:
        lg, a = "llm-gateway", "agent"
        plan = [
            probes.resolve(lg, ANTHROPIC, probes.ALLOW, "edge-19: its API name, through the search walk"),
            probes.tcp(lg, ANTHROPIC, probes.ALLOW, "edge-20: toFQDNs api.anthropic.com:443", 443),
            probes.tcp(lg, ANTHROPIC, probes.DENY, "edge-20: 443 only", 80),
            probes.dns(lg, "api.openai.com.", probes.DENY, "edge-19: no other name"),
            probes.tcp(lg, probes.INTERNET, probes.DENY, "edge-20: no other address"),
            probes.dns(a, f"{ANTHROPIC}.", probes.DENY, "edge-19: the agent never gets the name"),
            probes.resolve(a, ANTHROPIC, probes.DENY, "edge-19: the agent never gets the name"),
        ]
        results = {}
        for _ in range(10):  # Cilium validates and applies the new policy within a few seconds
            results = {r["edge"]: r for r in run_matrix(plan, probe_pods, addresses)}
            if results[f"{lg} resolve {ANTHROPIC}"]["observed"] == probes.ALLOW:
                break
            time.sleep(2)
        bad = {e: (r["expected"], r["observed"], r["detail"]) for e, r in results.items()
               if r["observed"] != r["expected"]}
        assert not bad
    finally:
        kubectl("delete", "-f", "-", "--ignore-not-found", stdin=json.dumps(policy))


# --- admission on running pods: ephemeral containers and pod updates ----------------------------

def ephemeral(probe_pods: dict, image: str, **security) -> tuple[bool, str]:
    """Server-side dry run of adding an ephemeral (debug) container to the running fake-sms probe."""
    target = probe_pods["fake-sms"]
    live = kubectl_json("--namespace", target["namespace"], "get", "pod", target["name"])
    sc = {**pod("ah-fakes", "x")["spec"]["containers"][0]["securityContext"], **security}
    live["spec"]["ephemeralContainers"] = [{"name": "debug", "image": image, "command": ["sh"],
                                            "securityContext": sc}]
    url = f"/api/v1/namespaces/{target['namespace']}/pods/{target['name']}/ephemeralcontainers?dryRun=All"
    result = kubectl("replace", "--raw", url, "-f", "-", stdin=json.dumps(live))
    return result.returncode == 0, result.stderr + result.stdout


def test_admission_rejects_ephemeral_container_off_the_rules(probe_pods):
    admitted, error = ephemeral(probe_pods, "busybox:1.37")
    assert not admitted and "ah-images-pinned" in error, error
    admitted, error = ephemeral(probe_pods, PINNED, privileged=True, allowPrivilegeEscalation=True)
    assert not admitted, error
    # Control: a pinned, restricted debug container is admitted (RBAC decides who may add one).
    admitted, error = ephemeral(probe_pods, PINNED)
    assert admitted, error


def test_admission_rejects_image_swap_on_a_running_pod(probe_pods):
    """kubectl set image on a running pod is a pod UPDATE: the image policy checks it too."""
    target = probe_pods["fake-sms"]

    def set_image(image: str) -> subprocess.CompletedProcess:
        return kubectl("--namespace", target["namespace"], "set", "image", f"pod/{target['name']}",
                       f"probe={image}", "--dry-run=server")

    result = set_image("busybox:1.37")
    assert result.returncode != 0 and "ah-images-pinned" in result.stderr, result.stderr
    result = set_image("docker.io/library/busybox@sha256:" + "a" * 64)
    assert result.returncode != 0 and "ah-images-pinned" in result.stderr, result.stderr
    # Control: another image from the registry, by digest, passes admission.
    assert set_image(PINNED).returncode == 0
