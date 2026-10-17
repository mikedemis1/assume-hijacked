"""The network and admission walls on the live kind cluster `ah` (`sh scripts/kind-up.sh`).

Admission is checked with server-side dry runs: the API server runs every admission step (Pod
Security, the ValidatingAdmissionPolicies, RBAC for `--as`) and stores nothing, and no image is
pulled. If the chart is not installed (no Helm release owns the namespaces), the session
fixture applies the chart's namespaces, ServiceAccounts, dispatcher RBAC and policies from
`helm template`, and deletes them again at the end.
"""

import json
import subprocess
import time

import pytest
import yaml

from tests.k8s.conftest import CONTEXT, kubectl_json
from tests.k8s.test_chart import (HELM, NAMESPACES, SANDBOX_RUNTIME, agent_job, helm)

pytestmark = [pytest.mark.k8s, pytest.mark.skipif(HELM is None, reason="helm is not installed")]

WALL_KINDS = {"Namespace", "ServiceAccount", "Role", "RoleBinding", "NetworkPolicy", "CiliumNetworkPolicy",
              "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding"}
DISPATCHER = "system:serviceaccount:ah-intake:dispatcher"
PINNED = "localhost:5001/assume-hijacked@sha256:" + "0" * 64


def kubectl(*args: str, stdin: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(["kubectl", "--context", CONTEXT, *args], input=stdin, capture_output=True,
                          text=True, encoding="utf-8", timeout=120, check=False)


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
    wait_until(lambda: all("Valid" in c for c in statuses().values()))
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
    # The LLM gateway's own pods (from its Deployment) are not sandboxed (R17b).
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
