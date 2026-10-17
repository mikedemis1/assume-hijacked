"""The local cluster has the shape the walls expect: Cilium and Hubble running, a sandbox node
that only sandbox pods can use, and the stand-in RuntimeClass that sends pods there."""

import subprocess

import pytest

pytestmark = pytest.mark.k8s


def ready_replicas(obj) -> tuple[int, int]:
    status = obj["status"]
    return status.get("numberReady", status.get("readyReplicas", 0)), (
        status.get("desiredNumberScheduled", status.get("replicas", 0))
    )


@pytest.mark.parametrize(
    ("kind", "name"),
    [
        ("daemonset", "cilium"),
        ("deployment", "cilium-operator"),
        ("deployment", "hubble-relay"),
        ("deployment", "hubble-ui"),
    ],
)
def test_cilium_ready(get, kind, name):
    ready, wanted = ready_replicas(get("--namespace", "kube-system", "get", kind, name))
    assert wanted >= 1, f"{kind}/{name} wants no replicas"
    assert ready == wanted, f"{kind}/{name}: {ready} of {wanted} ready"


def test_all_nodes_ready(get):
    nodes = get("get", "nodes")["items"]
    assert len(nodes) == 2
    for node in nodes:
        ready = [c for c in node["status"]["conditions"] if c["type"] == "Ready"]
        assert ready and ready[0]["status"] == "True", node["metadata"]["name"]


def test_runtimeclass_exists(get):
    rc = get("get", "runtimeclass", "kata-vm-isolation")
    assert rc["handler"] == "runc"
    scheduling = rc["scheduling"]
    assert scheduling["nodeSelector"] == {"ah/pool": "sandbox"}
    assert {"key": "ah/sandbox", "operator": "Equal", "value": "true", "effect": "NoSchedule"} in (
        scheduling["tolerations"]
    )


def test_sandbox_node_tainted(get):
    nodes = get("get", "nodes")["items"]
    pools = {n["metadata"]["labels"].get("ah/pool"): n for n in nodes}
    assert set(pools) == {"system", "sandbox"}

    sandbox_taints = pools["sandbox"]["spec"].get("taints", [])
    assert {"key": "ah/sandbox", "value": "true", "effect": "NoSchedule"} in sandbox_taints

    # Control: the system node takes ordinary pods, so the taint is what keeps them off the sandbox.
    assert pools["system"]["spec"].get("taints", []) == []


def test_nodes_pull_from_the_local_registry(get):
    """Images by digest come from kind-registry (scripts/kind-registry.sh). Each node
    maps localhost:5001 to the registry container; the ConfigMap tells tools where it is."""
    hosting = get("--namespace", "kube-public", "get", "configmap", "local-registry-hosting")
    assert 'host: "localhost:5001"' in hosting["data"]["localRegistryHosting.v1"]
    for node in get("get", "nodes")["items"]:
        name = node["metadata"]["name"]
        result = subprocess.run(["docker", "exec", name, "cat", "/etc/containerd/certs.d/localhost:5001/hosts.toml"],
                                capture_output=True, text=True, timeout=30, check=False)
        assert result.stdout.strip() == '[host."http://kind-registry:5000"]', (name, result.stderr)
