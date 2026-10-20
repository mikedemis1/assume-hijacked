"""The local cluster has the shape the walls expect: Cilium and Hubble running, a sandbox node
that only sandbox pods can use, and the stand-in RuntimeClass that sends pods there."""


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


def test_runtimeclass_exists(get):
    rc = get("get", "runtimeclass", "kata-vm-isolation")
    assert rc["handler"] == "runc"
    scheduling = rc["scheduling"]
    assert scheduling["nodeSelector"] == {"ah/pool": "sandbox"}
    assert {"key": "ah/sandbox", "operator": "Equal", "value": "true", "effect": "NoSchedule"} in (
        scheduling["tolerations"]
    )


