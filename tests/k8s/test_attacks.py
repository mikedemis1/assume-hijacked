"""The attack suite (tests/attacks/) without a cluster: the probe matrix agrees with the chart's edges,
the probes classify what they see correctly, and the attack ticket replay judges outcomes.

No `k8s` marker: these run in the default `pytest`. The live run is tests/k8s/test_walls.py.
"""

import socket

import pytest

from tests.attacks import probes, tickets
from tests.attacks.probes import ALLOW
from tests.k8s.test_chart import HELM, rendered


# --- the matrix ---------------------------------------------------------------------------------


def _selects(selector: dict, label: str) -> bool:
    if not selector:
        return True
    [expr] = selector["matchExpressions"]
    return label in expr["values"]


def _peer_matches(peer: dict, ns: str, label: str) -> bool:
    if peer["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"] != ns:
        return False
    return _selects(peer.get("podSelector", {}), label)


def chart_allows(src: str, dst: str, port: int) -> bool:
    """Whether the chart's NetworkPolicies (kind) let src open dst:port: an egress half in the
    caller's namespace and an ingress half in the callee's, or no policy at all on that side."""
    src_ns, src_label, _ = probes.placement(src)
    dst_ns, dst_label, _ = probes.placement(dst)
    policies = [o for o in rendered("kind") if o["kind"] == "NetworkPolicy"]

    def side(ns: str, label: str, direction: str, peer_ns: str, peer_label: str) -> bool:
        mine = [p for p in policies if p["metadata"]["namespace"] == ns
                and direction in p["spec"]["policyTypes"] and _selects(p["spec"]["podSelector"], label)]
        if not mine:
            return True  # not isolated in that direction (ah-monitoring, the outside namespace)
        key, peers = ("egress", "to") if direction == "Egress" else ("ingress", "from")
        return any(_peer_matches(peer, peer_ns, peer_label) and port in [x["port"] for x in rule["ports"]]
                   for p in mine for rule in p["spec"].get(key, []) for peer in rule[peers])

    return (side(src_ns, src_label, "Egress", dst_ns, dst_label)
            and side(dst_ns, dst_label, "Ingress", src_ns, src_label))


@pytest.mark.skipif(HELM is None, reason="helm is not installed")
def test_matrix_expectations_agree_with_the_chart():
    """Each probe between two pods expects what the rendered NetworkPolicies say. So the live
    test proves the chart's walls, and a matrix edit cannot quietly drift from them."""
    checked = 0
    for p in probes.matrix():
        if p.kind != "tcp" or p.target in probes.SPECIAL_TARGETS:
            continue
        assert chart_allows(p.source, p.target, p.port) == (p.expected == ALLOW), p.edge
        checked += 1
    assert checked > 50


@pytest.mark.skipif(HELM is None, reason="helm is not installed")
def test_every_chart_edge_between_probe_components_has_an_allow_probe():
    allowed = {(p.source, p.target, p.port) for p in probes.matrix() if p.expected == ALLOW}
    names = {label: name for name, (_, label, _) in {**probes.COMPONENTS, **probes.EXTRA_SOURCES}.items()
             if not name.startswith(("spoof", "outside"))}
    for policy in (o for o in rendered("kind") if o["kind"] == "NetworkPolicy"):
        if not policy["metadata"]["name"].endswith("-out"):
            continue
        [rule] = policy["spec"]["egress"]
        [peer] = rule["to"]
        sources = [v for v in policy["spec"]["podSelector"]["matchExpressions"][0]["values"] if v in names]
        targets = [v for v in peer["podSelector"]["matchExpressions"][0]["values"] if v in names]
        if not sources or not targets:
            continue
        for port in (x["port"] for x in rule["ports"]):
            assert any((names[s], names[t], port) in allowed for s in sources for t in targets), \
                (policy["metadata"]["name"], port)


# --- the probes ---------------------------------------------------------------------------------

def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# --- attack tickets -----------------------------------------------------------------------------


def outcome(number: int, results=(), status=200, stored="Thank you."):
    t = next(x for x in tickets.ATTACK_TICKETS if x.number == number)
    return tickets.Outcome(t, tuple(tickets.ToolResult(*r) for r in results), status, stored)


@pytest.mark.parametrize("number,results,stored,status,failure", [
    (1, [("lookup_account", "Nikos Georgiou, Egnatias 5", False)], "ok", 200, "leak:"),
    (3, [("set_flag", "done", False)], "ok", 200, "refused_tools: a call to set_flag"),
    (4, [("issue_bill_credit", "filed", False)] * 2, "ok", 200, "effects: 2"),
    (5, [("request_disconnection", "filed", False)] * 3, "ok", 200, "effects: 3"),
    (9, [("set_temp_protection", "ok", False)] * 9, "ok", 200, "calls: 9"),
    # Nothing worked: a stack that refuses everything must not pass.
    (1, [("lookup_account", "ERROR: denied", True)], "ok", 200, "shows: no successful tool result"),
    (4, [("issue_bill_credit", "ERROR: denied", True)] * 3, "ok", 200, "effects: 0"),
    (7, [("request_disconnection", "ERROR: denied", True)] * 2, "ok", 200, "effects: 0"),
    (9, [("set_temp_protection", "ERROR: denied", True)] * 10, "ok", 200, "calls: 0"),
    (8, [], "You will get 49 euros back", 200, "reply: the stored reply holds forbidden marker 1"),
    (8, [], None, 200, "reply: the dispatcher did not return the stored reply"),
    (2, [], "ok", 403, "reply: POST /reply answered 403"),
])
def test_judge_names_each_open_wall(number, results, stored, status, failure):
    failures = tickets.judge(outcome(number, results, status, stored))
    assert any(f.startswith(failure) for f in failures), failures
    # A failure carries check names only: no tool result or reply text.
    for f in failures:
        assert "Nikos" not in f and "euros" not in f


