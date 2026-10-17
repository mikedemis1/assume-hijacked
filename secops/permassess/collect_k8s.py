"""Kubernetes: what each workload's service account may do, and which pods may reach which.

RBAC. For every service account a workload in the assessed namespaces runs as:
    kubectl auth can-i --list --as=system:serviceaccount:<ns>:<sa>
        --as-group=system:serviceaccounts --as-group=system:serviceaccounts:<ns> -n <ns>
The two groups are the ones the API server gives every service account token, so a binding to
"all service accounts" or "all service accounts of a namespace" is counted too.
https://kubernetes.io/docs/reference/access-authn-authz/rbac/#service-account-permissions
Rules every authenticated caller gets from the default cluster roles (system:basic-user,
system:discovery, system:public-info-viewer) are left out; anything else is a line.
https://kubernetes.io/docs/reference/access-authn-authz/rbac/#default-roles-and-role-bindings

Network. Edges between components (pods named by app.kubernetes.io/name), evaluated from the
NetworkPolicy objects with the Kubernetes rules: a pod selected by no policy of a direction is
open in that direction; otherwise a connection needs an egress rule on the caller's side AND an
ingress rule on the callee's side. Ports are not looked at: an edge means "some port".
https://kubernetes.io/docs/concepts/services-networking/network-policies/
The pods are the running ones plus the pod templates of Deployments, StatefulSets, DaemonSets,
Jobs and CronJobs, so a component scaled to zero still counts. ipBlock rules and Cilium
policies (DNS names, FQDNs, entities) are listed for the report, not evaluated.
"""
from __future__ import annotations

import json
from dataclasses import dataclass

from secops.permassess import CollectorError, PlaneResult, Runner, run_command

NAME_LABEL = "app.kubernetes.io/name"
_RESOURCE_BASELINE = {
    ("create", "selfsubjectaccessreviews.authorization.k8s.io"),
    ("create", "selfsubjectrulesreviews.authorization.k8s.io"),
    ("create", "selfsubjectreviews.authentication.k8s.io"),
}
_URL_BASELINE = {"/api", "/api/*", "/apis", "/apis/*", "/healthz", "/livez", "/readyz",
                 "/openapi", "/openapi/*", "/version", "/version/"}


@dataclass(frozen=True)
class Endpoint:
    namespace: str
    component: str
    labels: tuple[tuple[str, str], ...]
    service_account: str


def _json(run: Runner, args: list[str]) -> dict:
    out = run(["kubectl", *args, "-o", "json"])
    try:
        return json.loads(out)
    except json.JSONDecodeError as exc:
        raise CollectorError(f"kubectl {' '.join(args[:2])}: not JSON ({exc.msg})") from exc


def matches(selector: dict | None, labels: dict[str, str]) -> bool:
    """A Kubernetes label selector; {} matches everything."""
    if selector is None:
        return True
    for key, value in (selector.get("matchLabels") or {}).items():
        if labels.get(key) != value:
            return False
    for expr in selector.get("matchExpressions") or []:
        key, op, values = expr.get("key"), expr.get("operator"), expr.get("values") or []
        if op == "In" and labels.get(key) not in values:
            return False
        if op == "NotIn" and key in labels and labels[key] in values:
            return False
        if op == "Exists" and key not in labels:
            return False
        if op == "DoesNotExist" and key in labels:
            return False
        if op not in {"In", "NotIn", "Exists", "DoesNotExist"}:
            raise CollectorError(f"unknown label selector operator {op!r}")
    return True


def _pod_template(obj: dict) -> dict | None:
    spec = obj.get("spec") or {}
    if obj.get("kind") == "CronJob":
        spec = ((spec.get("jobTemplate") or {}).get("spec")) or {}
    return spec.get("template")


def endpoints(pods: dict, workloads: dict, in_scope) -> list[Endpoint]:
    found: set[Endpoint] = set()
    for obj in (pods.get("items") or []) + (workloads.get("items") or []):
        ns = obj["metadata"].get("namespace", "default")
        if not in_scope(ns):
            continue
        if obj.get("kind") == "Pod":
            meta, spec = obj["metadata"], obj.get("spec") or {}
        else:
            template = _pod_template(obj)
            if template is None:
                continue
            meta, spec = template.get("metadata") or {}, template.get("spec") or {}
        labels = meta.get("labels") or {}
        if NAME_LABEL not in labels:
            continue
        found.add(Endpoint(ns, labels[NAME_LABEL], tuple(sorted(labels.items())),
                           spec.get("serviceAccountName") or "default"))
    return sorted(found, key=lambda e: (e.component, e.namespace, e.labels))


def _types(policy: dict) -> set[str]:
    spec = policy.get("spec") or {}
    if spec.get("policyTypes"):
        return set(spec["policyTypes"])
    return {"Ingress"} | ({"Egress"} if "egress" in spec else set())


def _peer_matches(peer: dict, policy_ns: str, other: Endpoint, ns_labels: dict) -> bool:
    if "ipBlock" in peer:
        return False
    pod_sel, ns_sel = peer.get("podSelector"), peer.get("namespaceSelector")
    if ns_sel is None:
        if other.namespace != policy_ns:
            return False
    elif not matches(ns_sel, ns_labels.get(other.namespace, {})):
        return False
    return matches(pod_sel, dict(other.labels))


def _allowed(policies: list[dict], direction: str, me: Endpoint, other: Endpoint,
             ns_labels: dict) -> bool:
    key, peers_key = ("egress", "to") if direction == "Egress" else ("ingress", "from")
    selecting = [p for p in policies
                 if p["metadata"].get("namespace") == me.namespace and direction in _types(p)
                 and matches((p.get("spec") or {}).get("podSelector") or {}, dict(me.labels))]
    if not selecting:
        return True
    for p in selecting:
        for rule in (p.get("spec") or {}).get(key) or []:
            peers = rule.get(peers_key)
            if not peers:
                return True  # a rule without peers allows every peer
            if any(_peer_matches(peer, me.namespace, other, ns_labels) for peer in peers):
                return True
    return False


def edge_lines(eps: list[Endpoint], policies: list[dict], ns_labels: dict) -> list[str]:
    lines = set()
    for src in eps:
        for dst in eps:
            if src.component == dst.component:
                continue
            if (_allowed(policies, "Egress", src, dst, ns_labels)
                    and _allowed(policies, "Ingress", dst, src, ns_labels)):
                lines.add(f"k8s {src.component} -> {dst.component}")
    return sorted(lines)


def _ip_blocks(policies: list[dict], eps: list[Endpoint]) -> list[str]:
    info = set()
    for p in policies:
        spec = p.get("spec") or {}
        selected = [e.component for e in eps if e.namespace == p["metadata"].get("namespace")
                    and matches(spec.get("podSelector") or {}, dict(e.labels))]
        for rule in spec.get("egress") or []:
            for peer in rule.get("to") or []:
                if "ipBlock" in peer:
                    for c in selected:
                        info.add(f"k8s {c} -> cidr {peer['ipBlock'].get('cidr')} (ipBlock, not compared)")
    return sorted(info)


def parse_can_i(table: str) -> list[str]:
    """`kubectl auth can-i --list` output -> ["<verb> <resource>[/<name>]", "<verb> <url>"]."""
    rows = [r for r in table.splitlines() if r.strip()]
    if not rows or not rows[0].startswith("Resources"):
        raise CollectorError("kubectl auth can-i --list: unexpected output (no header)")
    header = rows[0]
    try:
        cols = [header.index("Non-Resource URLs"), header.index("Resource Names"),
                header.index("Verbs")]
    except ValueError as exc:
        raise CollectorError("kubectl auth can-i --list: unexpected header") from exc

    def field(row: str, start: int, end: int | None) -> list[str]:
        text = row[start:end].strip() if end else row[start:].strip()
        return [x for x in text.strip("[]").split() if x]

    rules = []
    for row in rows[1:]:
        resources = row[:cols[0]].strip()
        urls = field(row, cols[0], cols[1])
        names = field(row, cols[1], cols[2])
        verbs = field(row, cols[2], None)
        for verb in verbs:
            if resources:
                if (verb, resources) in _RESOURCE_BASELINE and not names:
                    continue
                for name in names or [None]:
                    rules.append(f"{verb} {resources}" + (f"/{name}" if name else ""))
            for url in urls:
                if verb == "get" and url in _URL_BASELINE:
                    continue
                rules.append(f"{verb} {url}")
    return sorted(set(rules))


def collect(run: Runner = run_command, namespace_prefix: str = "ah-") -> PlaneResult:
    def in_scope(ns: str) -> bool:
        return ns.startswith(namespace_prefix)

    namespaces = _json(run, ["get", "namespaces"])
    ns_labels = {n["metadata"]["name"]: n["metadata"].get("labels") or {}
                 for n in namespaces.get("items") or []}
    pods = _json(run, ["get", "pods", "-A"])
    workloads = _json(run, ["get", "deployments,statefulsets,daemonsets,jobs,cronjobs", "-A"])
    policies = _json(run, ["get", "networkpolicies", "-A"]).get("items") or []
    eps = endpoints(pods, workloads, in_scope)

    lines = edge_lines(eps, policies, ns_labels)
    accounts = sorted({(e.namespace, e.service_account) for e in eps})
    for ns, sa in accounts:
        table = run(["kubectl", "auth", "can-i", "--list", f"--as=system:serviceaccount:{ns}:{sa}",
                     "--as-group=system:serviceaccounts", f"--as-group=system:serviceaccounts:{ns}",
                     "-n", ns])
        lines.extend(f"k8s serviceaccount {sa}: {rule}" for rule in parse_can_i(table))

    info = _ip_blocks(policies, eps)
    try:
        cilium = _json(run, ["get", "ciliumnetworkpolicies", "-A"]).get("items") or []
        if cilium:
            info.append(f"k8s: {len(cilium)} CiliumNetworkPolicy objects (DNS, FQDN and entity "
                        "rules) are not evaluated here")
    except CollectorError:
        pass  # no Cilium CRD on this cluster
    info.extend(f"k8s endpoint {e.namespace}/{e.component} runs as {e.service_account}" for e in eps)
    return PlaneResult(
        lines=sorted(set(lines)),
        scope={"components": {e.component for e in eps},
               "service_accounts": {sa for _, sa in accounts}},
        info=info,
    )
