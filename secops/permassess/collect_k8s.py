"""Kubernetes: what each workload's service account may do, and which pods may reach which.

RBAC. For every ServiceAccount, whether a pod runs as it right now or not, inspect each
assessed target namespace (the dispatcher creates Jobs outside its own namespace):
    kubectl auth can-i --list --as=system:serviceaccount:<ns>:<sa>
        --as-group=system:serviceaccounts --as-group=system:serviceaccounts:<ns>
        --as-group=system:authenticated -n <target namespace>
These groups match a service account token, including authenticated callers. Namespaced rules
carry their target namespace. Cluster-scoped resources come from kubectl api-resources. Duplicate
nondefault account names across assessed namespaces cause an error because the manifest format
identifies an account by name. Default accounts have no declared grants; extra grants still fail.
https://kubernetes.io/docs/reference/access-authn-authz/rbac/#service-account-permissions
Rules every authenticated caller gets from the default cluster roles (system:basic-user,
system:discovery, system:public-info-viewer), public OIDC issuer/JWKS reads and read-only cluster
trust bundle discovery are left out. Writes and named-resource grants are still lines.
https://kubernetes.io/docs/reference/access-authn-authz/rbac/#default-roles-and-role-bindings

Network. Edges between components (pods named by app.kubernetes.io/name), evaluated from the
NetworkPolicy objects with the Kubernetes rules: a pod selected by no policy of a direction is
open in that direction; otherwise a connection needs an egress rule on the caller's side AND an
ingress rule on the callee's side. Ports are not looked at: an edge means "some port".
https://kubernetes.io/docs/concepts/services-networking/network-policies/
The pods are the running ones plus the pod templates of Deployments, StatefulSets, DaemonSets,
Jobs and CronJobs, so a component scaled to zero still counts. The dispatcher's ConfigMap also
supplies the agent Job template when no agent Job has run yet. A pod or template in an assessed
namespace without the name label cannot be placed in any edge, so it becomes a line of its own
(`k8s unlabelled <kind> <namespace>/<name>`), which no manifest declares: the run fails until it
is labelled. ipBlock rules and Cilium policies (DNS names, FQDNs, entities) are listed for the
report, not evaluated. Namespace exclusions are explicit operator input and appear in report info.
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
    ("get", "clustertrustbundles.certificates.k8s.io"),
    ("list", "clustertrustbundles.certificates.k8s.io"),
    ("watch", "clustertrustbundles.certificates.k8s.io"),
}
_URL_BASELINE = {"/api", "/api/*", "/apis", "/apis/*", "/healthz", "/livez", "/readyz",
                 "/openapi", "/openapi/*", "/version", "/version/",
                 "/.well-known/openid-configuration", "/.well-known/openid-configuration/",
                 "/openid/v1/jwks", "/openid/v1/jwks/"}


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


def endpoints(pods: dict, workloads: dict, in_scope,
              unlabelled: list[str] | None = None) -> list[Endpoint]:
    """The labelled pods and pod templates of the assessed namespaces. The others are appended
    to `unlabelled` as lines, never dropped."""
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
            if unlabelled is not None:
                unlabelled.append(f"k8s unlabelled {obj.get('kind', 'Pod')} "
                                  f"{ns}/{obj['metadata'].get('name', '?')}")
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


def _configured_jobs(configmaps: dict, in_scope) -> list[dict]:
    jobs = []
    for obj in configmaps.get("items") or []:
        meta = obj.get("metadata") or {}
        if meta.get("name") != "agent-job-template" or not in_scope(meta.get("namespace", "default")):
            continue
        try:
            job = json.loads(obj.get("data", {})["job.json"])
            if not isinstance(job, dict) or job.get("apiVersion") != "batch/v1" or job.get("kind") != "Job":
                raise ValueError("not a Job")
            if not in_scope(job["metadata"]["namespace"]):
                raise ValueError("namespace is outside the assessment")
            template = job["spec"]["template"]
            if (template["metadata"]["labels"][NAME_LABEL] != "agent"
                    or template["spec"]["serviceAccountName"] != "agent"):
                raise ValueError("not the agent identity")
        except (KeyError, ValueError, TypeError, AttributeError) as exc:
            raise CollectorError("the configured agent Job template cannot be assessed") from exc
        jobs.append(job)
    return jobs


def collect(run: Runner = run_command, namespace_prefix: str = "ah-",
            excluded_namespaces: set[str] | None = None) -> PlaneResult:
    excluded_namespaces = excluded_namespaces or set()
    def in_scope(ns: str) -> bool:
        return ns.startswith(namespace_prefix) and ns not in excluded_namespaces

    namespaces = _json(run, ["get", "namespaces"])
    ns_labels = {n["metadata"]["name"]: n["metadata"].get("labels") or {}
                 for n in namespaces.get("items") or []}
    pods = _json(run, ["get", "pods", "-A"])
    workloads = _json(run, ["get", "deployments,statefulsets,daemonsets,jobs,cronjobs", "-A"])
    configured = _json(run, ["get", "configmaps", "-A"])
    workloads["items"] = (workloads.get("items") or []) + _configured_jobs(configured, in_scope)
    policies = _json(run, ["get", "networkpolicies", "-A"]).get("items") or []
    service_accounts = _json(run, ["get", "serviceaccounts", "-A"]).get("items") or []
    unlabelled: list[str] = []
    eps = endpoints(pods, workloads, in_scope, unlabelled)

    lines = edge_lines(eps, policies, ns_labels) + unlabelled
    accounts = sorted({(e.namespace, e.service_account) for e in eps}
                      | {(sa["metadata"].get("namespace", "default"), sa["metadata"]["name"])
                         for sa in service_accounts
                         if in_scope(sa["metadata"].get("namespace", "default"))})
    names = [sa for _, sa in accounts if sa != "default"]
    if len(names) != len(set(names)):
        raise CollectorError("duplicate service account name across assessed namespaces; source principals cannot be merged")
    targets = {ns for ns in ns_labels if in_scope(ns)} | {ns for ns, _ in accounts}
    cluster_resources = set(run(["kubectl", "api-resources", "--namespaced=false", "-o", "name"]).splitlines())
    for ns, sa in accounts:
        for target in sorted(targets):
            table = run(["kubectl", "auth", "can-i", "--list", f"--as=system:serviceaccount:{ns}:{sa}",
                         "--as-group=system:serviceaccounts", f"--as-group=system:serviceaccounts:{ns}",
                         "--as-group=system:authenticated", "-n", target])
            for rule in parse_can_i(table):
                resource = rule.split(" ", 1)[1]
                global_rule = resource.startswith("/") or resource.split("/", 1)[0] in cluster_resources
                suffix = "" if global_rule else f" in {target}"
                lines.append(f"k8s serviceaccount {sa}: {rule}{suffix}")

    info = _ip_blocks(policies, eps)
    info.extend(f"k8s namespace {ns} excluded explicitly" for ns in sorted(excluded_namespaces))
    info.append("k8s public API/OIDC discovery, self reviews and read-only cluster trust bundle discovery are baseline permissions")
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
