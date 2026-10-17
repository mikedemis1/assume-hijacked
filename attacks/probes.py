"""The probe matrix: every network edge the walls must refuse, next to the edges they must allow.

A probe runs inside a pod that carries the labels of one component (its *source*), so the
NetworkPolicies and CiliumNetworkPolicies select it exactly as they select that component. It
tries one thing and reports what happened:

  tcp      open a TCP connection to a component, the internet, the instance metadata endpoint or
           the Kubernetes API. Connected or refused (RST: the packet got through and nobody
           listens) count as allow; a timeout (Cilium drops denied packets) counts as deny.
  dns      one DNS query for an absolute name, straight to the pod's nameserver, no search list.
           NOERROR, NXDOMAIN or SERVFAIL mean a DNS server answered for that name, so the query
           was let through (SERVFAIL: CoreDNS tried to forward it): allow. REFUSED (Cilium's DNS
           proxy) is deny.
  resolve  the C library resolver (getaddrinfo), with the pod's search list and ndots, as an
           application would look a name up. A result is allow. A failed lookup is deny only when
           the same name, asked directly, is REFUSED.

Anything else is error: a failed name lookup before a connection, no DNS answer at all, an
unreachable network, a malformed answer. An error never matches an expectation, so a probe that
could not run cannot pass as a wall that held.

Each result is {"edge", "source", "expected", "observed", "detail"}; observed is allow, deny or
error, detail says why (connected, timeout, REFUSED, ...). The matrix below is data: the live test
(tests/k8s/test_walls.py) and the chart's attack-suite test pods run the same list.
"""

from __future__ import annotations

import os
import secrets
import socket
import struct
from dataclasses import asdict, dataclass

ALLOW = "allow"
DENY = "deny"
ERROR = "error"
# What a deny must look like, per probe kind: the wall's own signature.
DENY_DETAIL = {"tcp": "timeout", "dns": "REFUSED", "resolve": "REFUSED"}

# Components a probe can run as or aim at: namespace, labels (app.kubernetes.io/name) and the
# ports the real component listens on (stand-in probe pods listen on the same ones).
COMPONENTS: dict[str, tuple[str, str, tuple[int, ...]]] = {
    # name                 (namespace,    label,                 ports)
    "agent":               ("ah-agent",   "agent",               ()),
    "llm-gateway":         ("ah-agent",   "llm-gateway",         (8083, 9000)),
    "dispatcher":          ("ah-intake",  "dispatcher",          (8081, 9000)),
    "tool-gateway":        ("ah-gateway", "tool-gateway",        (8080, 9000)),
    "tool-read-ticket":    ("ah-tools",   "tool-read-ticket",    (8000, 9000)),
    "tool-lookup-account": ("ah-tools",   "tool-lookup-account", (8000, 9000)),
    "tool-request-disconnection": ("ah-tools", "tool-request-disconnection", (8000, 9000)),
    "tool-issue-bill-credit":     ("ah-tools", "tool-issue-bill-credit",     (8000, 9000)),
    "tool-set-temp-protection":   ("ah-tools", "tool-set-temp-protection",   (8000, 9000)),
    "risk-engine":         ("ah-core",    "risk-engine",         (8082, 9000)),
    "executor":            ("ah-core",    "executor",            (9000,)),
    "register-sync":       ("ah-core",    "register-sync",       (9000,)),
    "console":             ("ah-staff",   "console",             (8084, 9000)),
    "fake-register":       ("ah-fakes",   "fake-register",       (8090,)),
    "fake-dso":            ("ah-fakes",   "fake-dso",            (8091,)),
    "fake-sms":            ("ah-fakes",   "fake-sms",            (8092,)),
    "postgres":            ("ah-data",    "postgres",            (5432,)),
}

# Probe identities that are not chart components. Only the live test creates them (the chart's
# test pods run as the components above).
#   spoof-tool-gateway     in ah-agent, labelled tool-gateway: a label is not an identity
#   outside-tool-gateway   in a namespace with no policies, labelled tool-gateway: the ingress
#                          halves name the caller's namespace too
#   outside-agent          same, labelled agent
#   outside                no labels the walls know: the control for "the internet, DNS and
#                          the metadata endpoint are reachable at all from this cluster"
#   monitoring             in ah-monitoring (matrix row 21: Prometheus scrapes port 9000)
#   stray                  in ah-fakes with a label no edge names: what default-deny alone
#                          guards (every component pod is also selected by its edge policies)
OUTSIDE_NAMESPACE = "ah-probe-outside"
EXTRA_SOURCES: dict[str, tuple[str, str, tuple[int, ...]]] = {
    "spoof-tool-gateway":   ("ah-agent",        "tool-gateway", ()),
    "outside-tool-gateway": (OUTSIDE_NAMESPACE, "tool-gateway", ()),
    "outside-agent":        (OUTSIDE_NAMESPACE, "agent",        ()),
    "outside":              (OUTSIDE_NAMESPACE, "probe-outside", ()),
    "monitoring":           ("ah-monitoring",   "prometheus",   ()),
    "stray":                ("ah-fakes",        "stray",        (8092,)),
}

# Targets that are not components.
INTERNET = "internet"            # a public IP: no component may open a connection out
IMDS = "imds"                    # Azure instance metadata (managed identity tokens)
KUBE_API = "kube-apiserver"      # the Kubernetes API service
CLUSTER_NAME = "kubernetes.default.svc.cluster.local."  # always exists in a cluster
SPECIAL_TARGETS = {
    INTERNET: ("1.1.1.1", 443),
    IMDS: ("169.254.169.254", 80),
    KUBE_API: ("kubernetes.default.svc.cluster.local.", 443),
}
# A fresh label per run, so no cache anywhere can answer it: a name like this carries data out
# when the resolver forwards it (DNS exfiltration).
RANDOM = "{random}"
EXFIL_NAME = f"{RANDOM}.exfil.example."


@dataclass(frozen=True)
class Probe:
    source: str
    kind: str            # tcp | dns | resolve
    target: str          # component or special target (tcp), name (dns, resolve)
    expected: str        # allow | deny
    port: int = 0
    why: str = ""        # the wall or matrix row this probe checks

    @property
    def edge(self) -> str:
        if self.kind == "tcp":
            return f"{self.source} -> {self.target}:{self.port}"
        return f"{self.source} {self.kind} {self.target}"

    def to_json(self) -> dict:
        return {**asdict(self), "edge": self.edge}

    @classmethod
    def from_json(cls, data: dict) -> "Probe":
        return cls(source=data["source"], kind=data["kind"], target=data["target"],
                   expected=data["expected"], port=int(data.get("port", 0)), why=data.get("why", ""))


def tcp(source: str, target: str, expected: str, why: str, port: int | None = None) -> Probe:
    if port is None:
        port = SPECIAL_TARGETS[target][1] if target in SPECIAL_TARGETS else placement(target)[2][0]
    return Probe(source, "tcp", target, expected, port, why)


def dns(source: str, name: str, expected: str, why: str) -> Probe:
    return Probe(source, "dns", name, expected, 0, why)


def resolve(source: str, name: str, expected: str, why: str) -> Probe:
    return Probe(source, "resolve", name, expected, 0, why)


def _everywhere_denied(source: str, extra: tuple[str, ...] = ()) -> list[Probe]:
    """What no component may do: reach the internet or the metadata endpoint, or resolve a name
    outside the cluster."""
    probes = [
        tcp(source, INTERNET, DENY, "default deny: no egress to the internet"),
        tcp(source, IMDS, DENY, "deny-instance-metadata (Cilium egressDeny)"),
        dns(source, EXFIL_NAME, DENY, "edge-22: DNS for cluster.local names only (exfiltration)"),
        dns(source, CLUSTER_NAME, ALLOW, "control: this pod's DNS works, so a refusal is the rule"),
    ]
    if source not in extra:
        probes.append(tcp(source, KUBE_API, DENY, "only dispatcher, tool-gateway, llm-gateway reach the API"))
    return probes


API_CALLERS = ("dispatcher", "tool-gateway", "llm-gateway")
TOOLS = tuple(name for name in COMPONENTS if name.startswith("tool-") and name != "tool-gateway")


def matrix() -> list[Probe]:
    """Every probe, in a fixed order. Sources not in COMPONENTS are live-test only."""
    m: list[Probe] = []
    a = "agent"
    m += [
        tcp(a, "tool-gateway", ALLOW, "edge-05 agent -> tool-gateway", 8080),
        tcp(a, "llm-gateway", ALLOW, "edge-06 agent -> llm-gateway", 8083),
        tcp(a, "dispatcher", ALLOW, "edge-07 agent -> dispatcher", 8081),
        tcp(a, "tool-gateway", DENY, "wrong port on an allowed edge (ops is for ah-monitoring)", 9000),
        tcp(a, "llm-gateway", DENY, "wrong port on an allowed edge", 9000),
        *[tcp(a, t, DENY, "agent never reaches a tool directly", 8000) for t in TOOLS],
        tcp(a, "postgres", DENY, "agent has no database"),
        tcp(a, "risk-engine", DENY, "agent never reaches the risk engine", 8082),
        tcp(a, "fake-register", DENY, "agent never reaches the outside systems"),
        tcp(a, "fake-dso", DENY, "agent never reaches the outside systems"),
        tcp(a, "fake-sms", DENY, "agent never reaches the outside systems"),
        tcp(a, "console", DENY, "agent never reaches staff", 8084),
        *_everywhere_denied(a),
        dns(a, "example.com.", DENY, "edge-22: names outside cluster.local are refused"),
        dns(a, "api.anthropic.com.", DENY, "edge-19: only llm-gateway resolves the LLM API"),
        dns(a, "tool-gateway.ah-gateway.svc.cluster.local.", ALLOW, "edge-22: cluster names resolve"),
        resolve(a, "kubernetes.default.svc.cluster.local", ALLOW,
                "edge-22: the search walk of a service name passes the DNS rule"),
        resolve(a, "kubernetes.default", ALLOW, "edge-22: a short service name (search list) resolves"),
    ]
    t = "tool-lookup-account"
    m += [
        tcp(t, "postgres", ALLOW, "edge-12 tools -> db"),
        tcp(t, "tool-read-ticket", DENY, "no tool -> tool", 8000),
        tcp(t, "tool-gateway", DENY, "tools never call back into the gateway", 8080),
        tcp(t, "risk-engine", DENY, "tools never reach the risk engine", 8082),
        tcp(t, "fake-dso", DENY, "tools never reach the outside systems"),
        tcp(t, "dispatcher", DENY, "tools never reach the dispatcher", 8081),
        *_everywhere_denied(t),
    ]
    g = "tool-gateway"
    m += [
        *[tcp(g, t, ALLOW, "edge-09 tool-gateway -> tools", 8000) for t in TOOLS],
        tcp(g, "tool-read-ticket", DENY, "ops port of a tool is for ah-monitoring only", 9000),
        tcp(g, "risk-engine", ALLOW, "edge-08 tool-gateway -> risk-engine", 8082),
        tcp(g, "postgres", ALLOW, "edge-11 tool-gateway -> db"),
        tcp(g, KUBE_API, ALLOW, "edge-10 tool-gateway -> API (TokenReview)"),
        tcp(g, "dispatcher", DENY, "not an edge", 8081),
        tcp(g, "fake-dso", DENY, "not an edge"),
        *_everywhere_denied(g, API_CALLERS),
    ]
    lg = "llm-gateway"
    m += [
        tcp(lg, KUBE_API, ALLOW, "edge-10 llm-gateway -> API (TokenReview)"),
        tcp(lg, "postgres", DENY, "llm-gateway has no database"),
        tcp(lg, "tool-gateway", DENY, "llm-gateway never calls tools", 8080),
        *_everywhere_denied(lg, API_CALLERS),
    ]
    d = "dispatcher"
    m += [
        tcp(d, "postgres", ALLOW, "edge-04 dispatcher -> db"),
        tcp(d, KUBE_API, ALLOW, "edge-03 dispatcher -> API (creates agent Jobs)"),
        tcp(d, "tool-read-ticket", DENY, "dispatcher never reaches a tool", 8000),
        tcp(d, "tool-gateway", DENY, "dispatcher never calls tools", 8080),
        *_everywhere_denied(d, API_CALLERS),
    ]
    r = "risk-engine"
    m += [
        tcp(r, "postgres", ALLOW, "edge-13 risk-engine -> db"),
        tcp(r, "tool-read-ticket", DENY, "risk engine never reaches a tool", 8000),
        tcp(r, "fake-dso", DENY, "not an edge"),
        *_everywhere_denied(r),
    ]
    e = "executor"
    m += [
        tcp(e, "fake-dso", ALLOW, "edge-15 executor -> fake-dso"),
        tcp(e, "fake-sms", ALLOW, "edge-15 executor -> fake-sms"),
        tcp(e, "postgres", ALLOW, "edge-14 executor -> db"),
        tcp(e, "fake-register", DENY, "only register-sync reads the register"),
        tcp(e, "tool-read-ticket", DENY, "executor never reaches a tool", 8000),
        tcp(e, "tool-gateway", DENY, "executor never calls the gateway", 8080),
        *_everywhere_denied(e),
    ]
    s = "register-sync"
    m += [
        tcp(s, "fake-register", ALLOW, "edge-16 register-sync -> fake-register"),
        tcp(s, "postgres", ALLOW, "edge-16 register-sync -> db"),
        tcp(s, "fake-dso", DENY, "not an edge"),
        *_everywhere_denied(s),
    ]
    c = "console"
    m += [
        tcp(c, "postgres", ALLOW, "edge-18 console -> db"),
        tcp(c, "tool-read-ticket", DENY, "staff never reach a tool", 8000),
        tcp(c, "tool-gateway", DENY, "staff never call the gateway", 8080),
        *_everywhere_denied(c),
    ]
    f = "fake-sms"
    m += [
        tcp(f, "postgres", DENY, "the outside systems never reach in"),
        tcp(f, "tool-gateway", DENY, "the outside systems never reach in", 8080),
        tcp(f, "fake-dso", DENY, "the outside systems never reach each other"),
        tcp(f, "dispatcher", DENY, "the outside systems never reach in", 8081),
        *_everywhere_denied(f),
    ]
    p = "postgres"
    m += [
        tcp(p, "tool-read-ticket", DENY, "the database never calls out", 8000),
        *_everywhere_denied(p),
    ]
    # Live-test only identities.
    m += [
        tcp("spoof-tool-gateway", "tool-read-ticket", DENY,
            "a pod in ah-agent labelled tool-gateway is not the gateway", 8000),
        dns("spoof-tool-gateway", CLUSTER_NAME, ALLOW, "control: the pod runs and its DNS works"),
        tcp("outside-tool-gateway", "tool-read-ticket", DENY,
            "edge-09-in names the gateway's namespace, not only its label", 8000),
        tcp("outside-tool-gateway", INTERNET, ALLOW, "control: this pod's egress is open"),
        tcp("outside-agent", "tool-gateway", DENY,
            "edge-05-in names the agent's namespace, not only its label", 8080),
        tcp("outside-agent", INTERNET, ALLOW, "control: this pod's egress is open"),
        tcp("outside", INTERNET, ALLOW, "control: the internet is reachable without the walls"),
        dns("outside", EXFIL_NAME, ALLOW, "control: CoreDNS answers outside names without the walls"),
        tcp("monitoring", "tool-gateway", ALLOW, "edge-21 ah-monitoring -> ops port", 9000),
        tcp("monitoring", "tool-read-ticket", ALLOW, "edge-21 ah-monitoring -> ops port", 9000),
        tcp("monitoring", "tool-gateway", DENY, "ah-monitoring reaches the ops port only", 8080),
        tcp("monitoring", "console", ALLOW, "edge-21 ah-monitoring -> ops port", 9000),
        tcp("outside", "stray", DENY, "default-deny: a pod no edge names takes no connection", 8092),
        tcp("stray", INTERNET, DENY, "default-deny: a pod no edge names opens no connection"),
        tcp("stray", "fake-dso", DENY, "default-deny: a pod no edge names opens no connection", 8091),
        dns("stray", CLUSTER_NAME, ALLOW, "control: the pod runs and its DNS works"),
    ]
    return m


def sources(probes: list[Probe]) -> list[str]:
    return list(dict.fromkeys(p.source for p in probes))


def placement(name: str) -> tuple[str, str, tuple[int, ...]]:
    """(namespace, label, ports) of a probe identity."""
    return COMPONENTS.get(name) or EXTRA_SOURCES[name]


def service_addresses() -> dict[str, str]:
    """Where each target is when the real chart runs: its Service name (absolute, so the
    resolver does not walk the search list), and the API server from the env Kubernetes sets."""
    addresses = {name: f"{name}.{ns}.svc.cluster.local." for name, (ns, _, _) in COMPONENTS.items()}
    host = os.environ.get("KUBERNETES_SERVICE_HOST")
    if host:
        addresses[KUBE_API] = host
    # The database: on kind the postgres Service (a cluster name every pod may resolve); on Azure
    # the private endpoint's IP address, because most pods may not resolve the server's name, and
    # a refused lookup must not stand in for the network wall.
    db = os.environ.get("AH_DB_ADDRESS")
    if db:
        addresses["postgres"] = db if db.endswith(".") or db[-1].isdigit() else f"{db}."
    return addresses


# --- the probes themselves ----------------------------------------------------------------------

TIMEOUT = 3.0
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


def try_tcp(host: str, port: int, timeout: float = TIMEOUT) -> tuple[str, str]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return ALLOW, "connected"
    except ConnectionRefusedError:
        return ALLOW, "refused (the packet got through; nothing listens)"
    except TimeoutError:
        return DENY, "timeout"
    except socket.gaierror as exc:
        return ERROR, f"name lookup failed: {exc.strerror}"
    except OSError as exc:
        return ERROR, f"{type(exc).__name__}: {exc.strerror or exc}"


def dns_query(name: str, qid: int) -> bytes:
    """A standard query (recursion desired) for the A record of an absolute name."""
    labels = [part for part in name.rstrip(".").split(".") if part]
    qname = b"".join(struct.pack("B", len(p)) + p.encode("ascii") for p in labels) + b"\x00"
    return struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + qname + struct.pack(">HH", 1, 1)


def dns_rcode(answer: bytes, qid: int) -> str:
    if len(answer) < 12:
        return "short answer"
    rid, flags = struct.unpack(">HH", answer[:4])
    if rid != qid or not flags & 0x8000:
        return "not an answer to the query"
    return RCODES.get(flags & 0x000F, f"rcode {flags & 0x000F}")


def nameserver(resolv_conf: str = "/etc/resolv.conf") -> str:
    with open(resolv_conf, encoding="ascii") as handle:
        for line in handle:
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "nameserver":
                return parts[1]
    raise RuntimeError(f"no nameserver in {resolv_conf}")


def try_dns(name: str, server: str | None = None, timeout: float = TIMEOUT, port: int = 53) -> tuple[str, str]:
    qid = secrets.randbelow(0xFFFF)
    try:
        server = server or nameserver()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(dns_query(name, qid), (server, port))
            rcode = dns_rcode(sock.recv(4096), qid)
    except TimeoutError:
        return ERROR, "timeout (no answer)"
    except OSError as exc:
        return ERROR, f"{type(exc).__name__}: {exc}"
    if rcode in ("NOERROR", "NXDOMAIN", "SERVFAIL"):
        return ALLOW, rcode
    if rcode == "REFUSED":
        return DENY, rcode
    return ERROR, rcode


def try_resolve(name: str, server: str | None = None, port: int = 53) -> tuple[str, str]:
    try:
        infos = socket.getaddrinfo(name, None, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        # glibc reports a refusal and a lost answer alike: ask the name directly to tell them apart.
        observed, rcode = try_dns(name if name.endswith(".") else f"{name}.", server=server, port=port)
        if observed == DENY:
            return DENY, f"REFUSED (getaddrinfo: {exc.strerror})"
        return ERROR, f"getaddrinfo: {exc.strerror}; direct query: {rcode}"
    return ALLOW, "resolved to " + ", ".join(sorted({i[4][0] for i in infos}))


def run_probe(probe: Probe, addresses: dict[str, str], token: str) -> dict:
    """Run one probe. addresses maps a component (or kube-apiserver) to a host; token fills
    {random} in names."""
    target = probe.target.replace(RANDOM, token)
    if probe.kind == "tcp":
        host = addresses.get(target) or SPECIAL_TARGETS.get(target, (target, 0))[0]
        observed, detail = try_tcp(host, probe.port)
    elif probe.kind == "dns":
        observed, detail = try_dns(target)
    elif probe.kind == "resolve":
        observed, detail = try_resolve(target)
    else:
        raise ValueError(f"unknown probe kind {probe.kind!r}")
    if target != probe.target:
        detail = f"{detail} ({target})"
    return {"edge": probe.edge, "source": probe.source, "kind": probe.kind, "expected": probe.expected,
            "observed": observed, "detail": detail, "why": probe.why}


def mismatches(results: list[dict]) -> list[dict]:
    """Results that differ from the expectation, or whose deny lacks the wall's signature."""
    return [r for r in results if r["observed"] != r["expected"]
            or (r["observed"] == DENY and not r["detail"].startswith(DENY_DETAIL[r["kind"]]))]
