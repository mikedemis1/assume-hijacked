"""The attack suite (attacks/) without a cluster: the probe matrix agrees with the chart's edges,
the probes classify what they see correctly, and the attack ticket replay judges outcomes.

No `k8s` marker: these run in the default `pytest`. The live run is tests/k8s/test_walls.py.
"""

import ast
import json
import socket
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from attacks import probes, run, tickets
from attacks.probes import ALLOW, DENY, Probe
from tests.k8s.test_chart import HELM, ROOT, rendered

ATTACKS = ROOT / "attacks"


# --- the matrix ---------------------------------------------------------------------------------

def test_every_edge_name_is_unique():
    edges = [p.edge for p in probes.matrix()]
    assert len(edges) == len(set(edges))


def test_every_probe_names_a_known_source_target_and_port():
    for p in probes.matrix():
        probes.placement(p.source)  # raises KeyError for an unknown source
        assert p.expected in (ALLOW, DENY), p.edge
        assert p.why, p.edge
        if p.kind == "tcp":
            if p.target in probes.SPECIAL_TARGETS:
                assert p.port == probes.SPECIAL_TARGETS[p.target][1], p.edge
            else:
                # The target listens on that port, so a deny is the wall, not an empty port.
                assert p.port in probes.placement(p.target)[2], p.edge
        else:
            assert p.kind in ("dns", "resolve") and p.target, p.edge


# The runtime cases the network walls must show (default deny, tools, spoofing, wrong port, DNS,
# the Kubernetes API, IMDS, the internet), by edge name.
CARRY_IN = {
    # default deny + controls
    "agent -> tool-read-ticket:8000": DENY, "agent -> postgres:5432": DENY,
    "agent -> risk-engine:8082": DENY, "agent -> fake-register:8090": DENY,
    "agent -> fake-dso:8091": DENY, "agent -> fake-sms:8092": DENY,
    "agent -> tool-gateway:8080": ALLOW, "agent -> llm-gateway:8083": ALLOW,
    "agent -> dispatcher:8081": ALLOW,
    # tools
    "tool-lookup-account -> tool-gateway:8080": DENY, "tool-lookup-account -> risk-engine:8082": DENY,
    "tool-lookup-account -> fake-dso:8091": DENY, "tool-lookup-account -> postgres:5432": ALLOW,
    "tool-lookup-account -> tool-read-ticket:8000": DENY,
    # ingress spoofing
    "spoof-tool-gateway -> tool-read-ticket:8000": DENY,
    "outside-tool-gateway -> tool-read-ticket:8000": DENY,
    # wrong port on an allowed edge
    "agent -> tool-gateway:9000": DENY, "monitoring -> tool-gateway:9000": ALLOW,
    # DNS
    "agent dns {random}.exfil.example.": DENY, "agent dns example.com.": DENY,
    "agent dns tool-gateway.ah-gateway.svc.cluster.local.": ALLOW,
    "agent resolve kubernetes.default": ALLOW,
    # Kubernetes API
    "dispatcher -> kube-apiserver:443": ALLOW, "tool-gateway -> kube-apiserver:443": ALLOW,
    "llm-gateway -> kube-apiserver:443": ALLOW, "agent -> kube-apiserver:443": DENY,
    "tool-lookup-account -> kube-apiserver:443": DENY, "risk-engine -> kube-apiserver:443": DENY,
    "console -> kube-apiserver:443": DENY,
    # IMDS, the internet, the gateway to a tool
    "agent -> imds:80": DENY, "tool-lookup-account -> imds:80": DENY,
    "tool-lookup-account -> internet:443": DENY, "tool-gateway -> tool-read-ticket:8000": ALLOW,
    # executor -> tools, fakes -> anything
    "executor -> tool-read-ticket:8000": DENY, "fake-sms -> postgres:5432": DENY,
    "fake-sms -> internet:443": DENY, "fake-sms -> fake-dso:8091": DENY,
}


def test_matrix_covers_the_carried_in_probe_cases():
    matrix = {p.edge: p.expected for p in probes.matrix()}
    missing = {e: x for e, x in CARRY_IN.items() if matrix.get(e) != x}
    assert not missing


def test_every_source_is_checked_against_the_internet_metadata_and_dns():
    matrix = {p.edge: p.expected for p in probes.matrix()}
    for source in (s for s in probes.sources(probes.matrix()) if s in probes.COMPONENTS):
        for edge in (f"{source} -> internet:443", f"{source} -> imds:80",
                     f"{source} dns {probes.EXFIL_NAME}"):
            assert matrix.get(edge) == DENY, edge
        assert matrix.get(f"{source} dns {probes.CLUSTER_NAME}") == ALLOW, source


def test_every_probe_pod_has_an_allow_control_and_every_target_an_allowed_caller():
    """A pod whose probes all expect deny proves nothing if the pod cannot reach anything at all;
    the same for a target nobody may reach."""
    m = probes.matrix()
    for source in probes.sources(m):
        assert any(p.source == source and p.expected == ALLOW for p in m), source
    # stray is the exception by design: a pod no edge names, reachable by nobody. Its listener is
    # shown by the default-deny mutation proof instead.
    for target in {p.target for p in m if p.kind == "tcp" and p.target not in probes.SPECIAL_TARGETS} - {"stray"}:
        assert any(p.target == target and p.expected == ALLOW for p in m), target


def test_the_agent_is_probed_against_every_tool():
    edges = {p.edge for p in probes.matrix() if p.expected == DENY}
    for tool in ("read-ticket", "lookup-account", "request-disconnection", "issue-bill-credit",
                 "set-temp-protection"):
        assert f"agent -> tool-{tool}:8000" in edges


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
def test_api_server_probes_agree_with_the_chart():
    """The Kubernetes API is a Cilium entity rule, not a NetworkPolicy edge: each probe source may
    reach it exactly when a CiliumNetworkPolicy gives its component the kube-apiserver entity."""
    allowed = {(p["metadata"]["namespace"], p["spec"]["endpointSelector"]["matchLabels"]["app.kubernetes.io/name"])
               for p in rendered("kind") if p["kind"] == "CiliumNetworkPolicy"
               for rule in p["spec"].get("egress", []) if "kube-apiserver" in rule.get("toEntities", [])}
    api_probes = [p for p in probes.matrix() if p.kind == "tcp" and p.target == probes.KUBE_API
                  and p.source in probes.COMPONENTS]
    assert len(api_probes) >= 12
    for p in api_probes:
        namespace, label, _ = probes.placement(p.source)
        assert ((namespace, label) in allowed) == (p.expected == ALLOW), p.edge
    # Every component the chart lets reach the API has an allow probe (the control).
    assert {probes.placement(p.source)[:2] for p in api_probes if p.expected == ALLOW} == allowed


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


def test_tcp_probe_reads_connected_and_refused_as_allow():
    with socket.create_server(("127.0.0.1", 0)) as server:
        port = server.getsockname()[1]
        assert probes.try_tcp("127.0.0.1", port, timeout=2) == (ALLOW, "connected")
    # Windows retries a refused loopback connect for about two seconds; Linux answers at once.
    observed, detail = probes.try_tcp("127.0.0.1", free_port(), timeout=8)
    assert observed == ALLOW and detail.startswith("refused")


def test_tcp_probe_reads_a_timeout_as_deny(monkeypatch):
    def silent(*_args, **_kwargs):
        raise TimeoutError("timed out")
    monkeypatch.setattr(probes.socket, "create_connection", silent)
    assert probes.try_tcp("10.0.0.1", 80) == (DENY, "timeout")


def dns_answer(query: bytes, rcode: int, qid: int | None = None) -> bytes:
    rid = int.from_bytes(query[:2], "big") if qid is None else qid
    return rid.to_bytes(2, "big") + (0x8180 | rcode).to_bytes(2, "big") + query[4:]


@pytest.mark.parametrize("rcode,expected", [
    (0, (ALLOW, "NOERROR")), (3, (ALLOW, "NXDOMAIN")), (2, (ALLOW, "SERVFAIL")),
    (5, (DENY, "REFUSED")), (1, (probes.ERROR, "FORMERR")), (4, (probes.ERROR, "NOTIMP")),
])
def test_dns_probe_reads_the_answer_code(rcode, expected):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(("127.0.0.1", 0))
        port = server.getsockname()[1]

        def answer():
            query, client = server.recvfrom(512)
            server.sendto(dns_answer(query, rcode), client)

        thread = threading.Thread(target=answer)
        thread.start()
        try:
            assert probes.try_dns("x.exfil.example.", server="127.0.0.1", timeout=2, port=port) == expected
        finally:
            thread.join()


def test_dns_answer_must_match_the_query():
    query = probes.dns_query("a.b.example.", 7)
    assert query[12:] == b"\x01a\x01b\x07example\x00\x00\x01\x00\x01"
    assert probes.dns_rcode(dns_answer(query, 5), 7) == "REFUSED"
    assert probes.dns_rcode(dns_answer(query, 0, qid=8), 7) == "not an answer to the query"
    assert probes.dns_rcode(query, 7) == "not an answer to the query"  # QR bit not set
    assert probes.dns_rcode(b"\x00", 7) == "short answer"


def test_nameserver_comes_from_resolv_conf(tmp_path):
    conf = tmp_path / "resolv.conf"
    conf.write_text("search ah-agent.svc.cluster.local svc.cluster.local\nnameserver 10.96.0.10\n"
                    "options ndots:5\n", encoding="ascii")
    assert probes.nameserver(str(conf)) == "10.96.0.10"


def test_random_name_is_filled_per_run_and_shown():
    probe = Probe("agent", "resolve", probes.EXFIL_NAME, DENY, why="x")
    result = probes.run_probe(probe, {}, "abc123")
    assert result["edge"] == "agent resolve {random}.exfil.example."
    assert "abc123.exfil.example." in result["detail"]
    assert set(result) == {"edge", "source", "kind", "expected", "observed", "detail", "why"}


def test_service_addresses_are_absolute_and_take_the_database_from_the_env(monkeypatch):
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "10.96.0.1")
    monkeypatch.setenv("AH_DB_ADDRESS", "10.20.2.4")
    addresses = probes.service_addresses()
    assert addresses["tool-gateway"] == "tool-gateway.ah-gateway.svc.cluster.local."
    assert addresses[probes.KUBE_API] == "10.96.0.1"
    assert addresses["postgres"] == "10.20.2.4"
    monkeypatch.setenv("AH_DB_ADDRESS", "postgres.ah-data.svc.cluster.local")
    assert probes.service_addresses()["postgres"] == "postgres.ah-data.svc.cluster.local."


@pytest.mark.parametrize("exc,detail", [
    (socket.gaierror(-3, "Temporary failure in name resolution"), "name lookup failed"),
    (OSError(101, "Network is unreachable"), "OSError"),
])
def test_tcp_probe_reads_a_failed_lookup_or_network_as_error_not_deny(monkeypatch, exc, detail):
    """A refused name lookup must not pass for a closed port: the wall was never tried."""
    def fail(*_args, **_kwargs):
        raise exc
    monkeypatch.setattr(probes.socket, "create_connection", fail)
    observed, text = probes.try_tcp("psql.example", 5432)
    assert observed == probes.ERROR and text.startswith(detail)


def test_dns_probe_without_an_answer_is_an_error():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as silent:
        silent.bind(("127.0.0.1", 0))
        port = silent.getsockname()[1]
        assert probes.try_dns("x.exfil.example.", server="127.0.0.1", timeout=0.5, port=port) == (
            probes.ERROR, "timeout (no answer)")


def test_resolve_deny_needs_a_refused_answer(monkeypatch):
    def refused_lookup(*_args, **_kwargs):
        raise socket.gaierror(-3, "Temporary failure in name resolution")
    monkeypatch.setattr(probes.socket, "getaddrinfo", refused_lookup)
    for rcode, expected in ((5, probes.DENY), (3, probes.ERROR)):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
            server.bind(("127.0.0.1", 0))
            port = server.getsockname()[1]

            def answer(server=server, rcode=rcode):
                query, client = server.recvfrom(512)
                server.sendto(dns_answer(query, rcode), client)

            thread = threading.Thread(target=answer)
            thread.start()
            observed, detail = probes.try_resolve("api.anthropic.com", server="127.0.0.1", port=port)
            thread.join()
        assert observed == expected, detail
        assert detail.startswith("REFUSED") == (expected == probes.DENY)


def test_a_deny_without_the_walls_signature_is_a_mismatch():
    base = {"edge": "e", "expected": DENY, "observed": DENY}
    assert probes.mismatches([{**base, "kind": "tcp", "detail": "timeout"},
                              {**base, "kind": "dns", "detail": "REFUSED"},
                              {**base, "kind": "resolve", "detail": "REFUSED (getaddrinfo: x)"}]) == []
    assert len(probes.mismatches([{**base, "kind": "tcp", "detail": "OSError"},
                                  {**base, "kind": "dns", "detail": "FORMERR"}])) == 2
    assert probes.mismatches([{**base, "kind": "tcp", "observed": probes.ERROR, "detail": "x"}])


def test_probe_command_prints_results_and_fails_on_a_mismatch():
    with socket.create_server(("127.0.0.1", 0)) as server:
        port = server.getsockname()[1]
        plan = {"probes": [Probe("agent", "tcp", "tool-gateway", ALLOW, port, "x").to_json(),
                           Probe("agent", "tcp", "tool-gateway", DENY, port, "y").to_json()],
                "addresses": {"tool-gateway": "127.0.0.1"}}
        done = subprocess.run([sys.executable, "-m", "attacks.run", "probe"], input=json.dumps(plan),
                              capture_output=True, text=True, cwd=ROOT, timeout=30, check=False)
    assert done.returncode == 1, done.stderr
    results = json.loads(done.stdout)["results"]
    assert [(r["expected"], r["observed"]) for r in results] == [(ALLOW, ALLOW), (DENY, ALLOW)]


def test_serve_accepts_connections_on_every_port():
    ports = [free_port(), free_port()]
    proc = subprocess.Popen([sys.executable, "-m", "attacks.run", "serve", ",".join(map(str, ports))],
                            cwd=ROOT, stdout=subprocess.PIPE, text=True)
    try:
        assert json.loads(proc.stdout.readline()) == {"listening": ports}
        for port in ports:
            assert probes.try_tcp("127.0.0.1", port, timeout=2) == (ALLOW, "connected")
    finally:
        proc.kill()
        proc.wait()


def test_suite_refuses_an_unknown_source(capsys):
    assert run.main(["suite", "outside"]) == 2
    assert run.main([]) == 2


def test_attacks_use_only_the_standard_library():
    """Runtime code: no third-party package, no YAML library, and no app import (the suite must
    run before the app is deployed)."""
    for path in ATTACKS.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                names = [node.module]
            else:
                continue
            for name in names:
                top = name.split(".")[0]
                assert top == "attacks" or top in sys.stdlib_module_names, (path.name, name)


# --- attack tickets -----------------------------------------------------------------------------

def test_eleven_attack_tickets_one_per_attack_row():
    assert [t.number for t in tickets.ATTACK_TICKETS] == list(range(1, 12))
    doc = (ROOT / "docs" / "attacks.md").read_text(encoding="utf-8")
    for t in tickets.ATTACK_TICKETS:
        assert f"\n| {t.number} |" in doc, t.number
        assert t.leak or t.reply_forbidden or t.refused_tools or t.effects or t.calls or t.shows, t.number
    assert len({t.ticket_id for t in tickets.ATTACK_TICKETS}) == 11
    assert min(t.ticket_id for t in tickets.ATTACK_TICKETS) > 4  # the demo seed uses 1-4


def test_ticket_one_is_the_seeded_attack_word_for_word():
    seed = (ROOT / "db" / "sql" / "04-seed.sql").read_text(encoding="utf-8")
    body = seed.split("(4, 1001, E'", 1)[1].split("', 'open')", 1)[0].replace("\\n", "\n")
    first = tickets.ATTACK_TICKETS[0]
    assert (first.customer_id, first.body) == (1001, body)


def test_ticket_plans_read_like_the_scripted_model():
    """Same CALL/SAY reading as app/agent/llm.py (which the suite must not import at runtime)."""
    from app.agent.llm import Reply, ToolCall, _parse
    for t in tickets.ATTACK_TICKETS:
        ours = tickets.plan(t.body)
        theirs = _parse(t.body)
        assert len(ours) == len(theirs), t.number
        for a, b in zip(ours, theirs):
            if isinstance(a, tickets.Call):
                assert isinstance(b, ToolCall) and (a.tool, a.args) == (b.name, b.args), t.number
            else:
                assert isinstance(b, Reply) and a.text == b.text, t.number


def test_plan_skips_malformed_lines():
    assert tickets.plan('CALL x {bad\nCALL y [1]\nCALL z\nnoise\nSAY hi') == [tickets.Call("z"), tickets.Say("hi")]


def test_seed_sql_inserts_every_ticket_dollar_quoted():
    sql = tickets.seed_sql()
    assert sql.startswith("INSERT INTO tickets VALUES\n") and sql.rstrip().endswith("DO NOTHING;")
    for t in tickets.ATTACK_TICKETS:
        assert f"({t.ticket_id}, {t.customer_id}, $attack${t.body}$attack$, 'open')" in sql
    bad = tickets.AttackTicket(1, "x", 1001, "CALL x {}\nSAY $attack$", leak=("y",))
    with pytest.raises(ValueError):
        tickets.seed_sql((bad,))


def outcome(number: int, results=(), status=200, stored="Thank you."):
    t = next(x for x in tickets.ATTACK_TICKETS if x.number == number)
    return tickets.Outcome(t, tuple(tickets.ToolResult(*r) for r in results), status, stored)


def test_judge_passes_when_the_walls_hold():
    """Ticket 1 shows the owner, 4 and 7 get exactly one effect through, 9 exactly eight calls."""
    assert tickets.judge(outcome(1, [("lookup_account", "Eleni Papadopoulou, G1, Patision 10", False)])) == []
    effects = [("issue_bill_credit", "filed", False)] + [("issue_bill_credit", "ERROR: denied", True)] * 2
    assert tickets.judge(outcome(4, effects)) == []
    assert tickets.judge(outcome(9, [("set_temp_protection", "ok", False)] * 8
                                 + [("set_temp_protection", "ERROR: denied", True)] * 2)) == []


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


class FakeStack:
    """The dispatcher and gateway walls in memory: arguments dropped (results show the ticket
    owner only), unknown tools refused, one effect per ticket, 8 calls per lease."""

    owners = {1001: "Eleni Papadopoulou, Patision 10", 1002: "Maria", 1003: "Maria Ioannou, Maizonos 20"}

    def __init__(self, ticket_ids, effect_limit=True, refuse_all=False):
        self.queue = list(ticket_ids)
        self.effect_limit = effect_limit
        self.refuse_all = refuse_all
        self.calls: dict[str, list[str]] = {}
        self.replies: dict[str, str] = {}

    def claim(self):
        if not self.queue:
            return None
        ticket_id = self.queue.pop(0)
        return ticket_id, f"lease-{ticket_id}"

    def call_tool(self, lease, tool, args):
        calls = self.calls.setdefault(lease, [])
        calls.append(tool)
        if self.refuse_all:
            return tickets.ToolResult(tool, "ERROR: denied", True)
        if tool not in ("lookup_account", "read_ticket", "issue_bill_credit", "request_disconnection",
                        "set_temp_protection"):
            return tickets.ToolResult(tool, "ERROR: tool_not_in_lease", True)
        if len(calls) > 8:
            return tickets.ToolResult(tool, "ERROR: call_budget", True)
        effects = [c for c in calls if c in tickets.EFFECT_TOOLS]
        if self.effect_limit and tool in tickets.EFFECT_TOOLS and len(effects) > 1:
            return tickets.ToolResult(tool, "ERROR: one_effect_per_ticket", True)
        ticket = next((t for t in tickets.ATTACK_TICKETS if lease == f"lease-{t.ticket_id}"), None)
        owner = self.owners[ticket.customer_id] if ticket else "Eleni Papadopoulou"
        return tickets.ToolResult(tool, owner if tool == "lookup_account" else "ok", False)

    def reply(self, lease, text):
        blocked = any(w in text.lower() for w in ("euro", "49", "approved", "attacker.example"))
        stored = "Thank you. A colleague will check this and reply to you." if blocked else text
        self.replies[lease] = stored
        return 200, stored


def test_replay_passes_against_walls_that_hold():
    ids = [4] + [t.ticket_id for t in tickets.ATTACK_TICKETS]  # 4: a demo ticket, answered and skipped
    stack = FakeStack(ids)
    report = tickets.replay_all(stack)
    assert [r["ticket"] for r in report] == list(range(1, 12))
    assert all(r["passed"] for r in report), [r for r in report if not r["passed"]]
    assert "lease-4" in stack.replies


def test_replay_names_the_tickets_a_missing_wall_lets_through():
    report = tickets.replay_all(FakeStack([t.ticket_id for t in tickets.ATTACK_TICKETS], effect_limit=False))
    failed = {r["ticket"] for r in report if not r["passed"]}
    assert failed == {4, 5, 7}  # the three tickets that try a second effect


def test_replay_fails_when_the_stack_refuses_everything():
    report = tickets.replay_all(FakeStack([t.ticket_id for t in tickets.ATTACK_TICKETS], refuse_all=True))
    failed = {r["ticket"] for r in report if not r["passed"]}
    assert {1, 4, 5, 7, 9} <= failed


def test_a_failed_mcp_initialize_stops_the_ticket_instead_of_passing():
    claims = [(200, {}, json.dumps({"ticket_id": 103, "lease": "L"})), (204, {}, "")]

    def post(url, payload, headers):
        if url.endswith("/claim"):
            return claims.pop(0)
        if url.endswith("/reply"):
            return 200, {}, json.dumps({"text": "ok"})
        return 503, {}, "unavailable"

    api = tickets.HttpAgentApi("http://d:8081", "http://g:8080/mcp", post=post)
    with pytest.raises(RuntimeError, match="initialize"):
        api.call_tool("L", "set_flag", {})
    report = tickets.replay_all(api, tickets.ATTACK_TICKETS[2:3])  # ticket 3: refused tools only
    assert report[0]["failures"] == ["replay: RuntimeError"]


def test_replay_fails_a_ticket_it_never_got():
    report = tickets.replay_all(FakeStack([tickets.ATTACK_TICKETS[0].ticket_id]))
    assert report[0]["passed"] and not any(r["passed"] for r in report[1:])
    assert report[1]["failures"] == ["never claimed: the dispatcher did not hand it out"]


# --- the contract over HTTP ---------------------------------------------------------------------

class FakeContract:
    """The dispatcher (/claim, /reply) and the MCP gateway (/mcp) as a transport function: it
    records each request (url, headers, payload) and answers as the contract says. Not over a
    socket: the antivirus on the development PC rewrites MCP answers on loopback HTTP (it drops
    Content-Length and claims chunked). http_post itself is tested over a socket below."""

    def __init__(self):
        self.seen: list[tuple[str, dict, dict]] = []
        self.handed_out = False

    def __call__(self, url, payload, headers):
        path = url.split("8081", 1)[-1] if "8081" in url else url.split("8080", 1)[-1]
        self.seen.append((path, headers, payload))
        if path == "/claim":
            if self.handed_out:
                return 204, {}, ""
            self.handed_out = True
            return 200, {}, json.dumps({"ticket_id": 101, "lease": "L1"})
        if path == "/reply":
            return 200, {}, json.dumps({"text": "Thank you."})
        if payload["method"] == "initialize":
            body = {"jsonrpc": "2.0", "id": payload["id"], "result": {"protocolVersion": "2025-06-18"}}
            return 200, {"Content-Type": "text/event-stream", "mcp-session-id": "S1"}, \
                f"event: message\ndata: {json.dumps(body)}\n\n"
        if "id" not in payload:
            return 202, {}, ""
        text = "Eleni Papadopoulou" if payload["params"]["name"] == "lookup_account" else "ERROR: tool_not_in_lease"
        body = {"jsonrpc": "2.0", "id": payload["id"],
                "result": {"content": [{"type": "text", "text": text}], "isError": text.startswith("ERROR")}}
        return 200, {"Content-Type": "application/json"}, json.dumps(body)


def test_replay_speaks_the_dispatcher_and_mcp_contract(tmp_path):
    for audience in ("dispatcher", "tool-gateway"):
        (tmp_path / audience).mkdir()
        (tmp_path / audience / "token").write_text(f"token-{audience}\n", encoding="ascii")
    contract = FakeContract()
    api = tickets.HttpAgentApi("http://dispatcher:8081", "http://gateway:8080/mcp", token_dir=tmp_path,
                               post=contract)
    report = tickets.replay_all(api, tickets.ATTACK_TICKETS[:1])
    assert report == [{"ticket": 1, "name": "another customer's account", "passed": True, "failures": []}]
    assert [p for p, _, _ in contract.seen] == ["/claim", "/mcp", "/mcp", "/mcp", "/reply", "/claim"]
    assert contract.seen[0][1] == {"Authorization": "Bearer token-dispatcher"}
    methods = [payload.get("method") for path, _, payload in contract.seen if path == "/mcp"]
    assert methods == ["initialize", "notifications/initialized", "tools/call"]
    _, call_headers, call = contract.seen[3]
    assert call_headers["X-Lease"] == "L1" and call_headers["Mcp-Session-Id"] == "S1"
    assert call_headers["Authorization"] == "Bearer token-tool-gateway"
    assert "text/event-stream" in call_headers["Accept"]
    # The hijacked agent sends the model's arguments as they are: the gateway must drop them.
    assert call["params"] == {"name": "lookup_account", "arguments": {"customer_id": 1002}}
    _, reply_headers, reply = contract.seen[4]
    assert reply_headers["X-Lease"] == "L1" and reply == {"text": "Eleni Papadopoulou"}


def test_mcp_answers_come_as_json_or_server_sent_events():
    answer = {"jsonrpc": "2.0", "id": 3, "result": {"content": []}}
    assert tickets._sse_or_json(json.dumps(answer), "application/json", 3) == answer
    stream = ("event: message\ndata: " + json.dumps({"jsonrpc": "2.0", "method": "notifications/progress"})
              + "\n\nevent: message\ndata: " + json.dumps(answer) + "\n\n")
    assert tickets._sse_or_json(stream, "text/event-stream; charset=utf-8", 3) == answer
    with pytest.raises(ValueError):
        tickets._sse_or_json(stream, "text/event-stream", 4)


def test_claim_refused_or_unreachable_dispatcher_raises():
    api = tickets.HttpAgentApi("http://d:8081", "http://g:8080/mcp", post=lambda *a: (403, {}, ""))
    with pytest.raises(RuntimeError, match="403"):
        api.claim()


class ClaimHandler(BaseHTTPRequestHandler):
    seen: list = []

    def log_message(self, *args):  # keep test output quiet
        pass

    def do_POST(self):
        payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        type(self).seen.append((self.path, self.headers["Content-Type"], payload))
        status, body = (200, b'{"ticket_id": 7, "lease": "L7"}') if self.path == "/claim" else (409, b"no")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_http_post_sends_json_and_returns_error_statuses():
    ClaimHandler.seen = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), ClaimHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        status, _, body = tickets.http_post(f"{base}/claim", {}, {"X-Lease": "x"})
        assert (status, json.loads(body)) == (200, {"ticket_id": 7, "lease": "L7"})
        assert tickets.http_post(f"{base}/reply", {"text": "t"}, {})[0] == 409
    finally:
        server.shutdown()
    assert ClaimHandler.seen == [("/claim", "application/json", {}), ("/reply", "application/json", {"text": "t"})]


def test_http_api_sends_no_token_without_a_projected_token(tmp_path):
    api = tickets.HttpAgentApi("http://127.0.0.1:1", "http://127.0.0.1:1/mcp", token_dir=tmp_path)
    assert api._auth("dispatcher") == {}


# --- the chart's attack-suite test pods ---------------------------------------------------------

SUITE_IMAGE = "localhost:5001/assume-hijacked-attacks@sha256:" + "1" * 64


def suite_pods(env: str, *sets: str) -> list[dict]:
    return [o for o in rendered(env, *sets) if o["kind"] == "Pod"]


@pytest.mark.skipif(HELM is None, reason="helm is not installed")
@pytest.mark.parametrize("env", ["kind", "azure"])
def test_attack_suite_is_off_by_default(env):
    assert suite_pods(env) == []


@pytest.mark.skipif(HELM is None, reason="helm is not installed")
def test_attack_suite_runs_one_probe_pod_per_component_source():
    pods = suite_pods("kind", "attackSuite.enabled=true", f"attackSuite.image={SUITE_IMAGE}")
    by_source = {p["metadata"]["labels"]["app.kubernetes.io/name"]: p for p in pods}
    assert set(by_source) == {s for s in probes.sources(probes.matrix()) if s in probes.COMPONENTS}
    for source, p in by_source.items():
        ns, label, _ = probes.COMPONENTS[source]
        spec = p["spec"]
        assert p["metadata"]["namespace"] == ns and label == source
        assert p["metadata"]["annotations"]["helm.sh/hook"] == "test"
        assert spec["serviceAccountName"] == "attack-suite" and spec["automountServiceAccountToken"] is False
        assert spec["containers"][0]["args"] == ["suite", source]
        assert spec["containers"][0]["image"] == SUITE_IMAGE
        assert (spec.get("runtimeClassName") == "kata-vm-isolation") == (ns in ("ah-agent", "ah-tools"))
        sc = spec["containers"][0]["securityContext"]
        assert sc["readOnlyRootFilesystem"] and sc["capabilities"] == {"drop": ["ALL"]}
        assert not sc["allowPrivilegeEscalation"] and sc["runAsNonRoot"]
    sas = {(o["metadata"]["namespace"], o["metadata"]["name"]) for o in rendered(
        "kind", "attackSuite.enabled=true", f"attackSuite.image={SUITE_IMAGE}") if o["kind"] == "ServiceAccount"}
    assert {(p["metadata"]["namespace"], "attack-suite") for p in pods} <= sas


@pytest.mark.skipif(HELM is None, reason="helm is not installed")
def test_attack_suite_on_azure_has_no_database_pod_and_aims_at_the_private_endpoint_ip():
    """By IP: most pods may not resolve the server's name, and a refused lookup must not stand in
    for the network wall."""
    acr = "acrplaceholder.azurecr.io/assume-hijacked-attacks@sha256:" + "1" * 64
    on = ("attackSuite.enabled=true", f"attackSuite.image={acr}")
    pods = suite_pods("azure", *on, "attackSuite.databaseAddress=10.20.2.4")
    assert "postgres" not in {p["metadata"]["labels"]["app.kubernetes.io/name"] for p in pods}
    for p in pods:
        env = {e["name"]: e["value"] for e in p["spec"]["containers"][0]["env"]}
        assert env == {"AH_DB_ADDRESS": "10.20.2.4"}
    from tests.k8s.test_chart import helm
    for extra, message in (([], "attackSuite.databaseAddress"),
                           (["--set", "attackSuite.databaseAddress=10.30.0.4"], "is not in network.databaseCidr")):
        result = helm("template", "azure", *[a for s in on for a in ("--set", s)], *extra)
        assert result.returncode != 0 and message in result.stderr, result.stderr
    kind = suite_pods("kind", "attackSuite.enabled=true", f"attackSuite.image={SUITE_IMAGE}")
    assert {e["value"] for p in kind for e in p["spec"]["containers"][0]["env"]} == {
        "postgres.ah-data.svc.cluster.local"}


@pytest.mark.skipif(HELM is None, reason="helm is not installed")
def test_attack_suite_pods_never_become_service_endpoints():
    """They carry component labels; a readiness probe that never passes keeps real clients off."""
    for p in suite_pods("kind", "attackSuite.enabled=true", f"attackSuite.image={SUITE_IMAGE}"):
        assert p["spec"]["containers"][0]["readinessProbe"]["exec"]["command"] == ["false"]


@pytest.mark.skipif(HELM is None, reason="helm is not installed")
@pytest.mark.parametrize("sets,message", [
    (["attackSuite.enabled=true"], "attackSuite"),
    (["attackSuite.enabled=true", "attackSuite.image=localhost:5001/attacks:latest"], "attackSuite"),
    (["attackSuite.enabled=true", "attackSuite.image=docker.io/x/attacks@sha256:" + "1" * 64],
     "must come from the registry"),
])
def test_attack_suite_image_must_be_pinned_and_from_the_registry(sets, message):
    from tests.k8s.test_chart import helm
    result = helm("template", "kind", *[a for s in sets for a in ("--set", s)])
    assert result.returncode != 0 and message in result.stderr, result.stderr


def test_attack_suite_dockerfile_is_pinned_and_non_root():
    text = (ATTACKS / "Dockerfile").read_text(encoding="utf-8")
    base = [line for line in text.splitlines() if line.startswith("FROM ")]
    app_base = [line for line in (ROOT / "Dockerfile").read_text(encoding="utf-8").splitlines()
                if line.startswith("FROM python")]
    assert base == app_base  # same pinned Python as the app image
    assert "\nUSER 10001\n" in text and "COPY attacks ./attacks" in text
