"""Smoke tests against the running Compose stack (`docker compose up -d`, then `pytest -m smoke`).

They run the real agent container and look at what the real tool containers and network do.
"""

import functools
import itertools
import json
import os
import re
import subprocess
import time
from pathlib import Path

import psycopg
import pytest

from tests.conftest import TOOLS

pytestmark = pytest.mark.smoke

ROOT = Path(__file__).resolve().parent.parent


@functools.cache
def control_image():
    """The control container runs the pinned Python image (tag and digest) from ci/lib.sh, the
    same image the app is built on, never a bare tag that could move. Read when a test needs it,
    not at import: mutmut collects this module from its mutants/ copy, which has no ci/ folder."""
    lib = (ROOT / "ci" / "lib.sh").read_text(encoding="utf-8")
    return re.search(r'^PYTHON_IMAGE="([^"]+)"', lib, re.M).group(1)


# Values of CI that mean "not in CI". Anything else (true, 1, yes) counts as CI.
CI_OFF = ("", "0", "false", "False", "no")

TOOL_HOSTS = [
    "tool-read-ticket",
    "tool-lookup-account",
    "tool-request-disconnection",
    "tool-issue-bill-credit",
    "tool-set-temp-protection",
]

# Runs inside the agent container: wait (at most 30 s) until every tool accepts connections.
WAIT_FOR_TOOLS = """
import socket, sys, time
deadline = time.monotonic() + 30
for host in {hosts!r}:
    while True:
        try:
            socket.create_connection((host, 8000), timeout=2).close()
            break
        except OSError as err:
            if time.monotonic() > deadline:
                sys.exit(f"{{host}} does not accept connections: {{err}}")
            time.sleep(1)
"""

# Runs inside a container: open a TCP connection to a public address (no DNS, no TLS involved).
# Exit 0 = the internet answered, 3 = it could not be reached.
# Not an HTTPS request on purpose: antivirus HTTPS scanning (or a missing CA) makes the TLS step fail
# even when the network is open, and the test would pass without proving anything.
TRY_INTERNET = """
import socket, sys
try:
    socket.create_connection(("1.1.1.1", 443), timeout=5).close()
except OSError as err:
    print("BLOCKED", type(err).__name__, err)
    sys.exit(3)
print("REACHED")
"""

# Same idea for DNS: a name lookup is a way to carry data out (the name itself is the message).
TRY_DNS = """
import socket, sys
try:
    address = socket.gethostbyname("example.com")
except OSError as err:
    print("BLOCKED", type(err).__name__, err)
    sys.exit(3)
print("REACHED", address)
"""

# Runs inside a container: try a TCP connection to every target at once and print one line each,
# REACHED or BLOCKED. Always exits 0, so a crashed script (non-zero) is not mistaken for "blocked".
# A name that does not resolve counts as blocked: on an internal edge network Docker only knows
# the peers on that network.
TRY_TCP = """
import socket
from concurrent.futures import ThreadPoolExecutor

def attempt(target):
    host, port = target
    try:
        socket.create_connection((host, port), timeout=3).close()
    except OSError as err:
        return f"BLOCKED {{host}}:{{port}} {{type(err).__name__}}"
    return f"REACHED {{host}}:{{port}}"

with ThreadPoolExecutor(8) as pool:
    for line in pool.map(attempt, {targets!r}):
        print(line)
"""

# The stand-ins for the outside systems, and their HTTP ports.
FAKE_PORTS = {"fake-register": 8090, "fake-dso": 8091, "fake-sms": 8092}

# Every service on an internal network except the db (which is also on hostaccess on purpose).
WALLED_SERVICES = [*TOOL_HOSTS, "executor", "risk-engine", "register-sync", *FAKE_PORTS, "agent"]

DB_PORT = 5432  # inside the stack; the published host port is DB_HOST_PORT
DB_HOST_PORT = int(os.environ.get("DB_PORT", "5432"))
TOOL_PORT = 8000


def compose(*args, timeout=300, env=None):
    # check=False: when something fails, the assert message shows stderr instead of a bare traceback.
    return subprocess.run(
        ["docker", "compose", *args], capture_output=True, text=True, timeout=timeout, check=False, env=env
    )


def open_stack_lease(ticket_id):
    """A lease for the ticket in the stack database. The dispatcher's job once it exists (task A9);
    until then the test opens it as the database admin, over the published port."""
    with psycopg.connect(
        host=os.environ.get("DB_HOST", "127.0.0.1"),
        port=DB_HOST_PORT,
        dbname="supplier",
        user="postgres",
        password=os.environ["POSTGRES_PASSWORD"],
        autocommit=True,
    ) as conn:
        return conn.execute("SELECT open_lease(%s, %s, NULL)", (ticket_id, list(TOOLS))).fetchone()[0]


def run_agent(ticket_id):
    # `-e AGENT_LEASE` with no value: Compose takes it from this process's environment, so the
    # lease is not on any command line.
    env = {**os.environ, "AGENT_LEASE": open_stack_lease(ticket_id)}
    done = compose(
        "run", "--rm", "-e", "AGENT_LEASE", "agent", "python", "-m", "app.agent.main", str(ticket_id), env=env
    )
    assert done.returncode == 0, f"agent exited {done.returncode}\nstdout: {done.stdout}\nstderr: {done.stderr}"
    return done


@pytest.fixture(scope="module", autouse=True)
def tools_are_up():
    done = compose("run", "--rm", "agent", "python", "-c", WAIT_FOR_TOOLS.format(hosts=TOOL_HOSTS))
    assert done.returncode == 0, f"tools not ready\nstdout: {done.stdout}\nstderr: {done.stderr}"


def test_agent_container_answers_a_ticket():
    assert "Eleni Papadopoulou" in run_agent(1).stdout


def test_attack_ticket_through_the_real_stack_leaks_nothing_and_is_logged():
    done = run_agent(4)  # ticket 4 asks for customer 1002 with a customer_id argument
    assert "Eleni Papadopoulou" in done.stdout, done.stderr
    assert "Nikos" not in done.stdout, done.stderr
    dropped = [e for e in security_events(done.stderr) if e["kind"] == "dropped_argument"]
    assert dropped, f"no dropped_argument event on stderr:\n{done.stderr}"
    assert "customer_id" in json.dumps(dropped), dropped


# Runs inside the agent container, which holds the signing key for now and reaches every tool: send
# the tool one request each way and print the status codes as JSON.
TOKEN_CHECKS = """
import json, os, time, urllib.error, urllib.request
from app.security.tokens import load_private_key, mint_tool_token

key = load_private_key(os.environ["GATEWAY_SIGNING_KEY_FILE"])
host, tool = {host!r}, {tool!r}
lease = "ab" * 32

def post(token=None):
    request = urllib.request.Request(
        f"http://{{host}}:8000/mcp",
        data=json.dumps({{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}}).encode(),
        headers={{"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}},
    )
    if token:
        request.add_header("Authorization", "Bearer " + token)
    try:
        return urllib.request.urlopen(request, timeout=10).status
    except urllib.error.HTTPError as err:
        return err.code

now = time.time()
good = mint_tool_token(key, tool, lease, now)
print(json.dumps({{
    "no_token": post(),
    "garbage": post("not.a.token"),
    "wrong_audience": post(mint_tool_token(key, "read_ticket" if tool != "read_ticket" else "lookup_account", lease, now)),
    "expired": post(mint_tool_token(key, tool, lease, now - 120)),
    "good": post(good),
    "replay": post(good),
}}))
"""


@pytest.mark.parametrize("tool, host", list(zip(TOOLS, TOOL_HOSTS)))
def test_a_tool_container_accepts_one_good_token_and_refuses_everything_else(tool, host):
    done = compose("run", "--rm", "agent", "python", "-c", TOKEN_CHECKS.format(host=host, tool=tool), timeout=120)
    assert done.returncode == 0, f"stdout: {done.stdout}\nstderr: {done.stderr}"
    assert json.loads(done.stdout.strip().splitlines()[-1]) == {
        "no_token": 401, "garbage": 401, "wrong_audience": 401, "expired": 401, "good": 200, "replay": 401,
    }


def secret_files(service):
    done = compose("exec", "-T", service, "ls", "/run/secrets", timeout=60)
    return sorted(done.stdout.split()) if done.returncode == 0 else []


@pytest.mark.parametrize("host", TOOL_HOSTS)
def test_a_tool_container_holds_the_public_key_and_not_the_signing_key(host):
    assert secret_files(host) == ["gateway_public_key"]


@pytest.mark.parametrize("service", ["executor", "risk-engine", "register-sync", "db", *FAKE_PORTS])
def test_no_other_container_holds_a_gateway_key(service):
    assert secret_files(service) == []


def security_events(stderr):
    """The JSON event lines in stderr. Compose adds its own lines there; anything that is not a
    JSON object with a "kind" is skipped."""
    events = []
    for line in stderr.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if isinstance(event, dict) and "kind" in event:
            events.append(event)
    return events


def no_proof(reason):
    """The control could not connect, so a blocked result would prove nothing. On CI that must not
    pass quietly; on a developer PC (offline, image not pulled) it is shown as a skip."""
    if os.environ.get("CI", "") not in CI_OFF:
        pytest.fail(reason)
    pytest.skip(reason)


@functools.cache
def control_result(script):
    """Run the script in a container on Docker's normal network. Returns None if it got through,
    otherwise the reason it did not."""
    try:
        done = subprocess.run(
            ["docker", "run", "--rm", control_image(), "python", "-c", script],
            capture_output=True, text=True, timeout=120, check=False,
        )
    except subprocess.TimeoutExpired:
        return "the control container timed out"
    if done.returncode != 0:
        return f"the control container exited {done.returncode}: {done.stdout}{done.stderr}"
    return None


def probe(service, script):
    if service == "agent":  # not running by itself: start a one-off container on its network
        return compose("run", "--rm", "agent", "python", "-c", script, timeout=120)
    return compose("exec", "-T", service, "python", "-c", script, timeout=60)


@pytest.mark.parametrize("service", WALLED_SERVICES)
def test_no_outbound_connection_from_the_walled_services(service):
    failure = control_result(TRY_INTERNET)  # a normal container must get through, or "blocked" means nothing
    if failure:
        no_proof(f"no internet from a normal container, cannot prove the wall: {failure}")
    done = probe(service, TRY_INTERNET)
    assert done.returncode == 3 and "BLOCKED" in done.stdout, (
        f"expected the outbound connection from {service} to fail (exit 3), got {done.returncode}\n"
        f"stdout: {done.stdout}\nstderr: {done.stderr}"
    )


@pytest.mark.parametrize("service", WALLED_SERVICES)
def test_no_external_dns_from_the_walled_services(service):
    failure = control_result(TRY_DNS)
    if failure:
        no_proof(f"a normal container cannot resolve example.com, cannot prove the wall: {failure}")
    done = probe(service, TRY_DNS)
    assert done.returncode == 3 and "BLOCKED" in done.stdout, (
        f"expected the name lookup from {service} to fail (exit 3), got {done.returncode}\n"
        f"stdout: {done.stdout}\nstderr: {done.stderr}"
    )


# --- Network edges (compose.yaml): a service is on the networks of its allowed edges only ---------

def container_ips(service):
    """Every IP address of the service's running container, one per network it is on."""
    done = compose("ps", "-q", service)
    container = done.stdout.strip()
    assert done.returncode == 0 and container, f"{service} is not running\n{done.stderr}"
    inspect = subprocess.run(
        ["docker", "inspect", "--format", "{{json .NetworkSettings.Networks}}", container],
        capture_output=True, text=True, timeout=60, check=False,
    )
    assert inspect.returncode == 0, inspect.stderr
    ips = [net["IPAddress"] for net in json.loads(inspect.stdout).values() if net["IPAddress"]]
    assert ips, f"{service} has no IP address"
    return ips


def try_tcp(source, targets):
    """Connect from `source` to each (host, port). Returns {target: True if it connected}."""
    done = probe(source, TRY_TCP.format(targets=list(targets)))
    assert done.returncode == 0, f"probe from {source} failed\nstdout: {done.stdout}\nstderr: {done.stderr}"
    reached = {}
    for line in done.stdout.splitlines():
        verdict, _, rest = line.partition(" ")
        if verdict in ("REACHED", "BLOCKED"):
            host, _, port = rest.split(" ")[0].rpartition(":")
            reached[(host, int(port))] = verdict == "REACHED"
    assert set(reached) == set(targets), f"probe output does not cover every target:\n{done.stdout}"
    return reached


def service_targets(service, port):
    """The service by name and by each of its IPs: the name tests Docker's DNS, the IPs test the route."""
    return [(service, port), *((ip, port) for ip in container_ips(service))]


def assert_blocked(source, targets):
    reached = try_tcp(source, targets)
    open_ = [f"{host}:{port}" for (host, port), ok in reached.items() if ok]
    assert not open_, f"{source} reached {open_}; it must have no route to these"


def test_agent_cannot_reach_db_on_any_ip():
    # The db is on eight networks, so eight IPs. The agent shares none of them.
    targets = [*service_targets("db", DB_PORT), ("host.docker.internal", DB_HOST_PORT)]
    assert len(targets) > 3, targets
    assert_blocked("agent", targets)


TOOL_PAIRS = list(itertools.permutations(TOOL_HOSTS, 2))


@pytest.mark.parametrize("source,target", TOOL_PAIRS, ids=[f"{s}->{t}" for s, t in TOOL_PAIRS])
def test_tool_cannot_reach_other_tools(source, target):
    assert_blocked(source, service_targets(target, TOOL_PORT))


@pytest.mark.parametrize("tool", TOOL_HOSTS)
def test_executor_cannot_reach_tools(tool):
    assert_blocked("executor", service_targets(tool, TOOL_PORT))


@pytest.mark.parametrize("tool", TOOL_HOSTS)
def test_risk_engine_cannot_reach_tools(tool):
    # Its only edge today is the db (edge_risk_db); the gateway edge comes with task A8.
    assert_blocked("risk-engine", service_targets(tool, TOOL_PORT))


@pytest.mark.parametrize("tool", TOOL_HOSTS)
def test_register_sync_cannot_reach_tools(tool):
    # Its edges are the db and the register; nothing else.
    assert_blocked("register-sync", service_targets(tool, TOOL_PORT))


@pytest.mark.parametrize("fake", FAKE_PORTS)
def test_fakes_cannot_reach_db(fake):
    # A fake stands for a system outside the company: it gets no route to the database.
    assert_blocked(fake, [*service_targets("db", DB_PORT), ("host.docker.internal", DB_HOST_PORT)])


FAKE_TARGETS = [(fake, port) for fake, port in FAKE_PORTS.items()]


@pytest.mark.parametrize("source", ["agent", *TOOL_HOSTS, "risk-engine"])
def test_only_their_callers_reach_the_fakes(source):
    # A hijacked agent or tool cannot send an order to the grid operator or a text to an occupier
    # by itself: only the executor reaches the DSO and SMS fakes, only register-sync the register.
    assert_blocked(source, [t for fake, port in FAKE_TARGETS for t in service_targets(fake, port)])


FAKE_PAIRS = list(itertools.permutations(FAKE_PORTS, 2))


@pytest.mark.parametrize("source,target", FAKE_PAIRS, ids=[f"{s}->{t}" for s, t in FAKE_PAIRS])
def test_fakes_cannot_reach_each_other(source, target):
    assert_blocked(source, service_targets(target, FAKE_PORTS[target]))


# The controls: the same ports on the edges that ARE allowed. Without these, "blocked" above could
# just mean the service was down or the probe was broken.
ALLOWED_EDGES = {
    "agent": [(tool, TOOL_PORT) for tool in TOOL_HOSTS],
    **{tool: [("db", DB_PORT)] for tool in TOOL_HOSTS},
    "executor": [("db", DB_PORT), ("fake-dso", FAKE_PORTS["fake-dso"]), ("fake-sms", FAKE_PORTS["fake-sms"])],
    "risk-engine": [("db", DB_PORT)],
    "register-sync": [("db", DB_PORT), ("fake-register", FAKE_PORTS["fake-register"])],
}


@pytest.mark.parametrize("source", list(ALLOWED_EDGES))
def test_allowed_edges_connect(source):
    reached = try_tcp(source, ALLOWED_EDGES[source])
    assert all(reached.values()), f"{source} must reach its own peers: {reached}"


def test_ip_probe_reaches_the_allowed_db_address_and_no_other():
    # The executor shares exactly one network with the db, so exactly one of the db's IPs answers.
    # That shows the probe works by IP, so the agent result above is not a probe that never connects.
    reached = try_tcp("executor", [(ip, DB_PORT) for ip in container_ips("db")])
    assert sum(reached.values()) == 1, reached


# --- The risk engine in the stack (task A5) ---

def stack_db():
    return psycopg.connect(
        host=os.environ.get("DB_HOST", "127.0.0.1"),
        port=DB_HOST_PORT,
        dbname="supplier",
        user="postgres",
        password=os.environ["POSTGRES_PASSWORD"],
        autocommit=True,
    )


def test_pending_credit_is_assessed_by_the_risk_engine_and_credited_by_the_executor():
    # A duplicate charge of one cent, new each run (the stack database keeps earlier runs' credits,
    # and one cent keeps the monthly limit far away). Filed as the tool function would file it.
    with stack_db() as conn:
        first = conn.execute("SELECT coalesce(max(id), 0) + 1 FROM charges").fetchone()[0]
        conn.execute(
            "INSERT INTO charges VALUES (%s, 2, 'smoke', 0.01), (%s, 2, 'smoke', 0.01)", (first, first + 1)
        )
        rid = conn.execute(
            "INSERT INTO action_requests (kind, ticket_id, account_id, amount_eur, reason, evidence_ref) "
            "VALUES ('credit', 2, 2, 0.01, 'duplicate_charge', %s) RETURNING id",
            (first + 1,),
        ).fetchone()[0]
        deadline = time.monotonic() + 60  # the engine polls every 2 s, the executor every 5 s
        row = None
        while time.monotonic() < deadline:
            row = conn.execute(
                "SELECT r.status, a.tier, a.actor FROM action_requests r "
                "LEFT JOIN risk_assessments a ON a.request_id = r.id WHERE r.id = %s",
                (rid,),
            ).fetchone()
            if row[0] != "pending":
                break
            time.sleep(1)
    assert row == ("executed", "T0", "risk_engine"), row


DECIDE_FROM_INSIDE = """
import json, urllib.request, urllib.error
body = json.dumps({"lease": "0" * 64, "tool": "read_ticket"}).encode()
request = urllib.request.Request("http://127.0.0.1:8082/decide", data=body,
                                 headers={"Content-Type": "application/json"})
print(urllib.request.urlopen(request, timeout=5).read().decode())
print(urllib.request.urlopen("http://127.0.0.1:9000/healthz", timeout=5).status)
"""


def test_risk_engine_serves_decide_and_healthz():
    # Nothing can reach it yet (the gateway edge is task A8), so the probe runs inside its container.
    done = compose("exec", "-T", "risk-engine", "python", "-c", DECIDE_FROM_INSIDE, timeout=60)
    assert done.returncode == 0, f"stdout: {done.stdout}\nstderr: {done.stderr}"
    answer, health = done.stdout.strip().splitlines()
    assert json.loads(answer) == {"decision": "deny", "reasons": ["lease"]}
    assert health == "200"


# --- register-sync and the fakes in the stack ---

def wait_for(conn, query, args, done, seconds=60):
    """Run the query every second until done(row) or the time is up. Returns the last row."""
    deadline = time.monotonic() + seconds
    row = None
    while time.monotonic() < deadline:
        row = conn.execute(query, args).fetchone()
        if done(row):
            break
        time.sleep(1)
    return row


def test_register_sync_keeps_the_register_fresh():
    with stack_db() as conn:
        row = wait_for(
            conn,
            "SELECT (SELECT last_success > now() - interval '2 minutes' FROM register_sync WHERE id = 1), "
            "       (SELECT last_beat > now() - interval '2 minutes' FROM heartbeats WHERE component = 'register-sync'), "
            "       (SELECT source FROM flags WHERE supply_point_id = 'SP-1003')",
            (),
            lambda r: r[0] and r[1],
        )
    assert row == (True, True, "state_register"), row


CALLS_FROM_INSIDE = """
import json, urllib.request
print(urllib.request.urlopen("http://127.0.0.1:{port}/calls", timeout=5).read().decode())
"""


def fake_calls(fake):
    done = compose("exec", "-T", fake, "python", "-c", CALLS_FROM_INSIDE.format(port=FAKE_PORTS[fake]), timeout=60)
    assert done.returncode == 0, f"stdout: {done.stdout}\nstderr: {done.stderr}"
    return json.loads(done.stdout)["calls"]


def stack_moveout_limit():
    """The risk engine's flood limit (MOVEOUT_MAX_PER_HOUR) as the running container sees it."""
    script = "from app import config; print(config.load().moveout_max_per_hour)"
    done = compose("exec", "-T", "risk-engine", "python", "-c", script, timeout=60)
    assert done.returncode == 0, done.stderr
    return int(done.stdout.strip())


def wait_for_executor_rounds(conn, after, rounds=2, seconds=60):
    """Wait until the executor has finished `rounds` more trips round its loop after `after` (its
    database heartbeat, written at the end of each trip). Two, so at least one whole trip started
    after `after`."""
    seen = after
    for _ in range(rounds):
        row = wait_for(conn, "SELECT last_beat FROM heartbeats WHERE component = 'executor'", (),
                       lambda r, since=seen: r is not None and r[0] > since, seconds)
        assert row is not None and row[0] > seen, f"the executor did not beat after {seen}"
        seen = row[0]


def test_executor_calls_fake_dso_once_per_order():
    # A move-out for SP-1001 (not protected), assessed by the real risk engine. The executor sends
    # the notice (one SMS call); the test then makes the notice 73 hours old and two people approve,
    # so the executor writes the order (one DSO call). Later rounds make no second call.
    with stack_db() as conn:
        # Each run files a move-out in the stack database. The rows stay (effects and assessments
        # cannot be deleted), so the test moves its request out of the flood window when it ends;
        # otherwise enough runs within an hour would trip the flood rule and every move-out after
        # them would be held.
        limit = stack_moveout_limit()
        recent = conn.execute(
            "SELECT count(*) FROM action_requests WHERE kind = 'move_out' AND created_at >= now() - interval '1 hour'"
        ).fetchone()[0]
        assert recent < limit, f"{recent} move-outs in the last hour (limit {limit}): re-initialise the stack db"
        rid = conn.execute(
            "INSERT INTO action_requests (kind, ticket_id, account_id, move_out_date) "
            "VALUES ('move_out', 1, 1, (now() AT TIME ZONE 'UTC')::date) RETURNING id"
        ).fetchone()[0]
        try:
            row = wait_for(conn, "SELECT status FROM action_requests WHERE id = %s", (rid,), lambda r: r[0] != "pending")
            assert row == ("notice_sent",), row
            conn.execute("UPDATE occupier_notices SET sent_at = now() - interval '73 hours' WHERE request_id = %s", (rid,))
            for who in ("smoke.anna", "smoke.petros"):  # T1 needs one, T2 two
                conn.execute("INSERT INTO approvals (request_id, approver) VALUES (%s, %s)", (rid, who))
            row = wait_for(conn, "SELECT status FROM action_requests WHERE id = %s", (rid,),
                           lambda r: r[0] != "notice_sent")
            assert row == ("executed",), row
            order_id = conn.execute("SELECT id FROM disconnection_orders WHERE request_id = %s", (rid,)).fetchone()[0]
            wait_for_executor_rounds(conn, conn.execute("SELECT now()").fetchone()[0])
            events = conn.execute(
                "SELECT kind, detail FROM events WHERE kind LIKE 'outside_call_%%' AND detail LIKE %s ORDER BY id",
                (f"% move_out request={rid}",),
            ).fetchall()
        finally:
            conn.execute("UPDATE action_requests SET created_at = created_at - interval '2 hours' WHERE id = %s",
                         (rid,))
    to_dso = [c for c in fake_calls("fake-dso") if c["body"]["request_id"] == rid]
    assert [c["body"] for c in to_dso] == [{"request_id": rid, "order_id": order_id, "supply_point_id": "SP-1001"}]
    assert [c["caller"] for c in to_dso] == ["network"]
    to_sms = [c for c in fake_calls("fake-sms") if c["body"]["request_id"] == rid]
    assert len(to_sms) == 1, to_sms
    assert events == [(kind, f"{target} move_out request={rid}") for target in ("sms", "dso")
                      for kind in ("outside_call_due", "outside_call_sent")]
