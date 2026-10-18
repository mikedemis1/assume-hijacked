"""Smoke tests against the running Compose stack (`docker compose up -d`, then `pytest -m smoke`).

They run the real agent container and look at what the real tool gateway, tool containers and
network do.
"""

import functools
import itertools
import json
import os
import re
import subprocess
import time
from datetime import datetime, timezone
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

# Runs inside the gateway container, the one that reaches every tool: wait (at most 30 s) until every
# tool accepts connections, then until the gateway itself does.
WAIT_FOR_TOOLS = """
import socket, sys, time
deadline = time.monotonic() + 30
for host, port in {targets!r}:
    while True:
        try:
            socket.create_connection((host, port), timeout=2).close()
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
WALLED_SERVICES = [
    *TOOL_HOSTS, "tool-gateway", "dispatcher", "executor", "risk-engine", "register-sync", *FAKE_PORTS, "agent",
]

DB_PORT = 5432  # inside the stack; the published host port is DB_HOST_PORT
DB_HOST_PORT = int(os.environ.get("DB_PORT", "5432"))
TOOL_PORT = 8000
GATEWAY_PORT = 8080
RISK_PORT = 8082
DISPATCHER_PORT = 8081
OPS_PORT = 9000


def compose(*args, timeout=300, env=None):
    # check=False: when something fails, the assert message shows stderr instead of a bare traceback.
    return subprocess.run(
        ["docker", "compose", *args], capture_output=True, text=True, timeout=timeout, check=False, env=env
    )


def open_stack_lease(ticket_id):
    """A lease for the ticket in the stack database, opened as the database admin over the published
    port. The agent container still takes its lease from AGENT_LEASE; the dispatcher tests below
    claim theirs from the dispatcher."""
    with psycopg.connect(
        host=os.environ.get("DB_HOST", "127.0.0.1"),
        port=DB_HOST_PORT,
        dbname="supplier",
        user="postgres",
        password=os.environ["POSTGRES_PASSWORD"],
        autocommit=True,
    ) as conn:
        return conn.execute("SELECT open_lease(%s, %s, NULL)", (ticket_id, list(TOOLS))).fetchone()[0]


def run_agent(ticket_id, start_dependencies=True):
    # `-e AGENT_LEASE` with no value: Compose takes it from this process's environment, so the
    # lease is not on any command line. `run` starts the services the agent depends on, so a test
    # that has stopped one of them passes --no-deps, or the run would start it again.
    env = {**os.environ, "AGENT_LEASE": open_stack_lease(ticket_id)}
    deps = [] if start_dependencies else ["--no-deps"]
    done = compose(
        "run", "--rm", *deps, "-e", "AGENT_LEASE", "agent", "python", "-m", "app.agent.main", str(ticket_id), env=env
    )
    assert done.returncode == 0, f"agent exited {done.returncode}\nstdout: {done.stdout}\nstderr: {done.stderr}"
    return done


@pytest.fixture(scope="module", autouse=True)
def tools_are_up():
    targets = [*((host, TOOL_PORT) for host in TOOL_HOSTS), ("127.0.0.1", GATEWAY_PORT)]
    done = compose("exec", "-T", "tool-gateway", "python", "-c", WAIT_FOR_TOOLS.format(targets=targets))
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


# Runs inside the gateway container, which holds the signing key and reaches every tool: send the
# tool one request each way and print the status codes as JSON.
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
    done = compose("exec", "-T", "tool-gateway", "python", "-c", TOKEN_CHECKS.format(host=host, tool=tool), timeout=120)
    assert done.returncode == 0, f"stdout: {done.stdout}\nstderr: {done.stderr}"
    assert json.loads(done.stdout.strip().splitlines()[-1]) == {
        "no_token": 401, "garbage": 401, "wrong_audience": 401, "expired": 401, "good": 200, "replay": 401,
    }


def secret_files(service):
    """The names under /run/secrets in the running container; none if the folder does not exist
    (Docker makes it only for a container that has a secret). A container that cannot be reached
    fails the test: it must not read as "no secrets"."""
    done = compose("exec", "-T", service, "sh", "-c", "[ -d /run/secrets ] && ls /run/secrets; exit 0", timeout=60)
    assert done.returncode == 0, f"could not look inside {service}\nstdout: {done.stdout}\nstderr: {done.stderr}"
    return sorted(done.stdout.split())


@pytest.mark.parametrize("host", TOOL_HOSTS)
def test_a_tool_container_holds_the_public_key_and_not_the_signing_key(host):
    assert secret_files(host) == ["gateway_public_key"]


def test_the_gateway_holds_the_signing_key_and_not_the_public_one():
    assert secret_files("tool-gateway") == ["gateway_signing_key"]


@pytest.mark.parametrize("service", ["executor", "risk-engine", "register-sync", "dispatcher", "db", *FAKE_PORTS])
def test_no_other_container_holds_a_gateway_key(service):
    assert secret_files(service) == []


def test_the_agent_holds_no_key_and_is_told_no_tool_address():
    # A one-off agent container, like the one that answers a ticket: no secret mounted, and no
    # variable that names a key or a tool.
    done = compose("run", "--rm", "agent", "sh", "-c", "[ -d /run/secrets ] && ls /run/secrets; env", timeout=120)
    assert done.returncode == 0, f"stdout: {done.stdout}\nstderr: {done.stderr}"
    names = {line.split("=", 1)[0] for line in done.stdout.splitlines() if "=" in line}
    assert "GATEWAY_URL" in names                                   # the control: the env is the agent's
    # GPG_KEY is the Python image's public key id for its own download, not a secret of ours.
    held = [n for n in names if ("KEY" in n and n != "GPG_KEY") or n.startswith("TOOL_URL") or n.startswith("DB_PASSWORD")]
    assert not held, names
    assert "gateway_signing_key" not in done.stdout and "gateway_public_key" not in done.stdout


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
    # The db is on ten networks, so ten IPs. The agent shares none of them.
    targets = [*service_targets("db", DB_PORT), ("host.docker.internal", DB_HOST_PORT)]
    assert len(targets) > 3, targets
    assert_blocked("agent", targets)


TOOL_PAIRS = list(itertools.permutations(TOOL_HOSTS, 2))


@pytest.mark.parametrize("source,target", TOOL_PAIRS, ids=[f"{s}->{t}" for s, t in TOOL_PAIRS])
def test_tool_cannot_reach_other_tools(source, target):
    assert_blocked(source, service_targets(target, TOOL_PORT))


@pytest.mark.parametrize("tool", TOOL_HOSTS)
def test_agent_cannot_reach_any_tool(tool):
    # The agent calls a tool only through the gateway: no network in common with a tool, so no
    # route by name and none by address.
    assert_blocked("agent", service_targets(tool, TOOL_PORT))


@pytest.mark.parametrize("tool", TOOL_HOSTS)
def test_executor_cannot_reach_tools(tool):
    assert_blocked("executor", service_targets(tool, TOOL_PORT))


@pytest.mark.parametrize("tool", TOOL_HOSTS)
def test_risk_engine_cannot_reach_tools(tool):
    # Its edges are the db and the gateway's; a tool is neither.
    assert_blocked("risk-engine", service_targets(tool, TOOL_PORT))


def test_agent_cannot_reach_the_risk_engine():
    # Only the gateway asks the risk engine; an agent that could would ask for allows, or flood it.
    assert_blocked("agent", service_targets("risk-engine", RISK_PORT))


@pytest.mark.parametrize("source", ["executor", "register-sync", *FAKE_PORTS])
def test_nothing_without_an_edge_to_the_gateway_reaches_its_port(source):
    # The containers that share no network with the gateway cannot open its port at all. The five
    # tools and the risk engine do share one and can connect; what refuses them is the gateway's
    # check of the source address (test_a_neighbour_of_the_gateway_is_refused_and_the_agent_is_not).
    assert_blocked(source, service_targets("tool-gateway", GATEWAY_PORT))


@pytest.mark.parametrize("target", ["executor", "register-sync", "fake-dso", "fake-sms", "fake-register"])
def test_the_gateway_cannot_reach_what_is_not_its_peer(target):
    port = FAKE_PORTS.get(target, OPS_PORT)
    assert_blocked("tool-gateway", service_targets(target, port))


@pytest.mark.parametrize("tool", TOOL_HOSTS)
def test_register_sync_cannot_reach_tools(tool):
    # Its edges are the db and the register; nothing else.
    assert_blocked("register-sync", service_targets(tool, TOOL_PORT))


@pytest.mark.parametrize("fake", FAKE_PORTS)
def test_fakes_cannot_reach_db(fake):
    # A fake stands for a system outside the company: it gets no route to the database.
    assert_blocked(fake, [*service_targets("db", DB_PORT), ("host.docker.internal", DB_HOST_PORT)])


FAKE_TARGETS = [(fake, port) for fake, port in FAKE_PORTS.items()]


@pytest.mark.parametrize("source", ["agent", *TOOL_HOSTS, "tool-gateway", "risk-engine"])
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
    "agent": [("tool-gateway", GATEWAY_PORT), ("dispatcher", DISPATCHER_PORT)],
    "dispatcher": [("db", DB_PORT)],
    "tool-gateway": [*((tool, TOOL_PORT) for tool in TOOL_HOSTS), ("risk-engine", RISK_PORT), ("db", DB_PORT)],
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
    # The probe runs inside its container; the gateway's call to it is tested through the gateway.
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


# --- The tool gateway in the stack ---

OPS_FROM_INSIDE = """
import urllib.request
print(urllib.request.urlopen("http://127.0.0.1:9000/healthz", timeout=5).status)
print(urllib.request.urlopen("http://127.0.0.1:9000/metrics", timeout=5).read().decode())
"""


def ops_of(service):
    done = compose("exec", "-T", service, "python", "-c", OPS_FROM_INSIDE, timeout=60)
    assert done.returncode == 0, f"{service}\nstdout: {done.stdout}\nstderr: {done.stderr}"
    status, _, metrics = done.stdout.partition("\n")
    return status, metrics


@pytest.mark.parametrize("service", TOOL_HOSTS)
def test_a_tool_answers_healthz(service):
    status, _ = ops_of(service)
    assert status == "200"


def test_the_gateway_answers_healthz_and_publishes_its_metrics_from_the_start():
    status, metrics = ops_of("tool-gateway")
    assert status == "200"
    for tool in ("read_ticket", "lookup_account", "request_disconnection", "issue_bill_credit", "set_temp_protection"):
        assert f'gateway_calls_total{{outcome="ok",tool="{tool}"}} ' in metrics, tool
        assert f'gateway_denials_total{{reason="lease",tool="{tool}"}} ' in metrics, tool
    assert 'gateway_denials_total{reason="risk_timeout",tool="read_ticket"} ' in metrics


def stack_calls(after):
    with stack_db() as conn:
        return conn.execute(
            "SELECT tool, arg_names, dropped_args, outcome, reason, actor FROM tool_calls WHERE id > %s ORDER BY id",
            (after,),
        ).fetchall()


def last_call_id():
    with stack_db() as conn:
        return conn.execute("SELECT coalesce(max(id), 0) FROM tool_calls").fetchone()[0]


def gateway_log_since(moment):
    done = compose("logs", "--no-log-prefix", "--since", moment, "tool-gateway", timeout=60)
    assert done.returncode == 0, done.stderr
    return done.stdout + done.stderr


def test_a_ticket_through_the_gateway_leaves_a_record_of_names_only():
    after = last_call_id()
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    done = run_agent(4)  # ticket 4 asks for customer 1002 with a customer_id argument
    assert "Nikos" not in done.stdout, done.stderr
    rows = stack_calls(after)
    assert [(r[0], r[3], r[5]) for r in rows] == [("read_ticket", "ok", "gateway"), ("lookup_account", "ok", "gateway")]
    # The agent's own code already dropped customer_id, so the gateway had nothing left to drop here.
    assert all(r[2] == [] for r in rows)
    # The gateway's own log (another container): an honest ticket is refused nowhere.
    log = gateway_log_since(started)
    assert "gateway_denied" not in log and "gateway_error" not in log, log
    assert "heart" not in log and "Eleni" not in log


def test_the_gateway_denies_while_the_risk_engine_is_stopped_and_works_again_after():
    # The wall that matters most when something is down: no verdict, no tool call.
    after = last_call_id()
    stopped = compose("stop", "risk-engine", timeout=120)
    assert stopped.returncode == 0, stopped.stderr
    try:
        done = run_agent(1, start_dependencies=False)
        assert "Eleni" not in done.stdout and "colleague" in done.stdout, done.stdout   # the agent gave up
        rows = stack_calls(after)
        assert rows and {(r[0], r[3]) for r in rows} == {("read_ticket", "denied")}, rows
        assert rows[0][4] in ("risk_unavailable", "risk_timeout")
    finally:
        started = compose("start", "risk-engine", timeout=120)
        assert started.returncode == 0, started.stderr
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            probe_done = compose("exec", "-T", "risk-engine", "python", "-c", DECIDE_FROM_INSIDE, timeout=60)
            if probe_done.returncode == 0:
                break
            time.sleep(1)
    assert "Eleni Papadopoulou" in run_agent(1).stdout                          # the control


# A call to the gateway's MCP endpoint, made from inside a container: the status code.
CALL_THE_GATEWAY = """
import json, urllib.request, urllib.error
body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "issue_bill_credit",
                   "arguments": {"amount_eur": 0.01, "reason": "outage", "evidence_ref": 1}}}
request = urllib.request.Request(
    "http://tool-gateway:8080/mcp", data=json.dumps(body).encode(),
    headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
             "X-Lease": "ab" * 32},
)
try:
    print(urllib.request.urlopen(request, timeout=10).status)
except urllib.error.HTTPError as err:
    print(err.code)
"""


@pytest.mark.parametrize("source", [*TOOL_HOSTS, "risk-engine"])
def test_a_neighbour_of_the_gateway_is_refused_and_the_agent_is_not(source):
    # A hijacked tool (or the risk engine, which sees every lease) can open the gateway's port over
    # its own edge. The gateway accepts only addresses of the agent's network, so it answers 401
    # before any wall or tool runs. The same request from the agent is let in (200: the call itself
    # is then refused for its unknown lease, which is a tool answer, not a 401).
    after = last_call_id()
    refused = probe(source, CALL_THE_GATEWAY)
    assert refused.returncode == 0, f"stdout: {refused.stdout}\nstderr: {refused.stderr}"
    assert refused.stdout.strip() == "401", refused.stdout
    assert stack_calls(after) == []                      # it never reached the pipeline
    let_in = probe("agent", CALL_THE_GATEWAY)
    assert let_in.returncode == 0, f"stdout: {let_in.stdout}\nstderr: {let_in.stderr}"
    assert let_in.stdout.strip().splitlines()[-1] == "200", let_in.stdout
    assert [(r[0], r[3], r[4]) for r in stack_calls(after)] == [("issue_bill_credit", "denied", "lease")]


# --- The dispatcher in the stack ---

def test_the_dispatcher_answers_healthz_and_publishes_its_metrics_from_the_start():
    status, metrics = ops_of("dispatcher")
    assert status == "200"
    assert 'dispatcher_claims_total{outcome="issued"} ' in metrics
    assert 'dispatcher_replies_blocked_total{reason="currency"} ' in metrics
    assert 'dispatcher_callers_refused_total{reason="wrong_network"} ' in metrics


@pytest.mark.parametrize(
    "source",
    ["tool-gateway", *TOOL_HOSTS, "risk-engine", "executor", "register-sync", *FAKE_PORTS],
)
def test_nothing_without_an_edge_to_the_dispatcher_reaches_its_port(source):
    # The agent is the only container on the dispatcher's agent-side edge. The database shares the
    # dispatcher's other edge and is dealt with below.
    assert_blocked(source, service_targets("dispatcher", DISPATCHER_PORT))


@pytest.mark.parametrize(
    "target",
    [("tool-gateway", GATEWAY_PORT), ("risk-engine", RISK_PORT), ("executor", OPS_PORT), ("register-sync", OPS_PORT),
     *((host, TOOL_PORT) for host in TOOL_HOSTS), *FAKE_PORTS.items()],
)
def test_the_dispatcher_reaches_nothing_but_the_database(target):
    assert_blocked("dispatcher", service_targets(*target))


# Runs in the agent container: ask the dispatcher for work, optionally reply, print what happened.
# LEASE and TEXT come from the environment, so neither is on a command line.
DISPATCHER_CLIENT = """
import json, os, urllib.error, urllib.request

def call(path, body=None, lease=None):
    headers = {{"Content-Type": "application/json"}}
    if lease:
        headers["X-Lease"] = lease
    data = b"" if body is None else json.dumps(body).encode()
    request = urllib.request.Request("http://dispatcher:8081" + path, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=10) as answer:
            return answer.status, answer.read().decode()
    except urllib.error.HTTPError as err:
        return err.code, err.read().decode()

{steps}
"""

CLAIM = """
status, text = call("/claim")
out = {"claim": status}
if status == 200:
    out.update(json.loads(text))
print(json.dumps(out))
"""

REPLY = """
lease, text = os.environ["LEASE"], os.environ["TEXT"]
first, _ = call("/reply", {"text": text}, lease)
again, _ = call("/reply", {"text": "a second reply"}, lease)
print(json.dumps({"reply": first, "again": again}))
"""


def agent_script(steps, **env):
    """Run the steps in a one-off agent container (no restart of its dependencies) and parse the last
    line it printed as JSON."""
    names = [arg for key in env for arg in ("-e", key)]
    done = compose(
        "run", "--rm", "--no-deps", *names, "agent", "python", "-c", DISPATCHER_CLIENT.format(steps=steps),
        env={**os.environ, **env}, timeout=120,
    )
    assert done.returncode == 0, f"stdout: {done.stdout}\nstderr: {done.stderr}"
    return json.loads(done.stdout.strip().splitlines()[-1])


@pytest.fixture
def clean_runs():
    """The stack database keeps runs and replies between test runs; a ticket with a run is never
    handed out again, so each test starts from none and leaves none."""

    def wipe():
        with stack_db() as conn:
            conn.execute("DELETE FROM replies")
            conn.execute("DELETE FROM agent_runs")

    wipe()
    yield
    wipe()


def test_the_agent_gets_a_ticket_and_a_lease_and_its_reply_is_stored_and_the_lease_ends(clean_runs):
    claimed = agent_script(CLAIM)
    assert claimed["claim"] == 200 and claimed["ticket_id"] == 1 and len(claimed["lease"]) == 64
    with stack_db() as conn:
        scope = conn.execute("SELECT ticket_id, bound_pod FROM lease_scope(%s)", (claimed["lease"],)).fetchone()
        assert scope == (1, None)
        assert conn.execute("SELECT ticket_id, status FROM agent_runs").fetchall() == [(1, "claimed")]
    # The control: the lease works. The real agent answers ticket 1 with it, through the gateway.
    answered = compose(
        "run", "--rm", "--no-deps", "-e", "AGENT_LEASE", "agent", "python", "-m", "app.agent.main", "1",
        env={**os.environ, "AGENT_LEASE": claimed["lease"]}, timeout=180,
    )
    assert answered.returncode == 0 and "Eleni Papadopoulou" in answered.stdout, answered.stderr
    sent = agent_script(REPLY, LEASE=claimed["lease"], TEXT="Thank you, a colleague will check this.")
    assert sent == {"reply": 200, "again": 403}                         # stored once; the lease has ended
    with stack_db() as conn:
        assert conn.execute("SELECT ticket_id, text FROM replies").fetchall() == [
            (1, "Thank you, a colleague will check this.")]
        assert conn.execute("SELECT ticket_id, status FROM agent_runs").fetchall() == [(1, "replied")]
        assert conn.execute("SELECT count(*) FROM lease_scope(%s)", (claimed["lease"],)).fetchone()[0] == 0
    # The next agent gets the next ticket.
    assert agent_script(CLAIM)["ticket_id"] == 2


def test_a_reply_that_promises_money_is_replaced_by_the_dispatcher_not_the_agent(clean_runs):
    # The agent container here sends the text as a taken-over agent would: no guard of its own ran.
    claimed = agent_script(CLAIM)
    sent = agent_script(REPLY, LEASE=claimed["lease"], TEXT="Good news: a credit of 49 EUR will be paid back to you.")
    assert sent["reply"] == 200
    with stack_db() as conn:
        (text,) = conn.execute("SELECT text FROM replies").fetchone()
    assert text == "Thank you. A colleague will check this and reply to you."


# Runs in the database container, which shares the dispatcher's database edge and so can open its
# port, from an address that is not in the agent's subnet: the status line of the answer.
FROM_THE_DATABASE = "wget -S -O /dev/null --post-data x http://dispatcher:8081/claim 2>&1; true"


def test_a_neighbour_of_the_dispatcher_is_refused_and_the_agent_is_not(clean_runs):
    refused = compose("exec", "-T", "db", "sh", "-c", FROM_THE_DATABASE, timeout=60)
    assert refused.returncode == 0, refused.stderr
    assert "401" in refused.stdout and "HTTP/1.1 200" not in refused.stdout, refused.stdout
    with stack_db() as conn:
        assert conn.execute("SELECT count(*) FROM agent_runs").fetchone()[0] == 0   # it never got as far as a claim
    assert agent_script(CLAIM)["claim"] == 200                                      # the control: the agent is let in
