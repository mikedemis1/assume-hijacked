"""Smoke tests against the running Compose stack (`docker compose up -d`, then `pytest -m smoke`).

They run the real agent container and look at what the real tool containers and network do.
"""

import functools
import itertools
import json
import os
import re
import subprocess
from pathlib import Path

import pytest

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

# Every service on an internal network except the db (which is also on hostaccess on purpose).
WALLED_SERVICES = [*TOOL_HOSTS, "executor", "agent"]

DB_PORT = 5432  # inside the stack; the published host port is DB_HOST_PORT
DB_HOST_PORT = int(os.environ.get("DB_PORT", "5432"))
TOOL_PORT = 8000


def compose(*args, timeout=300):
    # check=False: when something fails, the assert message shows stderr instead of a bare traceback.
    return subprocess.run(["docker", "compose", *args], capture_output=True, text=True, timeout=timeout, check=False)


def run_agent(ticket_id):
    done = compose("run", "--rm", "agent", "python", "-m", "app.agent.main", str(ticket_id))
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
    # The db is on seven networks, so seven IPs. The agent shares none of them.
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


# The controls: the same ports on the edges that ARE allowed. Without these, "blocked" above could
# just mean the service was down or the probe was broken.
ALLOWED_EDGES = {
    "agent": [(tool, TOOL_PORT) for tool in TOOL_HOSTS],
    **{tool: [("db", DB_PORT)] for tool in TOOL_HOSTS},
    "executor": [("db", DB_PORT)],
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
