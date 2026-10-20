"""Tests against the live kind cluster `ah` (`sh scripts/kind-up.sh`, kubectl context kind-ah).

Run with `pytest -m k8s tests/k8s`. They only read the cluster through kubectl.
"""

import json
import shutil
import subprocess
import time

import pytest

CONTEXT = "kind-ah"
# The antivirus on the development PC sometimes aborts a loopback connection to the API server
# (wsarecv: "An established connection was aborted by the software in your host machine").
# Nothing reached the server then, so the same command is sent again.
DROPPED = "Unable to connect to the server"


def run_kubectl(args: list[str], stdin: str | None = None, timeout: int = 120) -> subprocess.CompletedProcess:
    """kubectl against the cluster `ah`, sent again (up to 3 times) when the connection dropped."""
    for attempt in range(3):
        result = subprocess.run(["kubectl", "--context", CONTEXT, *args], input=stdin, capture_output=True,
                                text=True, encoding="utf-8", timeout=timeout, check=False)
        if result.returncode == 0 or DROPPED not in result.stderr or attempt == 2:
            return result
        time.sleep(1)
    return result


@pytest.fixture(autouse=True)
def fresh_db():
    """Replaces the autouse fixture of tests/conftest.py, which truncates the test database.
    These tests never touch it (the database belongs to the cluster)."""


def kubectl_json(*args: str) -> dict:
    """`kubectl get ... -o json` against the cluster `ah`. Fails loudly if it is not running."""
    if shutil.which("kubectl") is None:
        pytest.fail("kubectl is not installed")
    result = run_kubectl([*args, "-o", "json"], timeout=60)
    if result.returncode != 0:
        pytest.fail(f"kubectl {' '.join(args)} failed (is the cluster up? sh scripts/kind-up.sh): "
                    f"{result.stderr.strip()}")
    return json.loads(result.stdout)


@pytest.fixture(scope="session")
def get():
    return kubectl_json
