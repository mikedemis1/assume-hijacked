"""Tests against the live kind cluster `ah` (`sh scripts/kind-up.sh`, kubectl context kind-ah).

Run with `pytest -m k8s tests/k8s`. They only read the cluster through kubectl.
"""

import json
import shutil
import subprocess

import pytest

CONTEXT = "kind-ah"


@pytest.fixture(autouse=True)
def fresh_db():
    """Replaces the autouse fixture of tests/conftest.py, which truncates the Compose database.
    These tests never touch it (the database belongs to the Compose stack)."""


def kubectl_json(*args: str) -> dict:
    """`kubectl get ... -o json` against the cluster `ah`. Fails loudly if it is not running."""
    if shutil.which("kubectl") is None:
        pytest.fail("kubectl is not installed")
    result = subprocess.run(
        ["kubectl", "--context", CONTEXT, *args, "-o", "json"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        pytest.fail(f"kubectl {' '.join(args)} failed (is the cluster up? sh scripts/kind-up.sh): "
                    f"{result.stderr.strip()}")
    return json.loads(result.stdout)


@pytest.fixture(scope="session")
def get():
    return kubectl_json
