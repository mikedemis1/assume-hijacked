"""scripts/kind-deploy.sh and the ops stand-in it deploys while the application code is not in
this tree. Read as files and run locally; no cluster needed. The deploy itself is checked on the
cluster by `pytest -m k8s tests/k8s/test_walls.py` against the installed release.
"""

import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

import pytest

from tests.k8s.test_chart import CHART, ROOT

DEPLOY = ROOT / "scripts" / "kind-deploy.sh"
STUB = CHART / "files" / "ops-stub.py"


def script() -> str:
    return DEPLOY.read_text(encoding="utf-8")


def helm_calls() -> list[str]:
    """Each helm upgrade/install command of the script, joined across its continuation lines."""
    text = script().replace("\\\n", " ")
    return [line for line in text.splitlines() if re.search(r"\bh upgrade\b|\bhelm\b.*\b(upgrade|install)\b", line)
            and not line.lstrip().startswith("#")]


def test_deploy_installs_the_pushed_image_by_digest():
    """The admission policy admits images only by digest from localhost:5001/: the script pushes
    to the local registry and installs the digest it got back, never a tag or `kind load`."""
    text = script()
    assert "kind load" not in text
    assert 'docker push --quiet "$PUSH:dev"' in text
    # Reproducible: no build-time attestation, so unchanged code keeps its digest and a re-run
    # restarts nothing.
    assert "docker build --quiet --provenance=false" in text
    assert 'image="$PULL:$tag@$digest"' in text
    assert 'tag=$(git rev-parse --short HEAD)' in text
    assert "PULL=localhost:5001/assume-hijacked" in text and "PUSH=127.0.0.1:5001/assume-hijacked" in text
    [call] = helm_calls()
    assert '--set "images.app=$image"' in call
    assert '-f "$CHART/values-kind.yaml"' in call


# --- the script run against fake kubectl, helm, docker and kind --------------------------------
# Each fake logs its calls and answers as the scenario says. openssl, sed, base64 are the real ones.


def passwords(values: str) -> list[str]:
    return re.findall(r':\s*"([^"]*)"', values)


# --- scripts/azure-rotate-db-passwords.sh against fakes ----------------------------------------

ROTATE = ROOT / "scripts" / "azure-rotate-db-passwords.sh"


# --- the ops stand-in -------------------------------------------------------------------------

def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def stub():
    """files/ops-stub.py run the way the chart runs it (python -c <source> <component>), on a free
    port instead of 9000."""
    port = free_port()
    source = STUB.read_text(encoding="utf-8")
    assert source.count("PORT = 9000") == 1
    proc = subprocess.Popen([sys.executable, "-c", source.replace("PORT = 9000", f"PORT = {port}"), "risk-engine"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    deadline = time.monotonic() + 10
    while True:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                break
        except OSError:
            if time.monotonic() > deadline or proc.poll() is not None:
                proc.kill()
                pytest.fail(f"stub did not start: {proc.communicate()}")
            time.sleep(0.1)
    yield f"http://127.0.0.1:{port}"
    proc.terminate()
    proc.wait(timeout=10)


def get(url: str) -> tuple[int, str, str]:
    try:
        with urllib.request.urlopen(url, timeout=5) as r:  # nosec B310: loopback test server
            return r.status, r.headers["Content-Type"], r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.headers["Content-Type"], e.read().decode()


