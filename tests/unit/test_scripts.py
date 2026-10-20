"""The shell scripts in scripts/ without a cluster or a database."""

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = sorted((ROOT / "scripts").glob("*.sh"))
SH = shutil.which("sh")

pytestmark = pytest.mark.skipif(SH is None, reason="sh is not installed")


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_all_scripts_parse(script):
    done = subprocess.run([SH, "-n", str(script)], capture_output=True, text=True, check=False, timeout=30)
    assert done.returncode == 0, done.stderr


@pytest.mark.parametrize("customer", ["abc", "1; DROP TABLE tickets", "", "-1", "1 2"])
def test_new_ticket_refuses_non_numeric_customer(customer, tmp_path):
    """The refusal comes before any kubectl call: a kubectl that records its calls stays unused."""
    marker = tmp_path / "kubectl-called"
    fake = tmp_path / "kubectl"
    fake.write_text(f'#!/bin/sh\ntouch "{marker.as_posix()}"\n', encoding="utf-8", newline="\n")
    fake.chmod(0o755)
    env = {"PATH": f"{tmp_path.as_posix()}:/usr/bin:/bin", "HOME": str(tmp_path)}
    done = subprocess.run([SH, str(ROOT / "scripts" / "new-ticket.sh"), customer, "text"], capture_output=True,
                          text=True, env=env, check=False, timeout=30, cwd=ROOT)
    assert done.returncode != 0
    assert not marker.exists()
    assert "customer" in done.stderr


def fake_kubectl(tmp_path, *, service_exists=True):
    """A kubectl that records its calls and whose port-forward ends at once (as a dropped one does)."""
    log = tmp_path / "calls"
    fake = tmp_path / "kubectl"
    fake.write_text(
        '#!/bin/sh\n'
        f'echo "$@" >> "{log.as_posix()}"\n'
        'case "$*" in\n'
        f'  *" get service demo"*) exit {0 if service_exists else 1} ;;\n'
        '  *port-forward*) exit 1 ;;\n'
        'esac\n', encoding="utf-8", newline="\n")
    fake.chmod(0o755)
    return log


def run_demo_ui(tmp_path, **env):
    full = {"PATH": f"{tmp_path.as_posix()}:/usr/bin:/bin", "HOME": str(tmp_path), "DEMO_UI_PAUSE": "0", **env}
    return subprocess.run([SH, str(ROOT / "scripts" / "demo-ui.sh")], capture_output=True, text=True, env=full,
                          check=False, timeout=30, cwd=ROOT)


def test_demo_ui_starts_the_port_forward_again_when_it_is_dropped(tmp_path):
    log = fake_kubectl(tmp_path)
    done = run_demo_ui(tmp_path, DEMO_UI_MAX_TRIES="3")
    assert done.returncode == 0, done.stderr
    forwards = [line for line in log.read_text(encoding="utf-8").splitlines() if "port-forward" in line]
    assert forwards == ["--context kind-ah --namespace ah-demo port-forward --address 127.0.0.1 service/demo 8085:8085"] * 3
    assert "http://localhost:8085" in done.stdout


def test_demo_ui_uses_the_port_it_is_given_and_only_a_number(tmp_path):
    log = fake_kubectl(tmp_path)
    assert run_demo_ui(tmp_path, DEMO_UI_MAX_TRIES="1", DEMO_PORT="9090").returncode == 0
    assert "9090:8085" in log.read_text(encoding="utf-8")
    log.unlink()
    for port in ("80; rm -rf /", "x", "1 2"):
        done = run_demo_ui(tmp_path, DEMO_UI_MAX_TRIES="1", DEMO_PORT=port)
        assert done.returncode == 2 and "number" in done.stderr
    assert not log.exists()


def test_demo_ui_says_so_when_the_demo_is_not_deployed(tmp_path):
    log = fake_kubectl(tmp_path, service_exists=False)
    done = run_demo_ui(tmp_path, DEMO_UI_MAX_TRIES="1")
    assert done.returncode == 1 and "demo.enabled" in done.stderr
    assert not [line for line in log.read_text(encoding="utf-8").splitlines() if "port-forward" in line]
