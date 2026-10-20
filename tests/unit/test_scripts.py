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
