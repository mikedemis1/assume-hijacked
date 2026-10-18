"""scripts/kind-deploy.sh and the ops stand-in it deploys while the application code is not in
this tree. Read as files and run locally; no cluster needed. The deploy itself is checked on the
cluster by `pytest -m k8s tests/k8s/test_walls.py` against the installed release.
"""

import re
import shutil
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


@pytest.mark.skipif(shutil.which("sh") is None, reason="sh is not installed")
def test_deploy_script_has_valid_shell_syntax():
    result = subprocess.run(["sh", "-n", str(DEPLOY)], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr


def test_deploy_installs_the_pushed_image_by_digest():
    """The admission policy admits images only by digest from localhost:5001/: the script pushes
    to the local registry and installs the digest it got back, never a tag or `kind load`."""
    text = script()
    assert "kind load" not in text
    assert 'docker push --quiet "$PUSH:dev"' in text
    # Reproducible: no build-time attestation, so unchanged code keeps its digest and a re-run
    # restarts nothing.
    assert "docker build --quiet --provenance=false" in text
    assert 'image="$PULL@$digest"' in text
    assert "PULL=localhost:5001/assume-hijacked" in text and "PUSH=127.0.0.1:5001/assume-hijacked" in text
    [call] = helm_calls()
    assert '--set "images.app=$image"' in call
    assert '-f "$CHART/values-kind.yaml"' in call


def test_deploy_never_lets_helm_wait_for_pods_before_the_database_setup():
    """Helm runs the post-install database setup only after --wait has seen every pod ready, and
    the pods need the database: helm waits for hooks only, then the script waits for rollouts."""
    [call] = helm_calls()
    assert "upgrade --install" in call
    assert "--wait=hookOnly" in call
    assert not re.search(r"--wait(?!=hookOnly)|--atomic|--rollback-on-failure|--wait-for-jobs", call)
    after = script().split("--wait=hookOnly", 1)[1]
    assert "rollout status statefulset/postgres" in after
    assert 'rollout status "deployment/' in after


def test_deploy_generates_secrets_once_and_reads_them_back():
    """Random on the first install, read back from the cluster afterwards (the database keeps the
    passwords it was set up with); never written into the repository."""
    text = script()
    assert "openssl rand -hex 24" in text
    assert "openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256" in text
    assert "secret_value ah-data postgres-secrets POSTGRES_PASSWORD" in text
    assert 'secret_value ah-data postgres-secrets "DB_PASSWORD_$upper"' in text
    assert "secret_value ah-gateway tool-gateway-secrets signing-key.pem" in text
    # Written only into a private temporary folder that is removed on exit.
    assert "work=$(mktemp -d)" in text and "trap 'rm -rf \"$work\"' EXIT" in text and 'chmod 700 "$work"' in text
    code = "\n".join(re.sub(r"(^|\s)#.*", "", line) for line in text.splitlines())
    for target in re.findall(r'>\s*"?([^\s"|&;]+)', code):
        assert target.startswith(("$work/", "/dev/", "&")), target
    # The .env passwords belong to Compose: only the two build settings are read from it.
    assert re.findall(r"env_setting (\w+)", text) == ["PIP_CERT_FILE", "LOCAL_WHEELS_DIR"]


def test_deploy_passes_every_role_and_every_sql_file():
    text = script()
    roles = re.search(r'DB_ROLES="([^"]+)"', text).group(1).split()
    chart_roles = re.search(r'define "ah.dbRoles" -}}\s*(\[[^\]]+\])',
                            (CHART / "templates" / "_helpers.tpl").read_text(encoding="utf-8")).group(1)
    assert roles == [r.strip(' "') for r in chart_roles.strip("[]").split(",")]
    assert '--set-file "dbFiles.initSh=db/init/init.sh"' in text
    assert 'for file in db/sql/*.sql; do' in text
    assert '--set-file "dbFiles.sql.$(basename "$file" .sql)=$file"' in text


def test_deploy_refuses_a_database_left_from_another_release():
    """init.sh runs on the first install only; on an old volume it would meet roles with
    passwords this run does not know."""
    text = script()
    assert "if ! release_exists && database_volume_exists; then" in text
    assert "kind-deploy.sh reset" in text


def test_stubs_are_added_only_while_their_values_file_exists():
    text = script()
    assert 'if [ -f "$CHART/values-kind-stubs.yaml" ]; then' in text
    assert "values-kind-stubs.yaml" not in "".join(helm_calls())


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


def test_stub_serves_healthz_and_metrics_and_nothing_else(stub):
    assert get(f"{stub}/healthz")[0] == 200
    status, content_type, body = get(f"{stub}/metrics")
    assert status == 200 and content_type.startswith("text/plain; version=0.0.4")
    assert body == '# TYPE ah_stub_up gauge\nah_stub_up{component="risk-engine"} 1\n'
    for path in ("/", "/decide", "/healthz/x", "/metrics?x=1"):
        assert get(f"{stub}{path}")[0] == 404, path


def test_stub_refuses_a_bad_component_name():
    source = STUB.read_text(encoding="utf-8")
    for bad in ('x"} 1\nevil{a="', "", "Risk"):
        result = subprocess.run([sys.executable, "-c", source, bad], capture_output=True, text=True, timeout=10,
                                check=False)
        assert result.returncode != 0, bad
        assert "usage" in result.stderr


def test_stub_is_marked_temporary_and_uses_only_the_standard_library():
    source = STUB.read_text(encoding="utf-8")
    assert "Temporary stand-in" in source and "Delete this file" in source
    imports = set(re.findall(r"^(?:from|import) ([a-z_.]+)", source, re.M))
    assert imports <= {"re", "signal", "sys", "http.server"}
