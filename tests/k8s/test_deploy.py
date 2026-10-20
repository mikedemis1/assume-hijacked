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
    assert 'image="$PULL:$tag@$digest"' in text
    assert 'tag=$(git rev-parse --short HEAD)' in text
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


def test_deploy_writes_secrets_only_into_its_temporary_folder():
    """Never into the repository; and Helm keeps few revisions of them (its release Secrets)."""
    text = script()
    assert "sh.helm.release.v1" in text
    [call] = helm_calls()
    assert re.search(r"--history-max [1-5]\b", call)
    # Written only into a private temporary folder that is removed on exit.
    assert "work=$(mktemp -d)" in text and "trap 'rm -rf \"$work\"' EXIT" in text and 'chmod 700 "$work"' in text
    code = "\n".join(re.sub(r"(^|\s)#.*", "", line) for line in text.splitlines())
    for target in re.findall(r'>\s*"?([^\s"|&;]+)', code):
        assert target.startswith(("$work/", "/dev/", "&")), target
    # Only the two build settings are read from .env.
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


# --- the script run against fake kubectl, helm, docker and kind --------------------------------
# Each fake logs its calls and answers as the scenario says. openssl, sed, base64 are the real ones.

FAKE_KUBECTL = r"""#!/bin/sh
echo "kubectl $*" >> "$FAKE_DIR/calls.log"
case "$*" in
    *"get --raw /version"*) echo '{}' ;;
    *"get pvc"*)
        case "$FAKE_PVC" in
            yes) echo persistentvolumeclaim/data-postgres-0 ;;
            no) echo 'Error from server (NotFound): persistentvolumeclaims "data-postgres-0" not found' >&2; exit 1 ;;
            *) echo 'Unable to connect to the server: dial tcp 127.0.0.1:16443: connectex' >&2; exit 1 ;;
        esac ;;
    *"get secret"*)
        case "$FAKE_SECRETS" in
            ok) case "$*" in *signing-key*) cat "$FAKE_DIR/key.b64" ;; *) printf '%s' ZGVwbG95ZWQ= ;; esac ;;
            empty) ;;
            *) echo 'Unable to connect to the server: dial tcp 127.0.0.1:16443: connectex' >&2; exit 1 ;;
        esac ;;
esac
exit 0
"""

FAKE_HELM = r"""#!/bin/sh
echo "helm $*" >> "$FAKE_DIR/calls.log"
case "$*" in
    *" history "*)
        case "$FAKE_RELEASE" in
            deployed) echo '[{"revision":1,"status":"superseded"},{"revision":2,"status":"deployed"}]' ;;
            failed) echo '[{"revision":1,"status":"failed"}]' ;;
            none) echo 'Error: release: not found' >&2; exit 1 ;;
            *) echo 'Error: Kubernetes cluster unreachable: connection refused' >&2; exit 1 ;;
        esac ;;
    *" upgrade "*)
        prev=""
        for a in "$@"; do
            if [ "$prev" = "-f" ]; then
                case "$a" in *secrets.yaml) cp "$a" "$FAKE_DIR/secrets-used.yaml" ;; esac
            fi
            prev=$a
        done
        echo UPGRADED >> "$FAKE_DIR/calls.log" ;;
esac
exit 0
"""

FAKE_DOCKER = r"""#!/bin/sh
case "$*" in
    *RepoDigests*) echo "127.0.0.1:5001/assume-hijacked@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ;;
    *State.Running*) echo true ;;
    *Networks.kind*) echo '{"NetworkID":"x"}' ;;
esac
exit 0
"""

FAKE_KIND = "#!/bin/sh\nexit 0\n"


@pytest.fixture
def run_deploy(tmp_path):
    if shutil.which("sh") is None or shutil.which("openssl") is None:
        pytest.skip("needs sh and openssl (Git Bash)")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    import base64
    import os

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in (("kubectl", FAKE_KUBECTL), ("helm", FAKE_HELM), ("docker", FAKE_DOCKER), ("kind", FAKE_KIND)):
        (bin_dir / name).write_bytes(body.encode())
        (bin_dir / name).chmod(0o755)
    pem = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    (tmp_path / "key.b64").write_bytes(base64.b64encode(pem))

    def run(release: str, secrets: str = "ok", pvc: str = "no") -> tuple[subprocess.CompletedProcess, str]:
        log = tmp_path / "calls.log"
        log.write_text("", encoding="utf-8")
        (tmp_path / "secrets-used.yaml").unlink(missing_ok=True)
        env = {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}", "FAKE_DIR": str(tmp_path),
               "FAKE_RELEASE": release, "FAKE_SECRETS": secrets, "FAKE_PVC": pvc}
        result = subprocess.run(["sh", "scripts/kind-deploy.sh"], cwd=ROOT, env=env, capture_output=True, text=True,
                                stdin=subprocess.DEVNULL, timeout=120, check=False)
        used = tmp_path / "secrets-used.yaml"
        return result, used.read_text(encoding="utf-8") if used.exists() else ""

    run.log = lambda: (tmp_path / "calls.log").read_text(encoding="utf-8")
    return run


def passwords(values: str) -> list[str]:
    return re.findall(r':\s*"([^"]*)"', values)


def test_deploy_reads_the_deployed_secrets_back(run_deploy):
    result, used = run_deploy("deployed")
    assert result.returncode == 0, result.stderr
    assert len(passwords(used)) == 12 and set(passwords(used)) == {"deployed"}
    assert "UPGRADED" in run_deploy.log()


@pytest.mark.parametrize(("secrets", "message"), [("error", "cannot read"), ("empty", "has no")])
def test_deploy_never_replaces_secrets_it_could_not_read(run_deploy, secrets, message):
    """While the release exists a failed or empty read stops the deploy: new passwords would not
    be the ones the database was set up with."""
    result, used = run_deploy("deployed", secrets=secrets)
    assert result.returncode != 0
    assert message in result.stderr
    assert "UPGRADED" not in run_deploy.log() and used == ""


def test_deploy_generates_secrets_on_the_first_install_only(run_deploy):
    result, used = run_deploy("none")
    assert result.returncode == 0, result.stderr
    values = passwords(used)
    assert len(values) == 12 and len(set(values)) == 12
    assert all(re.fullmatch(r"[0-9a-f]{48}", v) for v in values)
    # Nothing was read: there is no release to read from.
    assert "get secret" not in run_deploy.log()


@pytest.mark.parametrize(("release", "pvc", "message"), [
    ("failed", "yes", "never completed its first install"),
    ("none", "yes", "run sh scripts/kind-deploy.sh reset first"),
    ("none", "error", "cannot check the database volume"),
    ("error", "no", "helm cannot read release"),
])
def test_deploy_stops_when_the_database_state_is_unknown_or_broken(run_deploy, release, pvc, message):
    """A first install whose database setup failed is not upgraded (the pods would crash-loop),
    an old database volume is not reused, and an error is never taken for "nothing there"."""
    result, _ = run_deploy(release, pvc=pvc)
    assert result.returncode != 0
    assert message in result.stderr
    assert "UPGRADED" not in run_deploy.log()
    if release == "failed":
        assert "kind-deploy.sh reset" in result.stderr


# --- scripts/azure-rotate-db-passwords.sh against fakes ----------------------------------------

ROTATE = ROOT / "scripts" / "azure-rotate-db-passwords.sh"

FAKE_ROTATE_KUBECTL = r"""#!/bin/sh
echo "kubectl $*" >> "$FAKE_DIR/calls.log"
case "$*" in
    *"get job "*)
        n=$(cat "$FAKE_DIR/polls" 2>/dev/null || echo 0)
        n=$((n + 1))
        echo "$n" > "$FAKE_DIR/polls"
        if [ "$n" -lt 3 ]; then echo "/"; else echo "$FAKE_JOB_END"; fi ;;
    *"get deployments"*) printf '%s' "ah-core/executor ah-tools/tool-read-ticket " ;;
esac
exit 0
"""

FAKE_ROTATE_HELM = r"""#!/bin/sh
echo "helm $*" >> "$FAKE_DIR/calls.log"
case "$*" in
    *"get values"*) echo "env: azure" ;;
    *template*) echo "kind: Job" ;;
esac
exit 0
"""

FAKE_SLEEP = '#!/bin/sh\necho "sleep $*" >> "$FAKE_DIR/calls.log"\n'


@pytest.fixture
def run_rotate(tmp_path):
    if shutil.which("sh") is None:
        pytest.skip("needs sh (Git Bash)")
    import os

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in (("kubectl", FAKE_ROTATE_KUBECTL), ("helm", FAKE_ROTATE_HELM), ("sleep", FAKE_SLEEP)):
        (bin_dir / name).write_bytes(body.encode())
        (bin_dir / name).chmod(0o755)

    def run(job_end: str) -> tuple[subprocess.CompletedProcess, list[str]]:
        log = tmp_path / "calls.log"
        log.write_text("", encoding="utf-8")
        (tmp_path / "polls").unlink(missing_ok=True)
        env = {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}", "FAKE_DIR": str(tmp_path),
               "FAKE_JOB_END": job_end}
        result = subprocess.run(["sh", str(ROTATE), "aks-lab"], cwd=ROOT, env=env, capture_output=True, text=True,
                                stdin=subprocess.DEVNULL, timeout=60, check=False)
        return result, log.read_text(encoding="utf-8").splitlines()

    return run


def test_rotation_restarts_only_after_the_job_and_the_csi_wait(run_rotate):
    result, calls = run_rotate("1/")
    assert result.returncode == 0, result.stderr
    create = next(i for i, c in enumerate(calls) if " create -f " in c)
    polls = [i for i, c in enumerate(calls) if " get job db-passwords-rotate-" in c]
    wait = calls.index("sleep 180")
    restarts = [i for i, c in enumerate(calls) if "rollout restart" in c]
    statuses = [i for i, c in enumerate(calls) if "rollout status" in c]
    assert create < polls[0] and len(polls) == 3, calls
    # The CSI wait comes after the Job succeeded, the restarts after the wait.
    assert polls[-1] < wait < restarts[0] and len(restarts) == 2, calls
    assert max(restarts) < min(statuses) and len(statuses) == 2, calls
    assert any("--set dbPasswords.rotationJob=true" in c for c in calls if c.startswith("helm template"))


def test_rotation_restarts_nothing_when_the_job_failed(run_rotate):
    result, calls = run_rotate("/1")
    assert result.returncode != 0
    assert "half rotated" in result.stderr
    assert not [c for c in calls if "rollout" in c or c.startswith("sleep 1")]


def test_the_local_install_uses_the_merged_application_without_stand_ins():
    assert not (CHART / "values-kind-stubs.yaml").exists()
    assert "values-kind-stubs.yaml" not in script()


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
