"""The CI pipeline (.gitlab-ci.yml, scripts/ci-*.sh) and the test suite's database guard.

The pipeline checks read files only. GitLab's own lint API needs a project token, so these
catch the structural mistakes locally: a job that is not one of the three, an image that is not
pinned by digest, a downloaded tool without a sha256, a job that stops checking what it checks.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from tests.conftest import db_host_allowed

ROOT = Path(__file__).resolve().parent.parent
DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")
# Top-level keys that are settings, not jobs: https://docs.gitlab.com/ci/yaml/
RESERVED = {"workflow", "stages", "default", "variables", "include", "image", "services",
            "cache", "before_script", "after_script"}
JOBS = {"lint", "test", "build"}
SH = shutil.which("sh")
needs_sh = pytest.mark.skipif(SH is None, reason="no POSIX sh on PATH (Git Bash on Windows)")


@pytest.fixture(autouse=True)
def fresh_db():
    """Replaces the autouse fixture of tests/conftest.py for this module. Nothing in here reads
    a database; the original would TRUNCATE the test database before every test, which only
    slows these file checks down and gets in the way of whoever is running the DB suite."""


def _text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def _pipeline() -> dict:
    return yaml.safe_load(_text(".gitlab-ci.yml"))


def _merge(base: dict, override: dict) -> dict:
    """GitLab's `extends` merge: hashes (variables, cache ...) are merged key by key, a later
    value wins; anything else (script, rules, services) is replaced as a whole.
    https://docs.gitlab.com/ci/yaml/yaml_optimization/#merge-details"""
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _jobs() -> dict[str, dict]:
    """Every job with its `extends` templates merged in, in order, then the job itself."""
    pipeline = _pipeline()
    jobs = {}
    for name, body in pipeline.items():
        if name in RESERVED or name.startswith("."):
            continue
        parents = body.get("extends", [])
        merged: dict = {}
        for parent in [parents] if isinstance(parents, str) else parents:
            merged = _merge(merged, pipeline[parent])
        jobs[name] = _merge(merged, body)
    return jobs


def _script(job: str) -> str:
    return "\n".join(_jobs()[job]["script"])


def test_extends_merges_variables_like_gitlab():
    base = {"variables": {"A": "1", "B": "1"}, "script": ["x"]}
    job = _merge(base, {"variables": {"B": "2"}, "script": ["y"]})
    assert job == {"variables": {"A": "1", "B": "2"}, "script": ["y"]}


def _image(spec) -> str:
    return spec["name"] if isinstance(spec, dict) else spec


def _ci_images() -> set[str]:
    """Job images, service images, and the tool images a job runs by name (variables *_IMAGE)."""
    images = set()
    for job in _jobs().values():
        images.add(_image(job["image"]))
        images.update(_image(s) for s in job.get("services", []))
        images.update(v for k, v in job.get("variables", {}).items() if k.endswith("_IMAGE"))
    return images


def _shell_var(path: str, name: str) -> str:
    return re.search(rf"^{name}=(\S+)", _text(path), re.M).group(1)


# --- database guard (tests/conftest.py) ------------------------------------------------------

@pytest.mark.parametrize("host", ["localhost", "127.0.0.1"])
def test_guard_allows_the_local_database(host):
    assert db_host_allowed(host, {})


def test_guard_still_refuses_remote_host():
    # Pins the guard for the test database that scripts/test-db.sh starts: a non-local DB_HOST is
    # refused, a local one is allowed.
    assert not db_host_allowed("db.example.com", {})
    assert db_host_allowed("localhost", {})


@pytest.mark.parametrize("host", ["db.example.com", "10.0.0.5", "prod-db", "postgres"])
def test_guard_refuses_any_other_host_outside_ci(host):
    assert not db_host_allowed(host, {})
    # TEST_DB_SERVICE_HOST alone (no GITLAB_CI from the runner) is not enough.
    assert not db_host_allowed(host, {"TEST_DB_SERVICE_HOST": host})


def test_guard_allows_the_ci_service_alias_only_inside_gitlab_ci():
    env = {"GITLAB_CI": "true", "TEST_DB_SERVICE_HOST": "postgres"}
    assert db_host_allowed("postgres", env)
    assert not db_host_allowed("prod-db", env), "a host other than the declared alias"


@pytest.mark.parametrize("host", ["10.0.0.5", "db.prod.example.com", "Postgres", "-x", ""])
def test_guard_refuses_an_address_or_dotted_name_even_in_ci(host):
    assert not db_host_allowed(host, {"GITLAB_CI": "true", "TEST_DB_SERVICE_HOST": host})


def test_pytest_refuses_to_start_against_a_remote_database():
    """End to end: the guard stops pytest before any test (and any TRUNCATE) runs."""
    env = {**os.environ, "DB_HOST": "db.prod.example.com", "GITLAB_CI": "true",
           "TEST_DB_SERVICE_HOST": "db.prod.example.com"}
    done = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/test_pipeline.py"],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=120, check=False,
    )
    assert done.returncode == 2, done.stdout + done.stderr
    assert "Refusing to run" in done.stdout + done.stderr


# --- pipeline structure ---------------------------------------------------------------------

def test_pipeline_has_exactly_the_three_jobs():
    assert set(_jobs()) == JOBS
    assert _pipeline()["stages"] == ["lint", "test", "build"]
    for name, job in _jobs().items():
        assert job["stage"] == name, f"{name}: one job per stage"


def test_every_job_has_a_stage_an_image_and_a_script():
    pipeline = _pipeline()
    for name, job in _jobs().items():
        assert job.get("stage") in pipeline["stages"], f"{name}: unknown or missing stage"
        assert job.get("image"), f"{name}: no image"
        assert job.get("script"), f"{name}: no script"


def test_every_job_image_is_pinned_by_digest():
    images = _ci_images()
    assert len(images) >= 4, images
    for image in images:
        assert DIGEST.search(image), f"image without digest: {image}"
        assert ":" in image.split("@")[0], f"image without a tag next to the digest: {image}"


def test_pipeline_only_calls_scripts_that_exist():
    for name in _jobs():
        for path in re.findall(r"\bscripts/[\w./-]+\.sh\b", _script(name)):
            assert (ROOT / path).is_file(), f"{name}: {path} is missing"
    assert not (ROOT / "ci").exists(), "the v1 ci/ folder is gone"


def test_ci_runs_the_tests_on_the_images_that_ship():
    jobs = _jobs()
    base = [line.split()[1] for line in _text("Dockerfile").splitlines() if line.startswith("FROM python:")][0]
    assert _image(jobs["lint"]["image"]) == base
    assert _image(jobs["test"]["image"]) == base
    services = [_image(s) for s in jobs["test"]["services"]]
    # The test database is the one scripts/test-db.sh starts on a PC.
    assert services == [_shell_var("scripts/test-db.sh", "IMAGE")]


def test_python_jobs_cache_pip_downloads_keyed_on_the_dev_lock():
    job = _jobs()["test"]
    assert job["cache"]["key"]["files"] == ["requirements-dev.lock"]
    assert job["variables"]["PIP_CACHE_DIR"].endswith(".cache/pip")
    assert "--require-hashes -r requirements-dev.lock" in _script("test")


# --- job 1: lint ----------------------------------------------------------------------------

def test_lint_job_runs_every_check():
    script = _script("lint")
    for command in ("ruff check", "gitleaks git", "terraform fmt -check -recursive", "init -backend=false",
                    'validate', "helm lint"):
        assert command in script, f"lint does not run: {command}"
    # Both environments of the chart.
    assert "values-kind.yaml" in script and "values-azure.yaml" in script


def test_secret_scan_gets_the_full_history():
    job = _jobs()["lint"]
    assert str(job["variables"]["GIT_DEPTH"]) == "0"
    script = _script("lint")
    assert '--log-opts="--all"' in script and "--unshallow" in script
    assert "--redact" in script
    assert "reports/gitleaks.json" in job["artifacts"]["paths"]


def test_terraform_providers_follow_the_committed_lock():
    # -lockfile=readonly: a changed provider or a missing hash fails here, not at the first apply.
    assert "-lockfile=readonly" in _script("lint")


# --- job 2: test ----------------------------------------------------------------------------

def test_test_job_publishes_a_junit_report():
    job = _jobs()["test"]
    assert job["artifacts"]["reports"]["junit"] == "reports/junit.xml"
    assert job["artifacts"]["when"] == "always", "keep the report when tests fail"
    assert "--junitxml=reports/junit.xml" in _script("test")


def test_test_job_prepares_the_database_and_runs_the_whole_suite():
    script = _script("test")
    assert ". scripts/ci-db-setup.sh" in script
    assert script.index(". scripts/ci-db-setup.sh") < script.index("python -m pytest")
    # The whole default suite, so the chart render tests (tests/k8s/test_chart.py) are in it.
    pytest_line = [line for line in _jobs()["test"]["script"] if "python -m pytest" in line][0]
    assert not re.search(r"tests/|-k |--ignore|--deselect", pytest_line), pytest_line


def test_test_job_has_helm_so_the_chart_tests_cannot_skip():
    job = _jobs()["test"]
    assert re.search(r"install_tools\b.*\bhelm\b", _script("test")), "the test job installs helm"
    # The monitoring chart is downloaded and rendered too; a failed download is a failure.
    assert (job.get("variables") or {}).get("AH_REQUIRE_MONITORING_RENDER") == "1"


def test_helm_is_installed_when_the_pipeline_runs_the_tests():
    # tests/k8s/test_chart.py skips itself without helm. Inside GitLab CI that would be a green
    # job that checked nothing, so there the missing binary is a failure.
    if os.environ.get("GITLAB_CI") == "true":
        assert shutil.which("helm"), "helm is not installed in the test job"


def test_ci_database_alias_is_the_postgres_service():
    job = _jobs()["test"]
    alias = job["variables"]["TEST_DB_SERVICE_HOST"]
    assert alias in [s["alias"] for s in job["services"]]
    assert db_host_allowed(alias, {"GITLAB_CI": "true", "TEST_DB_SERVICE_HOST": alias})
    # The service starts with the bootstrap password that scripts/ci-db-setup.sh logs in with.
    service_password = job["services"][0]["variables"]["POSTGRES_PASSWORD"]
    assert job["variables"]["POSTGRES_BOOTSTRAP_PASSWORD"] == service_password
    setup = _text("scripts/ci-db-setup.sh")
    assert "$POSTGRES_BOOTSTRAP_PASSWORD" in setup and "$TEST_DB_SERVICE_HOST" in setup


@needs_sh
def test_db_setup_script_has_its_helpers_and_valid_syntax():
    # The v1 script sourced ci/lib.sh for rand_hex; it must now carry it.
    setup = _text("scripts/ci-db-setup.sh")
    assert re.search(r"^rand_hex\(\) \{", setup, re.M)
    assert "lib.sh" not in setup
    assert subprocess.run([SH, "-n", "scripts/ci-db-setup.sh"], cwd=ROOT, check=False).returncode == 0


# --- pinned tools (scripts/ci-tools.sh) -----------------------------------------------------

def _tool_pins() -> dict[str, dict[str, str]]:
    text = _text("scripts/ci-tools.sh")
    pins: dict[str, dict[str, str]] = {}
    for name, field, value in re.findall(r"^([A-Z]+)_(VERSION|URL|SHA256)=(\S+)$", text, re.M):
        pins.setdefault(name, {})[field] = value
    return pins


def test_every_downloaded_tool_has_a_version_a_url_and_a_sha256():
    pins = _tool_pins()
    assert set(pins) == {"RUFF", "GITLEAKS", "TERRAFORM", "HELM"}
    for name, pin in pins.items():
        assert set(pin) == {"VERSION", "URL", "SHA256"}, name
        assert re.fullmatch(r"[0-9a-f]{64}", pin["SHA256"]), name
        assert pin["URL"].startswith("https://"), name
        assert pin["VERSION"] in pin["URL"], f"{name}: the URL is not the pinned version"


def test_terraform_version_is_the_one_the_stacks_ask_for():
    version = _tool_pins()["TERRAFORM"]["VERSION"]
    for versions_tf in (ROOT / "infra").rglob("versions.tf"):
        constraint = re.search(r'required_version\s*=\s*"~>\s*(\d+\.\d+)', versions_tf.read_text(encoding="utf-8"))
        assert constraint and version.startswith(constraint.group(1) + "."), versions_tf


def test_every_job_that_downloads_a_tool_names_only_known_tools():
    for name in _jobs():
        for line in _jobs()[name]["script"]:
            m = re.match(r"install_tools (.+)", line)
            if m:
                assert set(m.group(1).split()) <= {"ruff", "gitleaks", "terraform", "helm"}, line
    assert "install_tools" in _script("lint")


@needs_sh
@pytest.mark.parametrize("good", [True, False])
def test_a_download_is_used_only_when_its_sha256_matches(tmp_path, good):
    payload = tmp_path / "payload.bin"
    payload.write_bytes(b"a tool that is not the pinned one")
    expected = hashlib.sha256(payload.read_bytes()).hexdigest() if good else "0" * 64
    target = tmp_path / "out.bin"
    done = subprocess.run(
        [SH, "-c", f'. scripts/ci-tools.sh && download_checked "{payload.as_uri()}" {expected} "{target.as_posix()}"'],
        cwd=ROOT, capture_output=True, text=True, timeout=60, check=False)
    if good:
        assert done.returncode == 0, done.stderr
        assert target.read_bytes() == payload.read_bytes()
    else:
        assert done.returncode != 0
        assert "expected" in done.stderr
        assert not target.exists(), "a file with the wrong hash must not stay behind"


# --- job 3: build ---------------------------------------------------------------------------

def test_build_job_talks_tls_to_the_docker_service():
    # https://docs.gitlab.com/ci/docker/docker_in_docker/ ("TLS enabled")
    variables = _jobs()["build"]["variables"]
    assert variables["DOCKER_HOST"] == "tcp://docker:2376"
    assert variables["DOCKER_TLS_CERTDIR"] == "/certs"
    assert str(variables["DOCKER_TLS_VERIFY"]) == "1"
    assert variables["DOCKER_CERT_PATH"] == "$DOCKER_TLS_CERTDIR/client"


def test_build_job_waits_for_the_daemon_before_building():
    script = _script("build")
    assert "docker info" in script
    assert script.index("docker info") < script.index("docker build")


def test_build_job_scans_the_image_and_keeps_the_full_trivy_report():
    job = _jobs()["build"]
    assert job["artifacts"]["when"] == "always"
    assert "reports/trivy-all.json" in job["artifacts"]["paths"]
    assert job["artifacts"]["reports"]["container_scanning"] == "reports/gl-container-scanning-report.json"
    script = _script("build")
    report_run = script[script.index("# 1. Report"):script.index("# 2. Gate")]
    assert "--exit-code 0" in report_run and "--ignore-unfixed" not in report_run
    gate = script[script.index("# 2. Gate"):]
    assert "--severity HIGH,CRITICAL" in gate and "--ignore-unfixed" in gate and "--exit-code 1" in gate
    assert DIGEST.search(job["variables"]["TRIVY_IMAGE"])
