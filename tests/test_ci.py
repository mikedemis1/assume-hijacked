"""The CI pipeline (.gitlab-ci.yml, ci/*.sh) and the test suite's database guard.

The pipeline checks read files only. GitLab's own lint API needs a project token, so these
catch the structural mistakes locally: a job without image/stage/script, an image that is not
pinned by digest, the local scripts drifting from the pipeline, the slow mutation job running on
every push.
"""
from __future__ import annotations

import importlib.util
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest
import yaml

from tests.conftest import db_host_allowed

ROOT = Path(__file__).resolve().parent.parent
DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")
# Top-level keys that are settings, not jobs: https://docs.gitlab.com/ci/yaml/
RESERVED = {"workflow", "stages", "default", "variables", "include", "image", "services",
            "cache", "before_script", "after_script"}


def _pipeline() -> dict:
    return yaml.safe_load((ROOT / ".gitlab-ci.yml").read_text(encoding="utf-8"))


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


def test_extends_merges_variables_like_gitlab():
    base = {"variables": {"A": "1", "B": "1"}, "script": ["x"]}
    job = _merge(base, {"variables": {"B": "2"}, "script": ["y"]})
    assert job == {"variables": {"A": "1", "B": "2"}, "script": ["y"]}


def _image(spec) -> str:
    return spec["name"] if isinstance(spec, dict) else spec


def _ci_images() -> set[str]:
    images = set()
    for job in _jobs().values():
        images.add(_image(job["image"]))
        images.update(_image(s) for s in job.get("services", []))
    return images


def _lib_images() -> dict[str, str]:
    text = (ROOT / "ci" / "lib.sh").read_text(encoding="utf-8")
    return dict(re.findall(r'^([A-Z_]+_IMAGE)="([^"]+)"', text, re.M))


# --- database guard (tests/conftest.py) ------------------------------------------------------

@pytest.mark.parametrize("host", ["localhost", "127.0.0.1"])
def test_guard_allows_the_local_database(host):
    assert db_host_allowed(host, {})


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
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/test_ci.py"],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=120, check=False,
    )
    assert done.returncode == 2, done.stdout + done.stderr
    assert "Refusing to run" in done.stdout + done.stderr


# --- pipeline structure ---------------------------------------------------------------------

def test_every_job_has_a_stage_an_image_and_a_script():
    pipeline = _pipeline()
    jobs = _jobs()
    assert {"secrets", "sast", "deps", "lint-container-hadolint", "lint-container-checkov",
            "test", "mutation", "build-scan", "smoke", "lock-check"} <= set(jobs)
    for name, job in jobs.items():
        assert job.get("stage") in pipeline["stages"], f"{name}: unknown or missing stage"
        assert job.get("image"), f"{name}: no image"
        assert job.get("script"), f"{name}: no script"


def test_every_job_calls_one_ci_script_that_exists():
    for name, job in _jobs().items():
        assert len(job["script"]) == 1, f"{name}: one script per job, so it runs locally too"
        m = re.fullmatch(r"sh (ci/[a-z-]+\.sh)", job["script"][0])
        assert m, f"{name}: script should be `sh ci/<name>.sh`, got {job['script'][0]!r}"
        assert (ROOT / m.group(1)).is_file(), f"{name}: {m.group(1)} is missing"


def test_every_ci_image_is_pinned_by_digest():
    images = _ci_images() | set(_lib_images().values())
    for line in (ROOT / "ci" / "smoke-runner.Dockerfile").read_text(encoding="utf-8").splitlines():
        if line.startswith("FROM "):
            images.add(line.split()[1])
    assert images
    for image in images:
        assert DIGEST.search(image), f"image without digest: {image}"
        assert ":" in image.split("@")[0], f"image without a tag next to the digest: {image}"


def test_local_scripts_use_the_same_images_as_the_pipeline():
    lib = _lib_images()
    ci = _ci_images()
    # The tool images run as job images in CI and through `docker run` on a PC.
    for var in ("GITLEAKS_IMAGE", "HADOLINT_IMAGE", "CHECKOV_IMAGE", "PYTHON_IMAGE"):
        assert lib[var] in ci, f"ci/lib.sh {var}={lib[var]} is not the image in .gitlab-ci.yml"
    # Every other CI image is either Docker itself (CI only; a PC has Docker Desktop) or the
    # compose db image used as the test service. trivy runs from lib.sh in both places.
    others = ci - set(lib.values())
    assert all(i.startswith("docker:") or i == _compose_db_image() for i in others), others
    assert "TRIVY_IMAGE" in lib


def _compose_db_image() -> str:
    text = (ROOT / "compose.yaml").read_text(encoding="utf-8")
    return re.search(r"^\s*image:\s*(\S+)", text, re.M).group(1)


def _dockerfile_base_image() -> str:
    text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    return [line.split()[1] for line in text.splitlines() if line.startswith("FROM python:")][0]


def test_ci_tests_run_on_the_images_that_ship():
    jobs = _jobs()
    python_jobs = [name for name, job in jobs.items() if _image(job["image"]).startswith("python:")]
    assert {"test", "mutation", "sast", "deps"} <= set(python_jobs)
    for name in python_jobs:
        assert _image(jobs[name]["image"]) == _dockerfile_base_image(), name
    for name in ("test", "mutation"):
        services = [_image(s) for s in jobs[name]["services"]]
        assert services == [_compose_db_image()], name


def test_mutation_job_never_runs_on_a_push():
    rules = _jobs()["mutation"]["rules"]
    for rule in rules:
        assert rule.get("if") == '$CI_PIPELINE_SOURCE == "schedule"' or (
            rule.get("when") == "manual" and "if" not in rule
        ), f"mutation rule would run it automatically: {rule}"


def test_test_job_publishes_a_junit_report():
    job = _jobs()["test"]
    assert job["artifacts"]["reports"]["junit"] == "reports/junit.xml"
    assert job["artifacts"]["when"] == "always", "keep the report when tests fail"
    assert "--junitxml=reports/junit.xml" in (ROOT / "ci" / "test.sh").read_text(encoding="utf-8")


def test_secret_scan_gets_the_full_history():
    assert str(_jobs()["secrets"]["variables"]["GIT_DEPTH"]) == "0"
    script = (ROOT / "ci" / "secrets.sh").read_text(encoding="utf-8")
    assert '--log-opts="--all"' in script and "--unshallow" in script


def test_ci_database_alias_is_the_postgres_service():
    for name in ("test", "mutation"):
        job = _jobs()[name]
        aliases = [s["alias"] for s in job["services"]]
        assert job["variables"]["TEST_DB_SERVICE_HOST"] in aliases, name
        assert db_host_allowed(job["variables"]["TEST_DB_SERVICE_HOST"],
                               {"GITLAB_CI": "true", "TEST_DB_SERVICE_HOST": job["variables"]["TEST_DB_SERVICE_HOST"]})
        # The service starts with the bootstrap password that ci/db-setup.sh logs in with.
        service_password = job["services"][0]["variables"]["POSTGRES_PASSWORD"]
        assert job["variables"]["POSTGRES_BOOTSTRAP_PASSWORD"] == service_password, name
    lib = (ROOT / "ci" / "lib.sh").read_text(encoding="utf-8")
    assert f'CI_POSTGRES_BOOTSTRAP_PASSWORD="{service_password}"' in lib, "ci/lib.sh (PC runs) differs"


def test_every_mutation_module_has_a_job_and_a_baseline():
    """The matrix covers the whole mutmut scope, and each entry has a README baseline (the job
    fails without one)."""
    matrix = _jobs()["mutation"]["parallel"]["matrix"]
    patterns = [p for entry in matrix for p in entry["MUTANTS"]]
    scope = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["mutmut"]
    for path in scope["only_mutate"]:
        module = path.removesuffix(".py").removesuffix("/*").replace("/", ".")
        assert any(p.rstrip("*") == module for p in patterns), f"{path} has no mutation job"
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for pattern in patterns:
        assert re.search(rf"Mutation score baseline `{re.escape(pattern)}`: [0-9]+(\.[0-9]+)?%", readme), (
            f"no README baseline for {pattern}"
        )


def test_mutation_jobs_start_at_once_and_are_not_cancelled_by_a_push():
    job = _jobs()["mutation"]
    assert job["needs"] == [], "a red build or smoke job must not skip the scheduled mutation run"
    assert job["interruptible"] is False, "a new push must not cancel a long mutation run"


def _mutation_score():
    spec = importlib.util.spec_from_file_location("mutation_score", ROOT / "ci" / "mutation_score.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _stats(killed, survived, **extra):
    return {"killed": killed, "survived": survived, "timeout": 0, "no_tests": 0,
            "suspicious": 0, "segfault": 0, "skipped": 0, **extra}


def test_mutation_score_is_compared_at_the_recorded_precision():
    ms = _mutation_score()
    # guard on 2026-10-15: 174 of 216 = 80.556%, recorded in the README as 80.6%.
    assert ms.meets_baseline(ms.score(_stats(174, 42)), 80.6)
    # one more survivor: 173 of 216 = 80.09%, a real drop.
    assert not ms.meets_baseline(ms.score(_stats(173, 43)), 80.6)


def test_mutation_score_counts_untested_mutants_as_not_caught():
    ms = _mutation_score()
    assert ms.score(_stats(3, 0, timeout=1, no_tests=4)) == 50.0
    with pytest.raises(ValueError):
        ms.score(_stats(0, 0))


def test_python_jobs_cache_pip_downloads_keyed_on_the_dev_lock():
    for name, job in _jobs().items():
        if not _image(job["image"]).startswith("python:"):
            continue
        assert job["cache"]["key"]["files"] == ["requirements-dev.lock"], name
        assert job["variables"]["PIP_CACHE_DIR"].endswith(".cache/pip"), name
    assert "--require-hashes" in (ROOT / "ci" / "lib.sh").read_text(encoding="utf-8")


def test_build_scan_keeps_the_full_trivy_report():
    job = _jobs()["build-scan"]
    assert job["artifacts"]["when"] == "always"
    assert "reports/trivy-all.json" in job["artifacts"]["paths"]
    assert job["artifacts"]["reports"]["container_scanning"] == "reports/gl-container-scanning-report.json"
    script = (ROOT / "ci" / "build-scan.sh").read_text(encoding="utf-8")
    report_run = script[script.index("# 1. Report"):script.index("# 2. Gate")]
    assert "--exit-code 0" in report_run and "--ignore-unfixed" not in report_run


# --- final review F5 -----------------------------------------------------------------------

def test_dind_jobs_talk_tls_to_the_docker_service():
    # https://docs.gitlab.com/ci/docker/docker_in_docker/ ("TLS enabled")
    for name in ("build-scan", "smoke"):
        variables = _jobs()[name]["variables"]
        assert variables["DOCKER_HOST"] == "tcp://docker:2376", name
        assert variables["DOCKER_TLS_CERTDIR"] == "/certs", name
        assert str(variables["DOCKER_TLS_VERIFY"]) == "1", name
        assert variables["DOCKER_CERT_PATH"] == "$DOCKER_TLS_CERTDIR/client", name


@pytest.mark.parametrize("script, first_docker_use", [
    ("ci/build-scan.sh", "docker build"),
    ("ci/smoke.sh", "docker compose up"),
])
def test_dind_scripts_wait_for_the_daemon_before_building(script, first_docker_use):
    text = (ROOT / script).read_text(encoding="utf-8")
    assert "wait_for_docker" in text, script
    assert text.index("wait_for_docker") < text.index(first_docker_use), script
    lib = (ROOT / "ci" / "lib.sh").read_text(encoding="utf-8")
    body = lib[lib.index("wait_for_docker() {"):]
    assert "docker info" in body[:body.index("\n}")]


def test_smoke_control_container_is_the_pinned_python_image():
    from tests import test_smoke

    assert test_smoke.CONTROL_IMAGE == _lib_images()["PYTHON_IMAGE"]
    assert DIGEST.search(test_smoke.CONTROL_IMAGE)
    assert '"python:3.12-slim"' not in (ROOT / "tests" / "test_smoke.py").read_text(encoding="utf-8")


@pytest.mark.parametrize("value", ["", "0", "false", "False", "no"])
def test_no_proof_skips_when_ci_is_not_set_to_true(monkeypatch, value):
    from tests.test_smoke import no_proof

    monkeypatch.setenv("CI", value)
    with pytest.raises(pytest.skip.Exception):
        no_proof("offline")


@pytest.mark.parametrize("value", ["true", "1", "yes"])
def test_no_proof_fails_in_ci(monkeypatch, value):
    from tests.test_smoke import no_proof

    monkeypatch.setenv("CI", value)
    with pytest.raises(pytest.fail.Exception):
        no_proof("offline")
