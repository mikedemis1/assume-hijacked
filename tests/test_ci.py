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
import shutil
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
    for var in ("GITLEAKS_IMAGE", "HADOLINT_IMAGE", "CHECKOV_IMAGE", "PYTHON_IMAGE", "TERRAFORM_IMAGE",
                "TFLINT_IMAGE", "HELM_IMAGE", "AZURE_CLI_IMAGE"):
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


def test_mutmut_does_not_run_the_tests_that_need_the_repository_or_the_stack():
    """mutmut runs pytest from its mutants/ copy (app/, tests/, pyproject.toml, db/sql/): no ci/,
    no locks, no Compose stack. These files would fail to collect or to run there (the job once
    died with "failed to collect stats" on tests/test_smoke.py)."""
    scope = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["mutmut"]
    ignored = scope["pytest_add_cli_args_test_selection"]
    for name in ("test_ci", "test_supply_chain", "test_smoke"):
        assert f"--ignore=tests/{name}.py" in ignored, name


def test_smoke_tests_import_without_the_ci_folder(tmp_path):
    """A copy of tests/test_smoke.py with no ci/ next to it (the mutants/ layout) must still
    import: pytest collects the whole module before it can skip or ignore anything in it."""
    (tmp_path / "tests").mkdir()
    copy = tmp_path / "tests" / "test_smoke.py"
    copy.write_text((ROOT / "tests" / "test_smoke.py").read_text(encoding="utf-8"), encoding="utf-8")
    assert not (tmp_path / "ci").exists()
    spec = importlib.util.spec_from_file_location("smoke_copy_without_ci", copy)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # raised FileNotFoundError when it read ci/lib.sh at import


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

    assert test_smoke.control_image() == _lib_images()["PYTHON_IMAGE"]
    assert DIGEST.search(test_smoke.control_image())
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


# --- IaC checks, chart tests and the Azure jobs -------------------------------------------

@pytest.fixture(autouse=True)
def fresh_db():
    """Replaces the autouse fixture of tests/conftest.py for this module. Nothing in here reads
    a database; the original would TRUNCATE the test database before every test, which only
    slows these file checks down and gets in the way of whoever is running the DB suite."""


SH = shutil.which("sh")
needs_sh = pytest.mark.skipif(SH is None, reason="no POSIX sh on PATH (Git Bash on Windows)")
IAC_STEPS = {"iac-terraform": ("terraform", "TERRAFORM_IMAGE"),
             "iac-tflint": ("tflint", "TFLINT_IMAGE"),
             "iac-checkov": ("checkov", "CHECKOV_IMAGE")}
AZURE_JOBS = ("tf-plan", "tf-apply", "tf-destroy-plan", "tf-destroy", "leftover-check")
OIDC_AUDIENCE = "api://AzureADTokenExchange"


def _text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_iac_jobs_run_on_every_push_with_one_step_and_the_pinned_tool_image():
    jobs = _jobs()
    lib = _lib_images()
    for name, (step, var) in IAC_STEPS.items():
        job = jobs[name]
        assert job["stage"] == "iac", name
        assert "rules" not in job and "only" not in job, f"{name} must run on every push"
        assert job["script"] == ["sh ci/iac.sh"], name
        assert job["variables"]["IAC_STEP"] == step, name
        assert _image(job["image"]) == lib[var], f"{name}: image differs from ci/lib.sh {var}"
        assert DIGEST.search(_image(job["image"])), name
    assert jobs["iac-checkov"]["variables"]["IAC_REQUIRE_DEPLOY"] == "true", (
        "a pipeline without deploy/ must fail, not scan nothing")


def test_chart_tests_job_runs_the_helm_chart_tests_on_a_pinned_helm_image():
    """The chart tests skip themselves without helm, so CI needs a job that has it. This only
    checks the job and the script; the chart and tests/k8s/ are not part of this checkout."""
    job = _jobs()["chart-tests"]
    assert job["stage"] == "iac" and "rules" not in job
    assert DIGEST.search(_image(job["image"]))
    assert _image(job["image"]) == _lib_images()["HELM_IMAGE"]
    assert _image(job["image"]).startswith("alpine/helm:")
    assert job["script"] == ["sh ci/chart.sh"]
    script = _text("ci/chart.sh")
    assert "tests/k8s/test_chart.py" in script
    assert "SKIPPED" in script, "a skipped chart test must fail the job"
    assert "requirements-dev.lock" in script and "--require-hashes" in script
    assert job["artifacts"]["reports"]["junit"] == "reports/chart-junit.xml"


def test_iac_script_runs_every_check_the_brief_names():
    script = _text("ci/iac.sh")
    for needed in ("fmt -check", "init -backend=false", "-lockfile=readonly", "validate",
                   'terraform -chdir="$stack" test', "tflint", "checkov_run infra",
                   "--framework kubernetes", "--skip-path tests"):
        assert needed in script, needed
    for stack in ("infra/base", "infra/net", "infra/lab", "infra/modules/workload-identity"):
        assert stack in script, stack
    tflint = _text(".tflint.hcl")
    assert re.search(r'plugin "azurerm" \{[^}]*version\s*=\s*"\d+\.\d+\.\d+"', tflint), (
        "the azurerm ruleset must be pinned")


def test_azure_jobs_are_manual_and_off_until_azure_enabled():
    jobs = _jobs()
    for name in AZURE_JOBS:
        job = jobs[name]
        assert job["stage"] == "azure", name
        assert job["rules"], f"{name} has no rules, so it would run on every push"
        for rule in job["rules"]:
            assert rule.get("when") == "manual", f"{name}: a rule that is not manual: {rule}"
            assert '$AZURE_ENABLED == "true"' in rule.get("if", ""), f"{name}: rule without AZURE_ENABLED"
        assert "only" not in job and "except" not in job, name
    for name in ("tf-apply", "tf-destroy"):
        condition = jobs[name]["rules"][0]["if"]
        assert "$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH" in condition, f"{name} must be main only"
        assert jobs[name]["resource_group"] == "azure-lab", f"{name}: one deployment at a time"
        assert jobs[name]["interruptible"] is False, f"{name}: a new push must not cancel it"


@pytest.mark.parametrize("apply_job, plan_job, folder", [("tf-apply", "tf-plan", "plans/apply/"),
                                                         ("tf-destroy", "tf-destroy-plan", "plans/destroy/")])
def test_apply_and_destroy_need_the_plan_job_of_the_same_pipeline_and_its_files(apply_job, plan_job, folder):
    jobs = _jobs()
    assert jobs[apply_job]["needs"] == [{"job": plan_job, "artifacts": True}], (
        "the plan files come from the plan job of this pipeline, nowhere else")
    artifacts = jobs[plan_job]["artifacts"]
    assert artifacts["paths"] == [folder] and artifacts["when"] == "always"
    assert artifacts["expire_in"] == "1 day", "plan files can hold resource values"
    assert "artifacts" not in jobs[apply_job] or not jobs[apply_job]["artifacts"]
    for rule in jobs[plan_job]["rules"]:
        assert "CI_DEFAULT_BRANCH" not in rule["if"], f"{plan_job} runs on any branch"
    script = _text(f"ci/{apply_job}.sh")
    code = [line for line in script.splitlines() if not line.lstrip().startswith("#")]
    assert any("require_plan" in line for line in code)
    assert not any(re.search(r"terraform\s.*\splan\s", line) for line in code), (
        f"{apply_job} must apply the saved files and never plan")


def test_azure_jobs_authenticate_with_an_id_token_and_store_no_secret():
    jobs = _jobs()
    for name in AZURE_JOBS:
        assert jobs[name]["id_tokens"] == {"AZURE_ID_TOKEN": {"aud": OIDC_AUDIENCE}}, name
        assert DIGEST.search(_image(jobs[name]["image"])), name
        assert not jobs[name].get("variables"), f"{name}: values belong in project variables"
    pipeline = _text(".gitlab-ci.yml")
    scripts = "".join(_text(f"ci/{n}") for n in
                      ("tf-common.sh", "tf-plan.sh", "tf-apply.sh", "tf-destroy-plan.sh", "tf-destroy.sh",
                       "leftover-check.sh"))
    for text in (pipeline, scripts):
        assert not re.search(r"CLIENT_SECRET|client_secret|ARM_ACCESS_KEY|--password|login[^\n]* -p ", text)
    assert "ARM_OIDC_TOKEN" in scripts and "--federated-token" in scripts


def test_local_only_tls_workaround_is_never_set_by_the_pipeline_or_a_script():
    """TF_DISABLE_PLUGIN_TLS=1 works around the antivirus on one PC; nothing committed may set it."""
    files = [ROOT / ".gitlab-ci.yml", *sorted((ROOT / "ci").glob("*.sh"))]
    for path in files:
        text = path.read_text(encoding="utf-8")
        assert not re.search(r"TF_DISABLE_PLUGIN_TLS\s*[=:]", text), path.name
        assert not re.search(r"export\s+TF_DISABLE_PLUGIN_TLS", text), path.name


def test_new_tool_images_in_lib_are_all_used_by_a_job():
    lib = _lib_images()
    used = _ci_images()
    for var in ("TERRAFORM_IMAGE", "TFLINT_IMAGE", "HELM_IMAGE", "AZURE_CLI_IMAGE"):
        assert lib[var] in used, f"{var} is in ci/lib.sh but no job uses it"


# Behaviour of the Azure scripts, with stand-ins for terraform and az on PATH. The stand-in
# terraform appends its arguments, and the Azure settings it was started with, to a log. It
# writes the file named by `plan -out=`, and `apply <file>` fails when that file is missing, like
# the real one. The scratch directory plays the part of the pipeline: the plans/ folder that
# one script leaves is the artifact the next one finds.

TERRAFORM_STANDIN = """#!/bin/sh
echo "terraform $*" >> "$STANDIN_LOG"
echo "env ARM_OIDC_TOKEN=${ARM_OIDC_TOKEN:-} ARM_CLIENT_ID=${ARM_CLIENT_ID:-} ARM_USE_OIDC=${ARM_USE_OIDC:-}" >> "$STANDIN_LOG"
case "$*" in
  *"state list"*)
    printf '%s' "${STANDIN_STATE:-}"
    exit "${STANDIN_STATE_RC:-0}" ;;
  *" plan "*)
    for a in "$@"; do
      case "$a" in -out=*) echo "plan file" > "${a#-out=}" ;; esac
    done
    exit "${STANDIN_PLAN_RC:-0}" ;;
  *" show "*) echo "Plan: 1 to add, 0 to change, 0 to destroy." ;;
  *" apply "*)
    for last in "$@"; do :; done
    [ -f "$last" ] || { echo "Error: Failed to load plan file $last" >&2; exit 1; }
    exit "${STANDIN_APPLY_RC:-0}" ;;
esac
exit 0
"""
AZ_STANDIN = """#!/bin/sh
echo "az $*" >> "$STANDIN_LOG"
case "$*" in
  "resource list"*) printf '%s' "${STANDIN_RESOURCES:-}" ;;
esac
exit 0
"""
AZURE_ENV = {
    "AZURE_ENABLED": "true", "AZURE_ID_TOKEN": "token-from-gitlab", "AZURE_TENANT_ID": "tenant-1",
    "AZURE_SUBSCRIPTION_ID": "sub-1", "AZURE_CI_PLAN_CLIENT_ID": "client-plan",
    "AZURE_CI_APPLY_CLIENT_ID": "client-apply", "TF_STATE_STORAGE_ACCOUNT": "stateacct",
    "CI_COMMIT_BRANCH": "main", "CI_DEFAULT_BRANCH": "main", "CI_COMMIT_SHA": "abc123",
}


def _scratch_repo(tmp_path, standins: dict[str, str]):
    """A copy of ci/ and empty infra stacks, with stand-in tools first on PATH."""
    shutil.copytree(ROOT / "ci", tmp_path / "ci", ignore=shutil.ignore_patterns("__pycache__"))
    for stack in ("base", "net", "lab"):
        (tmp_path / "infra" / stack).mkdir(parents=True)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in standins.items():
        (bin_dir / name).write_text(body, encoding="utf-8", newline="\n")
    return str(bin_dir) + os.pathsep + os.environ["PATH"]


@pytest.fixture
def azure_run(tmp_path):
    """run(script, **env) -> (CompletedProcess, log lines of that run). Runs the real ci/ scripts
    from a scratch copy, with terraform and az replaced by stand-ins. Files the scripts leave
    (plans/) stay for the next run, like artifacts. An env value of "" blanks a variable."""
    path = _scratch_repo(tmp_path, {"terraform": TERRAFORM_STANDIN, "az": AZ_STANDIN})
    log = tmp_path / "standin.log"

    def run(script: str, **env):
        merged = {**os.environ, **AZURE_ENV, **env, "STANDIN_LOG": str(log), "PATH": path}
        done = subprocess.run([SH, f"ci/{script}"], cwd=tmp_path, env=merged, capture_output=True,
                              text=True, timeout=60, check=False)
        lines = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
        if log.exists():
            log.unlink()
        return done, lines

    run.root = tmp_path
    return run


def _terraform_calls(lines):
    return [line for line in lines if line.startswith("terraform ")]


def _stack(call: str) -> str:
    return re.search(r"-chdir=(\S+)", call).group(1)


def _kinds(calls):
    """(stack, subcommand) for each terraform call; the subcommand follows -chdir=<stack>."""
    return [(_stack(c), c.split()[2]) for c in calls]


@needs_sh
def test_plan_saves_each_plan_for_the_apply_job_and_never_applies(azure_run):
    done, lines = azure_run("tf-plan.sh", CI_COMMIT_BRANCH="feature/x")  # any branch
    assert done.returncode == 0, done.stdout + done.stderr
    calls = _terraform_calls(lines)
    assert _kinds(calls) == [("infra/net", "init"), ("infra/net", "plan"), ("infra/net", "show"),
                             ("infra/lab", "init"), ("infra/lab", "plan"), ("infra/lab", "show")]
    plans = [c for c in calls if " plan " in c]
    assert all("-lock=false" in c and "-detailed-exitcode" in c for c in plans)
    assert not any(" apply " in c or "infra/base" in c for c in calls)
    folder = azure_run.root / "plans" / "apply"
    for name in ("net", "lab"):
        assert (folder / f"{name}.tfplan").is_file() and (folder / f"{name}.txt").is_file()
        assert (folder / f"{name}.changes").read_text(encoding="utf-8").strip() == "no"
    assert (folder / "commit").read_text(encoding="utf-8").strip() == "abc123"
    assert "ARM_CLIENT_ID=client-plan" in "".join(lines)
    assert "Plan: 1 to add" in done.stdout, "the plan is printed in the job log"


@needs_sh
def test_a_failed_plan_fails_the_job(azure_run):
    done, _ = azure_run("tf-plan.sh", STANDIN_PLAN_RC="1")
    assert done.returncode != 0 and "plan failed" in done.stderr


@needs_sh
def test_var_files_come_from_file_variables_when_set(azure_run, tmp_path):
    vars_file = tmp_path / "net.tfvars"
    vars_file.write_text("", encoding="utf-8")
    _, lines = azure_run("tf-plan.sh", TFVARS_NET=str(vars_file))
    plans = [c for c in _terraform_calls(lines) if " plan " in c]
    assert f"-var-file={vars_file}" in plans[0] and "-var-file" not in plans[1]


@needs_sh
def test_apply_runs_the_saved_plans_net_then_lab_and_never_plans(azure_run):
    assert azure_run("tf-plan.sh")[0].returncode == 0
    done, lines = azure_run("tf-apply.sh")
    assert done.returncode == 0, done.stdout + done.stderr
    calls = _terraform_calls(lines)
    assert _kinds(calls) == [("infra/net", "init"), ("infra/net", "apply"),
                             ("infra/lab", "init"), ("infra/lab", "apply")]
    assert not any(" plan " in c or "infra/base" in c for c in calls), "apply never plans"
    assert all("-auto-approve" not in c for c in calls)
    plan_files = [c.split()[-1] for c in calls if " apply " in c]
    assert [Path(p).name for p in plan_files] == ["net.tfplan", "lab.tfplan"]
    assert all(Path(p).parent.name == "apply" and Path(p).parent.parent.name == "plans"
               for p in plan_files), "the files tf-plan saved"
    assert "-backend-config=key=net.tfstate" in calls[0] and "-backend-config=key=lab.tfstate" in calls[2]
    assert "-lockfile=readonly" in calls[0]
    text = "".join(lines)
    assert "ARM_CLIENT_ID=client-apply" in text and "ARM_OIDC_TOKEN=token-from-gitlab" in text
    override = (azure_run.root / "infra" / "net" / "zz_backend_override.tf").read_text(encoding="utf-8")
    assert 'backend "azurerm" {}' in override


@needs_sh
def test_apply_without_a_saved_plan_or_with_a_plan_of_another_commit_fails_before_terraform(azure_run):
    done, lines = azure_run("tf-apply.sh")
    assert done.returncode != 0 and "no saved plan" in done.stderr and lines == []
    azure_run("tf-plan.sh")
    (azure_run.root / "plans" / "apply" / "lab.tfplan").unlink()
    done, lines = azure_run("tf-apply.sh")
    assert done.returncode != 0 and "no saved plan" in done.stderr
    assert not any(" apply " in c for c in _terraform_calls(lines)), "net must not be applied alone"
    azure_run("tf-plan.sh")
    done, lines = azure_run("tf-apply.sh", CI_COMMIT_SHA="def456")
    assert done.returncode != 0 and "another commit" in done.stderr and lines == []


@needs_sh
def test_apply_stops_before_lab_when_net_changed(azure_run):
    """The lab plan was made against the old net state: net is applied, lab is not."""
    azure_run("tf-plan.sh", STANDIN_PLAN_RC="2")  # both plans have changes
    done, lines = azure_run("tf-apply.sh")
    assert done.returncode != 0 and "tf-plan again" in done.stderr
    assert _kinds(_terraform_calls(lines)) == [("infra/net", "init"), ("infra/net", "apply")]


@needs_sh
def test_apply_and_destroy_refuse_to_run_off_the_default_branch(azure_run):
    azure_run("tf-plan.sh")
    azure_run("tf-destroy-plan.sh")
    for script in ("tf-apply.sh", "tf-destroy.sh"):
        done, lines = azure_run(script, CI_COMMIT_BRANCH="feature/x")
        assert done.returncode != 0 and "default branch" in done.stderr, script
        assert lines == [], f"{script} must stop before terraform runs"
    assert azure_run("tf-apply.sh")[0].returncode == 0, "control: the same job on main runs"


@needs_sh
@pytest.mark.parametrize("missing", ["AZURE_ENABLED", "AZURE_ID_TOKEN", "AZURE_CI_APPLY_CLIENT_ID",
                                     "TF_STATE_STORAGE_ACCOUNT"])
def test_azure_scripts_stop_without_their_inputs(azure_run, missing):
    azure_run("tf-plan.sh")
    done, lines = azure_run("tf-apply.sh", **{missing: ""})
    assert done.returncode != 0, missing
    assert not any(" apply " in c for c in _terraform_calls(lines)), missing


@needs_sh
def test_destroy_plan_goes_lab_then_net_and_saves_destroy_plans(azure_run):
    state = "data.azurerm_resource_group.lab\nazurerm_firewall.hub[0]\n"
    done, lines = azure_run("tf-destroy-plan.sh", STANDIN_STATE=state)
    assert done.returncode == 0, done.stdout + done.stderr
    calls = _terraform_calls(lines)
    assert _kinds(calls) == [("infra/lab", "init"), ("infra/lab", "state"), ("infra/lab", "plan"),
                             ("infra/lab", "show"), ("infra/net", "init"), ("infra/net", "state"),
                             ("infra/net", "plan"), ("infra/net", "show")]
    assert all("-destroy" in c and "-lock=false" in c for c in calls if " plan " in c)
    assert not any(" apply " in c or "infra/base" in c for c in calls)
    assert (azure_run.root / "plans" / "destroy" / "lab.tfplan").is_file()
    assert "ARM_CLIENT_ID=client-plan" in "".join(lines)


@needs_sh
def test_destroy_runs_the_saved_destroy_plans_lab_then_net_after_checking_both_states(azure_run):
    state = "data.azurerm_resource_group.lab\nmodule.x.data.azurerm_resource_group.y\nazurerm_firewall.hub[0]\n"
    assert azure_run("tf-destroy-plan.sh", STANDIN_STATE=state)[0].returncode == 0
    done, lines = azure_run("tf-destroy.sh", STANDIN_STATE=state)
    assert done.returncode == 0, done.stdout + done.stderr
    calls = _terraform_calls(lines)
    assert _kinds(calls) == [("infra/lab", "init"), ("infra/lab", "state"), ("infra/net", "init"),
                             ("infra/net", "state"), ("infra/lab", "apply"), ("infra/net", "apply")]
    assert not any(" plan " in c or "infra/base" in c for c in calls), "destroy never plans"
    assert [Path(c.split()[-1]).parts[-2:] for c in calls if " apply " in c] == [
        ("destroy", "lab.tfplan"), ("destroy", "net.tfplan")]
    assert "ARM_CLIENT_ID=client-apply" in "".join(lines)


@needs_sh
def test_destroy_without_a_saved_destroy_plan_fails_before_terraform(azure_run):
    done, lines = azure_run("tf-destroy.sh")
    assert done.returncode != 0 and "no saved plan" in done.stderr and lines == []
    azure_run("tf-plan.sh")  # an apply plan is not a destroy plan
    done, lines = azure_run("tf-destroy.sh")
    assert done.returncode != 0 and lines == []


@needs_sh
@pytest.mark.parametrize("script", ["tf-destroy-plan.sh", "tf-destroy.sh"])
@pytest.mark.parametrize("state", [
    "azurerm_resource_group.lab\n",
    "azurerm_firewall.hub[0]\nmodule.x.azurerm_resource_group.y\n",
    'module.x["a"].azurerm_resource_group.y[0]\n',
])
def test_destroy_refuses_when_a_state_manages_a_resource_group_also_inside_a_module(azure_run, script, state):
    if script == "tf-destroy.sh":
        assert azure_run("tf-destroy-plan.sh")[0].returncode == 0  # saved plans exist
    done, lines = azure_run(script, STANDIN_STATE=state)
    assert done.returncode != 0 and "resource group" in done.stderr
    assert not any(" apply " in c or " plan " in c for c in _terraform_calls(lines)), (
        "nothing may be planned or destroyed once a managed resource group is found")


@needs_sh
@pytest.mark.parametrize("script", ["tf-destroy-plan.sh", "tf-destroy.sh"])
def test_destroy_refuses_when_the_state_list_fails(azure_run, script):
    """A failing `state list` must not look like an empty state (a pipe would hide its status)."""
    if script == "tf-destroy.sh":
        assert azure_run("tf-destroy-plan.sh")[0].returncode == 0
    done, lines = azure_run(script, STANDIN_STATE_RC="1")
    assert done.returncode != 0 and "could not read the state" in done.stderr
    assert not any(" apply " in c or " plan " in c for c in _terraform_calls(lines))


@needs_sh
def test_leftover_check_fails_and_lists_what_is_still_there(azure_run):
    done, lines = azure_run("leftover-check.sh")
    assert done.returncode == 0, done.stdout + done.stderr
    login = next(line for line in lines if line.startswith("az login"))
    assert "--federated-token" in login and "client-plan" in login and "token-from-gitlab" in login
    queried = "".join(lines)
    for billable in ("managedClusters", "azureFirewalls", "flexibleServers", "publicIPAddresses"):
        assert billable in queried, billable
    left = "/subscriptions/s/resourceGroups/rg-lab/providers/Microsoft.Network/azureFirewalls/afw-hub\n"
    done, _ = azure_run("leftover-check.sh", STANDIN_RESOURCES=left)
    assert done.returncode == 1 and "azureFirewalls/afw-hub" in done.stderr


# Behaviour of ci/iac.sh that needs no tool: the step switch and the checkov guards, with a
# stand-in checkov.

CHECKOV_STANDIN = """#!/bin/sh
echo "$STANDIN_CHECKOV_OUTPUT"
exit "${STANDIN_CHECKOV_RC:-0}"
"""


@pytest.fixture
def iac_run(tmp_path):
    path = _scratch_repo(tmp_path, {"checkov": CHECKOV_STANDIN})

    def run(**env):
        merged = {**os.environ, "GITLAB_CI": "true", "IAC_STEP": "checkov", "IAC_RETRY_SLEEP": "0",
                  **env, "PATH": path}
        return subprocess.run([SH, "ci/iac.sh"], cwd=tmp_path, env=merged, capture_output=True,
                              text=True, timeout=60, check=False)

    return run


@needs_sh
def test_iac_script_rejects_an_unknown_step_and_the_all_step_in_ci(iac_run):
    assert iac_run(IAC_STEP="bogus").returncode == 2
    assert iac_run(IAC_STEP="all").returncode == 2  # CI has one job per step


@needs_sh
def test_checkov_step_passes_on_a_clean_scan_and_skips_a_missing_deploy_folder(iac_run):
    done = iac_run(STANDIN_CHECKOV_OUTPUT="Passed checks: 40, Failed checks: 0, Skipped checks: 35")
    assert done.returncode == 0, done.stdout + done.stderr
    assert "deploy/ not found, skipped" in done.stdout


@needs_sh
def test_checkov_step_fails_when_deploy_is_required_but_missing(iac_run):
    done = iac_run(STANDIN_CHECKOV_OUTPUT="Passed checks: 40, Failed checks: 0, Skipped checks: 0",
                   IAC_REQUIRE_DEPLOY="true")
    assert done.returncode == 1 and "IAC_REQUIRE_DEPLOY" in done.stderr


@needs_sh
@pytest.mark.parametrize("output, rc, why", [
    ("Passed checks: 40, Failed checks: 2, Skipped checks: 0", 1, "findings"),
    ("Passed checks: 0, Failed checks: 0, Skipped checks: 0, Parsing errors: 1", 0, "nothing scanned"),
    ("Passed checks: 17, Failed checks: 0, Skipped checks: 0, Parsing errors: 2", 0, "parsing errors"),
    ("Passed checks: 0, Failed checks: 0, Skipped checks: 0", 0, "empty scan, no parse error"),
    ("", 0, "no summary at all"),
])
def test_checkov_step_fails_on_findings_nothing_scanned_and_parse_errors(iac_run, output, rc, why):
    done = iac_run(STANDIN_CHECKOV_OUTPUT=output, STANDIN_CHECKOV_RC=str(rc))
    assert done.returncode == 1, why


# --- permission assessment and the visibility of plan files -------------------------------

def test_permissions_job_assesses_the_database_db_sql_builds():
    job = _jobs()["permissions"]
    assert job["stage"] == "test" and "rules" not in job, "it runs on every push"
    assert job["script"] == ["sh ci/permissions.sh"]
    assert [_image(s) for s in job["services"]] == [_compose_db_image()]
    assert job["variables"]["TEST_DB_SERVICE_HOST"] in [s["alias"] for s in job["services"]]
    assert job["artifacts"]["paths"] == ["reports/permissions/"]
    assert job["artifacts"]["when"] == "always", "keep the differences when the job fails"
    script = _text("ci/permissions.sh")
    for needed in (". ci/db-setup.sh", "-m secops.permassess --planes pg,compose",
                   "--compose-json", "secops.permassess.report", "--check"):
        assert needed in script, needed


def test_mutmut_does_not_run_the_permission_assessment_tests():
    """They import secops/ and read security/ and compose.yaml, which the mutants/ copy lacks;
    one test file that fails to collect stops the whole mutation job."""
    scope = tomllib.loads(_text("pyproject.toml"))["tool"]["mutmut"]
    assert "--ignore=tests/test_permassess.py" in scope["pytest_add_cli_args_test_selection"]


@pytest.mark.parametrize("job", ["tf-plan", "tf-destroy-plan"])
def test_plan_files_are_not_public_on_the_public_project(job):
    """Saved plans hold resource values; on a public project `access: all` (the default) would
    let anyone download them. https://docs.gitlab.com/ci/yaml/#artifactsaccess"""
    assert _jobs()[job]["artifacts"]["access"] == "developer"
