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

ROOT = Path(__file__).resolve().parents[2]
DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")
# Top-level keys that are settings, not jobs: https://docs.gitlab.com/ci/yaml/
RESERVED = {"workflow", "stages", "default", "variables", "include", "image", "services",
            "cache", "before_script", "after_script"}
SH = shutil.which("sh")
needs_sh = pytest.mark.skipif(SH is None, reason="no POSIX sh on PATH (Git Bash on Windows)")


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


# --- database guard (tests/conftest.py) ------------------------------------------------------

@pytest.mark.parametrize("host", ["localhost", "127.0.0.1"])
def test_guard_allows_the_local_database(host):
    assert db_host_allowed(host, {})


def test_pytest_refuses_to_start_against_a_remote_database():
    """End to end: the guard stops pytest before any test (and any TRUNCATE) runs."""
    env = {**os.environ, "DB_HOST": "db.prod.example.com", "GITLAB_CI": "true",
           "TEST_DB_SERVICE_HOST": "db.prod.example.com"}
    done = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/unit/test_pipeline.py"],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=120, check=False,
    )
    assert done.returncode == 2, done.stdout + done.stderr
    assert "Refusing to run" in done.stdout + done.stderr


# --- pipeline structure ---------------------------------------------------------------------


def test_every_job_image_is_pinned_by_digest():
    images = _ci_images()
    assert len(images) >= 4, images
    for image in images:
        assert DIGEST.search(image), f"image without digest: {image}"
        assert ":" in image.split("@")[0], f"image without a tag next to the digest: {image}"


# --- job 1: lint ----------------------------------------------------------------------------


def test_local_only_tls_workaround_is_never_set_by_the_pipeline_or_a_script():
    """TF_DISABLE_PLUGIN_TLS=1 works around the antivirus on one PC; nothing committed may set it."""
    files = [ROOT / ".gitlab-ci.yml", *sorted((ROOT / "scripts").glob("*.sh"))]
    assert len(files) > 2
    for path in files:
        text = path.read_text(encoding="utf-8")
        assert not re.search(r"TF_DISABLE_PLUGIN_TLS\s*[=:]", text), path.name
        assert not re.search(r"export\s+TF_DISABLE_PLUGIN_TLS", text), path.name


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


def test_terraform_providers_follow_the_committed_lock():
    # -lockfile=readonly: a changed provider or a missing hash fails here, not at the first apply.
    assert "-lockfile=readonly" in _script("lint")


def test_lint_job_scans_chart_terraform_and_dockerfiles_with_the_pinned_trivy():
    script = _script("lint")
    assert re.search(r"install_tools\b.*\btrivy\b", script), "the pinned trivy binary is installed"
    assert "sh scripts/trivy-config.sh" in script
    # The binary is the version of the image the build job scans with.
    image = _jobs()["build"]["variables"]["TRIVY_IMAGE"]
    assert f"aquasec/trivy:{_tool_pins()['TRIVY']['VERSION']}@" in image
    # What the script scans, and when it fails.
    scan = _text("scripts/trivy-config.sh")
    for scanned in ("render-chart.py", "cp -R infra", "Dockerfile", "tests/attacks/Dockerfile"):
        assert scanned in scan, scanned
    assert "--severity HIGH,CRITICAL --exit-code 1" in scan
    assert "--skip-check-update" in scan, "the checks are the ones built into the pinned version"


def test_every_trivy_ignore_has_a_reason():
    lines = _text(".trivyignore").splitlines()
    ids = [i for i, line in enumerate(lines) if line and not line.startswith("#")]
    assert ids, "the ignore file is empty: delete it, and the --ignorefile in the build job"
    for i in ids:
        assert re.fullmatch(r"[A-Z]+-\d{4}|CVE-\d{4}-\d+", lines[i]), lines[i]
        assert lines[i - 1].startswith("#"), f"{lines[i]} has no reason above it"


# --- pinned tools (scripts/ci-tools.sh) -----------------------------------------------------

def _tool_pins() -> dict[str, dict[str, str]]:
    text = _text("scripts/ci-tools.sh")
    pins: dict[str, dict[str, str]] = {}
    for name, field, value in re.findall(r"^([A-Z]+)_(VERSION|URL|SHA256)=(\S+)$", text, re.M):
        pins.setdefault(name, {})[field] = value
    return pins


def test_every_downloaded_tool_has_a_version_a_url_and_a_sha256():
    pins = _tool_pins()
    assert set(pins) == {"RUFF", "GITLEAKS", "TERRAFORM", "HELM", "TRIVY"}
    for name, pin in pins.items():
        assert set(pin) == {"VERSION", "URL", "SHA256"}, name
        assert re.fullmatch(r"[0-9a-f]{64}", pin["SHA256"]), name
        assert pin["URL"].startswith("https://"), name
        assert pin["VERSION"] in pin["URL"], f"{name}: the URL is not the pinned version"


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


