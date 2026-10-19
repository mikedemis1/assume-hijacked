"""Supply chain checks (gap I11): builds are repeatable and every download is checked.

These read files only. They fail if a package in the lock loses its hash, a dependency is
no longer pinned exactly, or a base image goes back to a floating tag.
"""
from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DIGEST = re.compile(r"@sha256:[0-9a-f]{64}\b")


def _lock_entries(lock: str = "requirements.lock") -> dict[str, list[str]]:
    """package==version -> list of sha256 hashes, from a lock file."""
    entries: dict[str, list[str]] = {}
    current = None
    for line in (ROOT / lock).read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace():  # a requirement line, e.g. "mcp==2.3.0 \"
            current = line.rstrip(" \\")
            assert "==" in current, f"lock line is not an exact pin: {line!r}"
            entries[current] = []
        elif line.strip().startswith("--hash=sha256:"):
            assert current is not None
            entries[current].append(line.strip().split(":", 1)[1].rstrip(" \\"))
    return entries


def _pyproject() -> dict:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def test_every_locked_package_has_a_sha256_hash():
    entries = _lock_entries()
    assert len(entries) > 20, "the lock should list the full dependency tree"
    unhashed = [name for name, hashes in entries.items() if not hashes]
    assert not unhashed, f"packages in requirements.lock without a hash: {unhashed}"
    for name, hashes in entries.items():
        assert all(re.fullmatch(r"[0-9a-f]{64}", h) for h in hashes), name


@pytest.mark.parametrize("lock", ["requirements.lock", "requirements-dev.lock"])
def test_lock_has_no_index_override_or_url_requirement(lock):
    text = (ROOT / lock).read_text(encoding="utf-8")
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        assert not line.startswith("-"), f"option line in lock: {line!r}"
        assert " @ " not in line and "://" not in line, f"url requirement in lock: {line!r}"


def test_runtime_dependencies_are_pinned_exactly_and_locked():
    project = _pyproject()["project"]
    locked = _lock_entries()
    assert project["dependencies"], "no runtime dependencies found"
    for dep in project["dependencies"]:
        assert re.fullmatch(r"[A-Za-z0-9_.-]+(\[[a-z,]+\])?==[0-9][A-Za-z0-9.+!-]*", dep), (
            f"runtime dependency not pinned with ==: {dep!r}"
        )
        name, version = re.sub(r"\[.*\]", "", dep).split("==")
        assert f"{name}=={version}" in locked, f"{dep} is not in requirements.lock at that version"


def test_build_and_dev_tools_are_pinned_exactly():
    data = _pyproject()
    requirements = list(data["build-system"]["requires"])
    requirements += data["project"]["optional-dependencies"]["dev"]
    for dep in requirements:
        assert re.fullmatch(r"[A-Za-z0-9_.-]+==[0-9][A-Za-z0-9.+!-]*", dep), f"not pinned with ==: {dep!r}"


def test_dockerfile_base_images_are_pinned_by_digest():
    stages = set()
    for line in (ROOT / "Dockerfile").read_text(encoding="utf-8").splitlines():
        m = re.match(r"FROM\s+(\S+)(?:\s+AS\s+(\S+))?", line, re.IGNORECASE)
        if not m:
            continue
        image, alias = m.groups()
        if image != "scratch" and image not in stages:
            assert DIGEST.search(image), f"Dockerfile base image without digest: {image}"
        if alias:
            stages.add(alias)


def test_compose_images_are_pinned_by_digest():
    images = re.findall(r"^\s*image:\s*(\S+)", (ROOT / "compose.yaml").read_text(encoding="utf-8"), re.M)
    assert images, "compose.yaml should name at least the db image"
    for image in images:
        assert DIGEST.search(image), f"compose image without digest: {image}"


def test_dockerfile_installs_with_hashes_only():
    script = (ROOT / "scripts" / "install-deps.sh").read_text(encoding="utf-8")
    assert "--require-hashes -r requirements.lock" in script
    assert "--no-deps ." in script, "the app must be installed without resolving dependencies again"


def test_locked_packages_are_installed_from_wheels_only():
    # Every package in requirements.lock had a cp312 manylinux wheel with a locked hash when this
    # was added (checked against PyPI on 2026-10-15), so no setup.py of a dependency runs in the build.
    script = (ROOT / "scripts" / "install-deps.sh").read_text(encoding="utf-8")
    (line,) = [ln for ln in script.splitlines() if ln.startswith("pip install") and ln.endswith("-r requirements.lock")]
    assert "--only-binary :all:" in line


def test_dev_lock_hashes_every_tool_and_ships_the_same_runtime_packages():
    """CI installs requirements-dev.lock (tests, scanners) with --require-hashes. It must hash
    every package, and hold every runtime package at the version and hashes of the image's lock,
    so the tests run against what ships."""
    dev = _lock_entries("requirements-dev.lock")
    unhashed = [name for name, hashes in dev.items() if not hashes]
    assert not unhashed, f"packages in requirements-dev.lock without a hash: {unhashed}"
    for name, hashes in _lock_entries().items():
        assert name in dev, f"{name} is in requirements.lock but not in requirements-dev.lock"
        assert sorted(dev[name]) == sorted(hashes), f"{name}: hashes differ between the locks"
    for dep in _pyproject()["project"]["optional-dependencies"]["dev"]:
        assert dep.lower().replace("_", "-") in {n.lower() for n in dev}, f"{dep} not in requirements-dev.lock"
