"""Supply chain checks (gap I11): builds are repeatable and every download is checked.

These read files only. They fail if a package in the lock loses its hash, a dependency is
no longer pinned exactly, or a base image goes back to a floating tag.
"""
from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
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


def test_every_locked_package_has_a_sha256_hash():
    entries = _lock_entries()
    assert len(entries) > 20, "the lock should list the full dependency tree"
    unhashed = [name for name, hashes in entries.items() if not hashes]
    assert not unhashed, f"packages in requirements.lock without a hash: {unhashed}"
    for name, hashes in entries.items():
        assert all(re.fullmatch(r"[0-9a-f]{64}", h) for h in hashes), name


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


