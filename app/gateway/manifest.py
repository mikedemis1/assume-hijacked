"""What the gateway knows about each tool, read from the reviewed capability manifests
(security/capabilities/tool-*.json): the arguments the model may set, and the fingerprint of the
description the tool must still have (app/security/descriptors.py).

The gateway reads the files at start and fails if one is missing or wrong, so it never runs
with a tool it has no reviewed fingerprint for.

The VULNERABLE demo build (docs/attacks.md) is the one exception to "no argument except the
manifest's": its lookup_account takes a customer id, which changes the tool's description and so
its fingerprint. The manifest lists that second fingerprint as `demo`, next to the reviewed one, and the
gateway uses it only when it runs in demo mode. In normal mode the demo hash is never accepted and
`customer_id` is dropped like any other unknown argument.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from app.tools.serve import TOOLS

MANIFESTS = Path(__file__).resolve().parents[2] / "security" / "capabilities"
_SHA256 = re.compile(r"[0-9a-f]{64}")


class ManifestError(ValueError):
    """A manifest the gateway cannot use."""


@dataclass(frozen=True)
class ToolSpec:
    name: str
    args: frozenset[str]
    descriptor_sha256: str
    demo_args: frozenset[str] = frozenset()
    demo_descriptor_sha256: str | None = None

    def allowed_args(self, vulnerable: bool) -> frozenset[str]:
        return self.args | self.demo_args if vulnerable else self.args

    def expected_sha256(self, vulnerable: bool) -> str:
        """The fingerprint the tool's live description must have. In demo mode a tool with a demo
        variant must match that variant, not the reviewed one: the demo is not a way to run
        something nobody reviewed."""
        if vulnerable and self.demo_descriptor_sha256 is not None:
            return self.demo_descriptor_sha256
        return self.descriptor_sha256


def _sha(where: str, value: object) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ManifestError(f"{where}: descriptor_sha256 must be 64 lowercase hex characters")
    return value


def _args(where: str, value: object) -> frozenset[str]:
    if not isinstance(value, dict) or not all(isinstance(name, str) for name in value):
        raise ManifestError(f"{where}: args must be an object")
    return frozenset(value)


def _spec(path: Path, tool: str) -> ToolSpec:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as err:
        raise ManifestError(f"{path.name}: cannot read ({type(err).__name__})") from err
    listed = (data.get("mcp") or {}).get("tools") if isinstance(data, dict) else None
    if not isinstance(listed, list) or len(listed) != 1 or listed[0].get("name") != tool:
        raise ManifestError(f"{path.name}: expected exactly one tool, {tool}")
    entry = listed[0]
    demo = entry.get("demo")
    if demo is None:
        return ToolSpec(tool, _args(path.name, entry.get("args")), _sha(path.name, entry.get("descriptor_sha256")))
    return ToolSpec(
        tool,
        _args(path.name, entry.get("args")),
        _sha(path.name, entry.get("descriptor_sha256")),
        # What the demo build adds to the reviewed arguments, and the fingerprint it then has.
        _args(path.name, demo.get("args")) - _args(path.name, entry.get("args")),
        _sha(path.name, demo.get("descriptor_sha256")),
    )


def load_manifests(directory: Path | None = None) -> dict[str, ToolSpec]:
    """The five tools' specs, from `directory` (default: the repository's, or CAPABILITIES_DIR in a
    container). Raises ManifestError if any tool is missing or its manifest is wrong."""
    directory = Path(directory) if directory is not None else MANIFESTS
    if not directory.is_dir():
        raise ManifestError(f"{directory}: no such directory")
    return {tool: _spec(directory / f"tool-{tool.replace('_', '-')}.json", tool) for tool in TOOLS}
