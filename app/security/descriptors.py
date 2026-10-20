"""A fingerprint of what a tool tells the model it is: its name, description and input schema.

The tool gateway compares the fingerprint of a tool's live `tools/list` entry with the one written
in the tool's capability manifest (security/capabilities/tool-*.json). A tool whose description or
schema changed since the manifest was reviewed is refused: a changed description is a way to
smuggle instructions to the model.

    sha256 of the canonical JSON {"description", "inputSchema", "name"}:
    keys sorted, no spaces, UTF-8 (not ASCII-escaped).

    python -m app.security.descriptors          # print the fingerprints
    python -m app.security.descriptors --write  # put them into the manifests
    python -m app.security.descriptors --check  # exit 1 if a manifest is out of date
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import sys
from pathlib import Path

from app import config
from app.tools import serve

FIELDS = ("name", "description", "inputSchema")
MANIFESTS = Path(__file__).resolve().parents[2] / "security" / "capabilities"


def canonical(entry: dict) -> bytes:
    """The bytes that are hashed: only the three fields, in canonical JSON."""
    picked = {field: entry.get(field) for field in FIELDS}
    return json.dumps(picked, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def descriptor_sha256(entry: dict) -> str:
    """`entry` is one item of a tools/list answer, as it goes over the wire (inputSchema, camel case)."""
    return hashlib.sha256(canonical(entry)).hexdigest()


def wire_entry(tool) -> dict:
    """A tools/list item from the MCP server's tool object, as the client receives it."""
    return tool.model_dump(by_alias=True, exclude_none=True, mode="json")


def tool_entries(tool_name: str, settings: config.Settings | None = None) -> list[dict]:
    server = serve.build_server(tool_name, settings or config.load())
    return [wire_entry(tool) for tool in asyncio.run(server.list_tools())]


def _arg_type(spec: dict) -> str:
    """The JSON type of an argument. An optional one (`anyOf` with null) gives its real type."""
    if "type" in spec:
        return spec["type"]
    options = [option.get("type", "any") for option in spec.get("anyOf", [])]
    return "|".join(option for option in options if option != "null") or "any"


def manifest_tools(tool_name: str, settings: config.Settings | None = None) -> list[dict]:
    """The `mcp.tools` list a manifest should hold for this tool."""
    out = []
    for entry in tool_entries(tool_name, settings):
        properties = entry["inputSchema"].get("properties", {})
        out.append({
            "name": entry["name"],
            "args": {name: _arg_type(spec) for name, spec in properties.items()},
            "descriptor_sha256": descriptor_sha256(entry),
        })
    return out


def manifest_path(tool_name: str, directory: Path = MANIFESTS) -> Path:
    return directory / f"tool-{tool_name.replace('_', '-')}.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.security.descriptors", description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--write", action="store_true", help="update mcp.tools in the manifests")
    mode.add_argument("--check", action="store_true", help="exit 1 if a manifest differs")
    parser.add_argument("--manifests", type=Path, default=MANIFESTS)
    args = parser.parse_args(argv)
    status = 0
    for tool_name in serve.TOOLS:
        wanted = manifest_tools(tool_name)
        path = manifest_path(tool_name, args.manifests)
        if not (args.write or args.check):
            print(f"{tool_name}: {wanted[0]['descriptor_sha256']}")
            continue
        manifest = json.loads(path.read_text(encoding="utf-8"))
        if args.check:
            if manifest.get("mcp", {}).get("tools") != wanted:
                print(f"{path.name}: mcp.tools is out of date; run python -m app.security.descriptors --write",
                      file=sys.stderr)
                status = 1
            continue
        manifest.setdefault("mcp", {})["tools"] = wanted
        path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")
    return status


if __name__ == "__main__":
    sys.exit(main())
