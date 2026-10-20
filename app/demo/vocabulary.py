"""The names the security console may print (ruling R14).

A tool name or an argument name in the records can come from the model, so from whoever wrote the
ticket. The console prints one only when it is in the known vocabulary: the tools and the arguments
of their schemas (the agent's table and the reviewed manifests in permissions/tool-*.json), plus the
names the attack table uses. Anything else is shown as a fixed phrase, never echoed, so a name
cannot carry text onto the screen.
"""

from __future__ import annotations

import logging

from app.agent.core import ALLOWED_ARGS
from app.demo import attacks

LOG = logging.getLogger(__name__)

UNKNOWN_TOOL = "an unknown tool"
UNKNOWN_ARG = "an argument the tool does not take"


def _from_manifests() -> tuple[set[str], set[str]]:
    try:
        from app.gateway.manifest import load_manifests

        specs = load_manifests()
    except Exception as err:  # the manifests are a second source; the agent's table still stands
        LOG.warning("demo vocabulary: manifests not loaded (%s)", type(err).__name__)
        return set(), set()
    return set(specs), {a for spec in specs.values() for a in spec.args}


def _build() -> tuple[frozenset[str], frozenset[str]]:
    attack_tools, attack_args = attacks.attack_names()
    manifest_tools, manifest_args = _from_manifests()
    tools = set(ALLOWED_ARGS) | manifest_tools | attack_tools
    args = {a for names in ALLOWED_ARGS.values() for a in names} | manifest_args | attack_args
    return frozenset(tools), frozenset(args)


TOOLS, ARGS = _build()


def tool(name: object) -> str:
    return name if isinstance(name, str) and name in TOOLS else UNKNOWN_TOOL


def arg(name: object) -> str:
    return name if isinstance(name, str) and name in ARGS else UNKNOWN_ARG


def args(names) -> str:
    """Argument names joined, each unknown one as the fixed phrase (said once per kind)."""
    shown: list[str] = []
    for name in names:
        word = arg(name)
        if word not in shown:
            shown.append(word)
    return ", ".join(shown)
