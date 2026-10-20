"""How a component says who it is when it calls a peer.

The caller sends its projected service account token for the peer's audience, read from
/var/run/secrets/ah/<audience>/token on every call (the kubelet rotates it). The peer checks it
with a TokenReview. That is the only mode (CALLER_AUTH=k8s); without CALLER_AUTH it is k8s too,
whatever APP_ENV says.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

MODES = ("k8s",)
TOKEN_DIR = Path("/var/run/secrets/ah")


def caller_auth_mode(env: Mapping[str, str] = os.environ) -> str:
    mode = env.get("CALLER_AUTH", "").strip()
    if not mode:
        return "k8s"
    if mode not in MODES:
        raise ValueError(f"CALLER_AUTH must be one of {MODES}, got {mode!r}")
    return mode


def auth_headers(audience: str, mode: str, token_dir: Path | str = TOKEN_DIR) -> dict[str, str]:
    """The headers that say who is calling. A missing token file raises OSError: no token, no call."""
    if mode not in MODES:
        raise ValueError(f"CALLER_AUTH must be one of {MODES}, got {mode!r}")
    token = (Path(token_dir) / audience / "token").read_text(encoding="utf-8").strip()
    return {"Authorization": f"Bearer {token}"}
