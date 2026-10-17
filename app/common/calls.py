"""HTTP calls from a component to a system outside it (the register, the grid operator, the SMS
provider; fakes of them in this project, app/fakes).

Who the caller is depends on where it runs (CALLER_AUTH):
  compose  no token. The network is the wall: each caller and its peer share one internal edge
           network (compose.yaml), and nothing else reaches the peer.
  k8s      the caller's projected service account token for the peer's audience, read from
           /var/run/secrets/ah/<audience>/token on every call (the kubelet rotates it). The peer
           checks it with a TokenReview (app/fakes).
Without CALLER_AUTH, APP_ENV decides: kind and azure mean k8s, anything else compose.
"""

from __future__ import annotations

import json
import os
import urllib.request
from collections.abc import Mapping
from pathlib import Path
from urllib.parse import urlsplit

MODES = ("compose", "k8s")
TOKEN_DIR = Path("/var/run/secrets/ah")


def caller_auth_mode(env: Mapping[str, str] = os.environ) -> str:
    mode = env.get("CALLER_AUTH", "").strip()
    if not mode:
        return "k8s" if env.get("APP_ENV", "").strip() in ("kind", "azure") else "compose"
    if mode not in MODES:
        raise ValueError(f"CALLER_AUTH must be one of {MODES}, got {mode!r}")
    return mode


def auth_headers(audience: str, mode: str, token_dir: Path | str = TOKEN_DIR) -> dict[str, str]:
    """The headers that say who is calling. A missing token file raises OSError: no token, no call."""
    if mode == "compose":
        return {}
    token = (Path(token_dir) / audience / "token").read_text(encoding="utf-8").strip()
    return {"Authorization": f"Bearer {token}"}


def _check_url(url: str) -> None:
    # urlopen also opens file:// and ftp:// URLs; a call to a peer is plain HTTP(S) only.
    if urlsplit(url).scheme not in ("http", "https"):
        raise ValueError("only http and https URLs are called")


def post_json(url: str, payload: dict, headers: Mapping[str, str], timeout_s: float) -> int:
    """POST the payload as JSON. Returns the status; a non-2xx answer raises HTTPError, a network
    failure URLError (both OSError)."""
    _check_url(url)
    request = urllib.request.Request(
        url, data=json.dumps(payload).encode(), method="POST",
        headers={"Content-Type": "application/json", **headers},
    )
    with urllib.request.urlopen(request, timeout=timeout_s) as answer:  # nosec B310 - scheme checked above
        return answer.status


def get_json(url: str, headers: Mapping[str, str], timeout_s: float, max_bytes: int) -> bytes:
    """GET the URL. Returns at most max_bytes + 1 bytes of the body, so the caller can tell an
    answer that is too big without reading all of it."""
    _check_url(url)
    request = urllib.request.Request(url, method="GET", headers={"Accept": "application/json", **headers})
    with urllib.request.urlopen(request, timeout=timeout_s) as answer:  # nosec B310 - scheme checked above
        return answer.read(max_bytes + 1)
