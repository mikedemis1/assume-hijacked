"""Whose token is this? Asks the Kubernetes API (authentication.k8s.io/v1 TokenReview).

Used by the services the agent calls (the tool gateway today). The caller's projected service
account token carries the audience of the service it is for; the API server says whether the token
is valid for that audience, which service account it belongs to, and which pod it was issued to
(`status.user.extra["authentication.kubernetes.io/pod-name"]`), so no service needs the right to
read pods or Jobs to find out.
https://kubernetes.io/docs/reference/access-authn-authz/authentication/#tokenreview-api
https://kubernetes.io/docs/concepts/storage/projected-volumes/#serviceaccounttoken

Anything but a clear "authenticated, for this audience" is None: fail closed. The pod needs its own
API token mounted and the RBAC right to `create` tokenreviews.
"""

from __future__ import annotations

import json
import os
import ssl
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

POD_NAME_KEY = "authentication.kubernetes.io/pod-name"
MAX_ANSWER_BYTES = 64 * 1024


@dataclass(frozen=True)
class Review:
    username: str
    pod: str | None


class TokenReviewer:
    def __init__(
        self,
        api_url: str | None = None,
        sa_dir: str = "/var/run/secrets/kubernetes.io/serviceaccount",
        post: Callable[[dict], object] | None = None,
        timeout_s: float = 3,
    ) -> None:
        host, port = os.environ.get("KUBERNETES_SERVICE_HOST"), os.environ.get("KUBERNETES_SERVICE_PORT", "443")
        self.api_url = api_url or (f"https://{host}:{port}" if host else "https://kubernetes.default.svc")
        self.sa_dir = Path(sa_dir)
        self.timeout_s = timeout_s
        self._post = post or self._post_to_api

    def __call__(self, token: str, audience: str) -> Review | None:
        if not token:
            return None
        body = {"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview",
                "spec": {"token": token, "audiences": [audience]}}
        try:
            answer = self._post(body)
        except Exception:  # an API server that is down or odd means "not verified"
            return None
        status = answer.get("status") if isinstance(answer, dict) else None
        if not isinstance(status, dict) or status.get("authenticated") is not True:
            return None
        if audience not in (status.get("audiences") or []):
            return None
        user = status.get("user")
        username = user.get("username") if isinstance(user, dict) else None
        if not isinstance(username, str) or not username:
            return None
        extra = user.get("extra")
        names = extra.get(POD_NAME_KEY) if isinstance(extra, dict) else None
        pod = names[0] if isinstance(names, list) and len(names) == 1 and isinstance(names[0], str) and names[0] else None
        return Review(username=username, pod=pod)

    def _post_to_api(self, body: dict) -> object:
        own_token = (self.sa_dir / "token").read_text(encoding="utf-8").strip()
        context = ssl.create_default_context(cafile=str(self.sa_dir / "ca.crt"))
        request = urllib.request.Request(
            f"{self.api_url}/apis/authentication.k8s.io/v1/tokenreviews",
            data=json.dumps(body).encode(), method="POST",
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {own_token}"},
        )
        # The API server's https URL from the pod's own environment, its CA from the mounted bundle.
        with urllib.request.urlopen(request, timeout=self.timeout_s, context=context) as answer:  # nosec B310
            return json.loads(answer.read(MAX_ANSWER_BYTES))
