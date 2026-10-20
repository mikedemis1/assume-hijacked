"""Who is calling the gateway.

The agent's projected service account token (audience `tool-gateway`) is checked with a TokenReview.
It must belong to the agent's service account, and it names the pod it was issued to; the gateway
then compares that pod with the one the lease is bound to (app/gateway/proxy.py), so a lease used
from any other pod is refused. There is no other way to be a caller: no token, no call.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.common.tokenreview import Review, TokenReviewer

__all__ = ["AGENT_USER", "AUDIENCE", "CallerAuth", "CallerError", "CallerIdentity", "Review"]

AUDIENCE = "tool-gateway"
# The service account every agent Job runs as: namespace ah-agent, name agent.
AGENT_USER = "system:serviceaccount:ah-agent:agent"
MODES = ("k8s",)


class CallerError(Exception):
    """The caller is not who it must be. `reason` is a category for the security log; the caller
    is told only "unauthorized"."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class CallerIdentity:
    pod: str | None


class CallerAuth:
    def __init__(
        self,
        mode: str,
        reviewer=None,
        audience: str = AUDIENCE,
        allowed_user: str = AGENT_USER,
    ) -> None:
        if mode not in MODES:
            raise ValueError(f"CALLER_AUTH must be one of {MODES}, got {mode!r}")
        self.mode = mode
        self._audience = audience
        self._allowed_user = allowed_user
        self._reviewer = reviewer if reviewer is not None else TokenReviewer()

    def verify_caller(self, request) -> CallerIdentity:
        """The caller of this HTTP request, or CallerError. Blocking (a TokenReview is a network
        call): run it in a thread."""
        values = request.headers.getlist("authorization")
        if len(values) != 1:  # none, or two that could disagree
            raise CallerError("missing")
        scheme, _, token = values[0].partition(" ")
        token = token.strip()
        if scheme.lower() != "bearer" or not token or " " in token:
            raise CallerError("malformed")
        try:
            review = self._reviewer(token, self._audience)
        except Exception as err:  # a reviewer that breaks means "not verified"
            raise CallerError("review_failed") from err
        if review is None:
            raise CallerError("not_authenticated")
        if review.username != self._allowed_user:
            raise CallerError("wrong_service_account")
        if not review.pod:
            raise CallerError("no_pod")
        return CallerIdentity(pod=review.pod)
