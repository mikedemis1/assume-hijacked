"""Who is calling the gateway.

    compose   the caller's source address must be inside the subnet pinned on the agent's edge
              network (edge_agent_gateway in compose.yaml, CALLER_SUBNET). Only the agent is on
              that network. The gateway also shares an edge network with each tool and with the
              risk engine, and a container on one of those reaches the gateway's port from an
              address in that other network, so it is refused here. There is no token in
              Compose, so this check is all that tells the agent from its neighbours; it holds
              as long as the source address is the real one (the gateway reads the peer address
              of the connection and trusts no forwarded header). The caller has no pod.
    k8s       the agent's projected service account token (audience `tool-gateway`) is checked with
              a TokenReview. It must belong to the agent's service account, and it names the pod it
              was issued to; the gateway then compares that pod with the one the lease is bound to
              (app/gateway/proxy.py), so a lease used from any other pod is refused.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from app.common.tokenreview import Review, TokenReviewer

__all__ = ["AGENT_USER", "AUDIENCE", "CallerAuth", "CallerError", "CallerIdentity", "Review"]

AUDIENCE = "tool-gateway"
# The service account every agent Job runs as: namespace ah-agent, name agent.
AGENT_USER = "system:serviceaccount:ah-agent:agent"
MODES = ("compose", "k8s")


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
        allowed_subnet: str | None = None,
    ) -> None:
        if mode not in MODES:
            raise ValueError(f"CALLER_AUTH must be one of {MODES}, got {mode!r}")
        self.mode = mode
        # Compose has no token, so without the subnet there would be no caller check at all: fail
        # closed at construction rather than let every neighbour in.
        if mode == "compose" and not allowed_subnet:
            raise ValueError("CALLER_SUBNET is required with CALLER_AUTH=compose: the agent's edge network subnet")
        self._subnet = ipaddress.ip_network(allowed_subnet, strict=True) if allowed_subnet else None
        self._audience = audience
        self._allowed_user = allowed_user
        self._reviewer = reviewer if reviewer is not None else (TokenReviewer() if mode == "k8s" else None)

    def verify_caller(self, request) -> CallerIdentity:
        """The caller of this HTTP request, or CallerError. Blocking (a TokenReview is a network
        call): run it in a thread."""
        if self.mode == "compose":
            if not self._from_agent_subnet(request.client.host if request.client else None):
                raise CallerError("wrong_network")
            return CallerIdentity(pod=None)
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

    def _from_agent_subnet(self, host: str | None) -> bool:
        try:
            address = ipaddress.ip_address(host or "")
        except ValueError:
            return False
        mapped = getattr(address, "ipv4_mapped", None)
        return (mapped or address) in self._subnet
