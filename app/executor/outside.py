"""The executor's calls to the outside world, made after the database row they report on is
committed:

  target  URL setting  audience  when
  dso     DSO_URL      fake-dso  a disconnection order was written: the grid operator carries it out
  sms     SMS_URL      fake-sms  an occupier notice was written: the SMS provider sends it

At most once. The row is the record; the call is made once, right after the commit. A call that
fails is logged (events: outside_call_failed) and counted, and never retried: a retry loop is how
one order becomes two at the grid operator. Staff resend by hand.

The payload carries ids only (request, order or notice, supply point). The executor holds no
phone number or address, so it cannot send one.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from app.common import calls
from app.config import Settings

TIMEOUT_S = 5.0


class OutsideCalls:
    def __init__(
        self,
        dso_url: str,
        sms_url: str,
        caller_auth: str = "compose",
        timeout_s: float = TIMEOUT_S,
        token_dir: Path | str = calls.TOKEN_DIR,
        post: Callable[..., int] = calls.post_json,
    ) -> None:
        self.urls = {"dso": dso_url, "sms": sms_url}
        self.audiences = {"dso": "fake-dso", "sms": "fake-sms"}
        self.caller_auth = caller_auth
        self.timeout_s = timeout_s
        self.token_dir = token_dir
        self._post = post

    def send(self, target: str, payload: dict) -> bool:
        """True when sent, False when no URL is set for the target. Any failure raises."""
        url = self.urls[target]
        if not url:
            return False
        headers = calls.auth_headers(self.audiences[target], self.caller_auth, self.token_dir)
        self._post(url, payload, headers, timeout_s=self.timeout_s)
        return True


def outside_calls(settings: Settings) -> OutsideCalls | None:
    """From the settings; None when neither URL is set (no outside world to tell)."""
    if not settings.dso_url and not settings.sms_url:
        return None
    return OutsideCalls(settings.dso_url, settings.sms_url, caller_auth=settings.caller_auth)
