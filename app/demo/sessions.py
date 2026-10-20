"""The visitor's session, kept in this process: who they signed in as, a CSRF token, and the
tickets they sent. The panel shows only these tickets, so a visitor cannot ask for another's.

A restart of the pod empties it. Nothing here is persisted and nothing is a credential: the demo's
sign-in is a dev sign-in that trusts whoever opens the page."""

from __future__ import annotations

import secrets
import threading
import time
from collections import deque
from dataclasses import dataclass, field

MAX_SESSIONS = 200
SESSION_SECONDS = 8 * 3600
MAX_TICKETS = 20  # per session
MAX_WAITING = 3  # tickets of one session without a reply yet
MESSAGES_PER_MINUTE = 30  # all visitors together


@dataclass
class Ticket:
    id: int
    text: str  # the customer's own words
    filed_at: str
    body: str = ""  # what was filed: the words, then the plan's lines when an attack was armed
    attack: str | None = None  # the armed attack's id, when the ticket carries its plan


@dataclass
class Session:
    customer: int
    csrf: str = field(default_factory=lambda: secrets.token_urlsafe(24))
    started: float = field(default_factory=time.monotonic)
    tickets: list[Ticket] = field(default_factory=list)
    armed: str | None = None  # the attack for this session's next message only (one shot)
    arm_seq: int = 0  # counts every arming, so a message can tell its own arming from a later one
    sending: bool = False  # one message at a time per session, so the caps below cannot be raced


class Sessions:
    def __init__(self, clock=time.monotonic) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._by_token: dict[str, Session] = {}
        self._sent: deque[float] = deque()

    def start(self, customer: int) -> tuple[str, Session]:
        token = secrets.token_urlsafe(32)
        session = Session(customer, started=self._clock())
        with self._lock:
            self._drop_expired()
            while len(self._by_token) >= MAX_SESSIONS:  # the oldest goes first (dicts keep order)
                del self._by_token[next(iter(self._by_token))]
            self._by_token[token] = session
        return token, session

    def get(self, token: str | None) -> Session | None:
        if not token:
            return None
        with self._lock:
            session = self._by_token.get(token)
            if session is not None and self._clock() - session.started > SESSION_SECONDS:
                del self._by_token[token]
                return None
            return session

    def end(self, token: str | None) -> None:
        with self._lock:
            self._by_token.pop(token or "", None)

    def allow_message(self) -> bool:
        """A global limit on messages, so a loop on the page cannot fill the ticket table."""
        now = self._clock()
        with self._lock:
            while self._sent and now - self._sent[0] > 60:
                self._sent.popleft()
            if len(self._sent) >= MESSAGES_PER_MINUTE:
                return False
            self._sent.append(now)
            return True

    def _drop_expired(self) -> None:
        now = self._clock()
        for token in [t for t, s in self._by_token.items() if now - s.started > SESSION_SECONDS]:
            del self._by_token[token]
