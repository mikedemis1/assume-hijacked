"""The demo's session store: caps and expiry (app/demo/sessions.py). No database."""

from app.demo import sessions as module
from app.demo.sessions import Sessions


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_a_session_is_found_by_its_token_and_ended():
    store = Sessions()
    token, session = store.start(1001)
    assert store.get(token) is session
    assert store.get("not-a-token") is None and store.get(None) is None and store.get("") is None
    store.end(token)
    assert store.get(token) is None


def test_tokens_and_csrf_tokens_are_not_reused():
    store = Sessions()
    (t1, s1), (t2, s2) = store.start(1001), store.start(1001)
    assert t1 != t2 and s1.csrf != s2.csrf and len(t1) >= 40


def test_a_session_ends_after_eight_hours():
    clock = Clock()
    store = Sessions(clock)
    token, _ = store.start(1001)
    clock.now += module.SESSION_SECONDS - 1
    assert store.get(token) is not None
    clock.now += 2
    assert store.get(token) is None


def test_the_oldest_session_goes_first_when_there_are_too_many(monkeypatch):
    monkeypatch.setattr(module, "MAX_SESSIONS", 3)
    store = Sessions()
    tokens = [store.start(1001)[0] for _ in range(4)]
    assert store.get(tokens[0]) is None
    assert all(store.get(t) is not None for t in tokens[1:])


def test_messages_are_limited_for_all_visitors_together_and_the_window_slides():
    clock = Clock()
    store = Sessions(clock)
    assert all(store.allow_message() for _ in range(module.MESSAGES_PER_MINUTE))
    assert not store.allow_message()
    clock.now += 61
    assert store.allow_message()
