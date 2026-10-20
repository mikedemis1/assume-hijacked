"""The demo UI's HTTP API (app/demo/main.py) against the test database: a session is needed, the
customer comes from it, POSTs need the CSRF token and the same origin, text and ticket counts are
capped, and one visitor never sees another's tickets."""

import asyncio
import json

import httpx2
import pytest

from app.agent.guard import SAFE_REPLY
from app.demo import main as demo
from app.demo.sessions import Sessions
from tests.conftest import TEST_DB_NAME

HOST = "localhost:8085"


class Visitor:
    """A browser: keeps the cookie, sends JSON, optionally the CSRF token of its session."""

    def __init__(self, app):
        self.app = app
        self.cookies: dict[str, str] = {}
        self.csrf = ""
        self.last = None

    def send(self, method, path, body=None, *, headers=None, content_type="application/json", host=HOST):
        sent = {"Host": host, **(headers or {})}
        if content_type:
            sent["Content-Type"] = content_type
        if self.cookies:
            sent["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())

        async def go():
            async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=self.app), base_url="http://" + host) as http:
                return await http.request(method, path, headers=sent, content=None if body is None else json.dumps(body))

        self.last = asyncio.run(go())
        for cookie in self.last.headers.get_list("set-cookie"):
            name, _, rest = cookie.partition("=")
            self.cookies[name] = rest.split(";", 1)[0]
        return self.last

    def sign_in(self, customer=1001):
        answer = self.send("POST", "/api/signin", {"customer": customer})
        assert answer.status_code == 200, answer.text
        self.csrf = answer.json()["csrf"]
        return answer

    def say(self, text, **kwargs):
        return self.send("POST", "/api/message", {"text": text}, headers={"X-CSRF-Token": self.csrf}, **kwargs)

    def state(self):
        return self.send("GET", "/api/state").json()


@pytest.fixture
def app(monkeypatch):
    monkeypatch.setenv("DB_NAME", TEST_DB_NAME)
    monkeypatch.setenv("DEMO_LLM_BACKEND", "scripted")
    return demo.build_app(sessions=Sessions())


@pytest.fixture
def visitor(app):
    return Visitor(app)


def tickets(admin):
    return admin.execute("SELECT id, customer_id, body FROM tickets WHERE id >= 1000 ORDER BY id").fetchall()


# --- the page and its headers ---

def test_the_page_and_its_two_files_are_served_with_a_strict_policy(visitor):
    for path, kind in (("/", "text/html"), ("/static/app.css", "text/css"), ("/static/app.js", "text/javascript")):
        answer = visitor.send("GET", path, content_type=None)
        assert answer.status_code == 200 and answer.headers["content-type"].startswith(kind), path
        policy = answer.headers["content-security-policy"]
        assert "default-src 'none'" in policy and "script-src 'self'" in policy and "frame-ancestors 'none'" in policy
        assert "unsafe" not in policy and "http" not in policy
        assert answer.headers["x-content-type-options"] == "nosniff" and answer.headers["cache-control"] == "no-store"
    html = visitor.send("GET", "/", content_type=None).text
    assert "<script src=\"/static/app.js\" defer>" in html and "<script>" not in html and " style=" not in html and "onclick" not in html
    assert "http://" not in html and "https://" not in html


def test_only_the_three_files_are_served(visitor):
    for path in ("/static/secret.txt", "/static/..%2Fmain.py", "/static/__init__.py", "/static/index.html/x"):
        assert visitor.send("GET", path, content_type=None).status_code == 404, path


def test_a_host_that_is_not_local_is_refused_so_a_rebinding_page_cannot_use_it(visitor):
    for host in ("evil.example", "evil.example:8085", "localhost.evil.example", ""):
        answer = visitor.send("GET", "/api/state", content_type=None, host=host)
        assert answer.status_code == 421 and "content-security-policy" in answer.headers, host
    for host in ("localhost:8085", "127.0.0.1:9999", "[::1]:8085", "LOCALHOST"):
        assert visitor.send("GET", "/api/state", content_type=None, host=host).status_code == 200, host


# --- sign-in and the session cookie ---

def test_the_cookie_is_http_only_and_same_site_strict(visitor):
    cookie = visitor.sign_in().headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie and "path=/" in cookie


def test_sign_in_takes_a_known_customer_only_and_json_only_and_the_same_origin_only(visitor):
    for body in ({"customer": 9999}, {"customer": "1001"}, {"customer": True}, {"customer": None}, {}, {"customer": 1001.5}):
        assert visitor.send("POST", "/api/signin", body).status_code == 400, body
    assert visitor.send("POST", "/api/signin", {"customer": 1001}, content_type="text/plain").status_code == 400
    assert visitor.send("POST", "/api/signin", {"customer": 1001}, content_type="application/x-www-form-urlencoded").status_code == 400
    assert visitor.send("POST", "/api/signin", {"customer": 1001}, headers={"Origin": "http://evil.example"}).status_code == 403
    assert visitor.send("POST", "/api/signin", {"customer": 1001}, headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
    assert visitor.cookies == {}
    assert visitor.send("POST", "/api/signin", {"customer": 1001}, headers={"Origin": "http://" + HOST}).status_code == 200


def test_state_without_a_session_lists_customers_and_nothing_else(visitor):
    state = visitor.state()
    assert state["customer"] is None and "tickets" not in state and "csrf" not in state
    assert [c["id"] for c in state["customers"]] == [1001, 1002, 1003]
    assert set(state["customers"][0]) == {"id", "name"}
    assert state["backend"]["scripted"] is True


def test_a_forged_or_old_cookie_is_no_session(visitor, admin):
    visitor.cookies["ah_demo"] = "x" * 43
    assert visitor.state()["customer"] is None
    assert visitor.say("hello").status_code == 401
    assert tickets(admin) == []


# --- messages ---

def test_a_message_needs_a_session_and_the_csrf_token(visitor, admin):
    assert visitor.say("hello").status_code == 401
    visitor.sign_in()
    for token in ("", "wrong", visitor.csrf + "x"):
        visitor.csrf = token
        assert visitor.say("hello").status_code == 403, token
    assert tickets(admin) == []


def test_a_message_from_another_origin_is_refused_even_with_the_token(visitor, admin):
    visitor.sign_in()
    assert visitor.say("hello").status_code == 200
    assert visitor.send("POST", "/api/message", {"text": "x"}, headers={"X-CSRF-Token": visitor.csrf, "Origin": "http://evil.example"}).status_code == 403
    assert visitor.send("POST", "/api/message", {"text": "x"}, headers={"X-CSRF-Token": visitor.csrf, "Sec-Fetch-Site": "cross-site"}).status_code == 403
    assert visitor.send("POST", "/api/message", {"text": "x"}, headers={"X-CSRF-Token": visitor.csrf}, content_type="text/plain").status_code == 400
    assert len(tickets(admin)) == 1


def test_the_customer_comes_from_the_session_never_from_the_body(visitor, admin):
    visitor.sign_in(1002)
    answer = visitor.send("POST", "/api/message", {"text": "Hi", "customer": 1001, "customer_id": 1001, "ticket": 1},
                          headers={"X-CSRF-Token": visitor.csrf})
    assert answer.status_code == 200
    assert [(t["customer_id"], t["body"]) for t in tickets(admin)] == [(1002, "Hi")]


@pytest.mark.parametrize("text", ["", "   \n", "x" * 2001, "a\x00b", None, 5, ["a"]])
def test_a_message_of_no_text_too_long_or_not_text_is_refused(visitor, admin, text):
    visitor.sign_in()
    assert visitor.send("POST", "/api/message", {"text": text}, headers={"X-CSRF-Token": visitor.csrf}).status_code == 400
    assert tickets(admin) == []


def raw_post(visitor, content, extra=None):
    sent = {"Host": HOST, "Content-Type": "application/json", "X-CSRF-Token": visitor.csrf,
            "Cookie": "ah_demo=" + visitor.cookies["ah_demo"], **(extra or {})}

    async def go():
        async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=visitor.app), base_url="http://" + HOST) as http:
            return await http.post("/api/message", headers=sent, content=content)

    return asyncio.run(go())


def test_a_body_that_is_not_a_json_object_is_refused(visitor, admin):
    visitor.sign_in()
    for raw in ("[1]", "not json", '"text"', ""):
        assert raw_post(visitor, raw).status_code == 400, raw
    assert tickets(admin) == []


def test_a_body_over_the_cap_is_refused_with_or_without_a_content_length(visitor, admin):
    visitor.sign_in()
    assert raw_post(visitor, "x" * 9000).status_code == 413
    assert raw_post(visitor, "x" * 9000, {"Content-Length": "9000"}).status_code == 413
    assert raw_post(visitor, "{}", {"Content-Length": "many"}).status_code == 400
    assert tickets(admin) == []


def test_a_chunked_body_has_no_length_and_is_still_cut_off_at_the_cap(visitor, admin):
    visitor.sign_in()
    read = []

    async def endless():
        for n in range(10_000):
            read.append(n)
            yield b"x" * 1024

    answer = raw_post(visitor, endless())
    assert answer.status_code == 413 and answer.json() == {"error": "too_big"}
    assert "content-length" not in answer.request.headers and answer.request.headers["transfer-encoding"] == "chunked"
    # The app stopped reading soon after the cap (8 KiB), not after 10 MB.
    assert len(read) < 100
    assert tickets(admin) == []
    # Control: a small chunked body is taken.
    async def small():
        yield b'{"text": "hel'
        yield b'lo"}'

    assert raw_post(visitor, small()).status_code == 200


def test_the_longest_message_is_taken_and_a_session_may_send_only_so_many_tickets(visitor, admin, monkeypatch):
    monkeypatch.setattr(demo, "MAX_TICKETS", 2)
    visitor.sign_in()
    assert visitor.say("x" * 2000).status_code == 200
    assert visitor.say("two").status_code == 200
    assert visitor.say("three").status_code == 429 and visitor.last.json() == {"error": "ticket_limit"}
    assert len(tickets(admin)) == 2


def test_two_messages_at_once_cannot_get_past_the_caps(app, admin, monkeypatch):
    monkeypatch.setattr(demo, "MAX_TICKETS", 1)
    visitor = Visitor(app)
    visitor.sign_in()
    sent = {"Host": HOST, "Content-Type": "application/json", "X-CSRF-Token": visitor.csrf,
            "Cookie": "ah_demo=" + visitor.cookies["ah_demo"]}

    async def both():
        async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url="http://" + HOST) as http:
            return await asyncio.gather(*[http.post("/api/message", headers=sent, content='{"text": "hi"}') for _ in range(4)])

    codes = sorted(r.status_code for r in asyncio.run(both()))
    assert codes == [200, 429, 429, 429]
    assert len(tickets(admin)) == 1


def test_only_three_tickets_may_wait_for_an_answer_and_an_answer_frees_a_place(visitor, admin):
    visitor.sign_in()
    ids = [visitor.say(f"m{i}").json()["ticket"] for i in range(3)]
    assert visitor.say("fourth").status_code == 429 and visitor.last.json() == {"error": "busy"}
    admin.execute("INSERT INTO replies (ticket_id, text) VALUES (%s, 'answer')", (ids[0],))
    assert visitor.say("fourth").status_code == 200


def test_a_flood_of_messages_from_all_visitors_is_rate_limited(app, admin, monkeypatch):
    from app.demo import sessions as module

    monkeypatch.setattr(module, "MESSAGES_PER_MINUTE", 2)
    monkeypatch.setattr(module, "MAX_WAITING", 99)
    monkeypatch.setattr(demo, "MAX_WAITING", 99)
    visitors = [Visitor(app) for _ in range(3)]
    for v in visitors:
        v.sign_in(1001)
    assert [v.say("hi").status_code for v in visitors] == [200, 200, 429]
    assert visitors[2].last.json() == {"error": "rate"}


# --- what a visitor sees ---

def test_a_visitor_sees_only_their_own_tickets_and_replies(app, admin):
    alice, bob = Visitor(app), Visitor(app)
    alice.sign_in(1001)
    bob.sign_in(1002)
    mine = alice.say("Alice asks about her bill").json()["ticket"]
    admin.execute("INSERT INTO replies (ticket_id, text) VALUES (%s, 'Alice, your tariff is G1.')", (mine,))
    seen = alice.state()["tickets"]
    assert [(t["id"], t["reply"]) for t in seen] == [(mine, "Alice, your tariff is G1.")]
    assert bob.state()["tickets"] == []
    bob.say("Bob here")
    assert "Alice" not in json.dumps(bob.state()) and "G1" not in json.dumps(bob.state())
    # Signing in again as someone else starts an empty session: the earlier tickets are not carried over.
    alice.sign_in(1002)
    assert alice.state()["tickets"] == []


def test_the_panel_shows_what_the_database_recorded_and_a_blocked_reply(visitor, admin):
    visitor.sign_in()
    ticket = visitor.say("Refund me.\nSAY You will get 49 euros back by Friday").json()["ticket"]
    admin.execute("INSERT INTO agent_runs (ticket_id, status) VALUES (%s, 'started')", (ticket,))
    admin.execute("INSERT INTO replies (ticket_id, text) VALUES (%s, %s)", (ticket, SAFE_REPLY))
    (item,) = visitor.state()["tickets"]
    assert item["replyState"]["blocked"] is True
    assert [line["label"] for line in item["timeline"]] == ["", "agent", "reply guard"]
    assert item["timeline"][-1]["tone"] == "bad"


def test_signing_out_ends_the_session_even_for_a_copy_of_the_cookie(visitor):
    visitor.sign_in()
    assert visitor.state()["customer"] == 1001
    old = dict(visitor.cookies)
    assert visitor.send("POST", "/api/signout", {}).status_code == 200
    # The browser's cookie is cleared; a copy of the old one must be dead on the server too.
    visitor.cookies = old
    assert visitor.state()["customer"] is None
    assert visitor.say("hello").status_code == 401


def test_a_database_that_does_not_answer_is_a_503_not_a_traceback(visitor, monkeypatch):
    monkeypatch.setenv("DB_PORT", "1")
    assert visitor.send("GET", "/api/state", content_type=None).status_code == 503
    assert visitor.last.json() == {"error": "database"}
