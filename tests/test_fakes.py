"""The fakes of the outside systems (app/fakes): the state register, the grid operator (DSO) and the
SMS provider. Each records the calls it gets in memory (GET /calls) and accepts only its one caller:

  fake        caller          what it serves
  register    register-sync   GET /protected   the homes the register lists as protected
  dso         executor        POST /orders     a disconnection order
  sms         executor        POST /messages   an occupier notice

A fake can also run in a token-less mode on loopback (tests only; the callers themselves have only the
token, app/common/calls.py). In the stack every request carries the caller's projected service account token, audience fake-<name>, checked with a TokenReview. Here the TokenReview is an
injected verifier, so no cluster is needed.
"""

import json
import logging
import socket
import urllib.error
import urllib.request

import pytest

from app.common import calls
from app.common.ops import Heartbeat, Metrics
from app.fakes import FAKES, TokenReviewVerifier, start_fake

EXECUTOR = "system:serviceaccount:ah-core:executor"
REGISTER_SYNC = "system:serviceaccount:ah-core:register-sync"
ORDER = {"request_id": 7, "order_id": 3, "supply_point_id": "SP-1001"}
NOTICE = {"request_id": 7, "notice_id": 2, "supply_point_id": "SP-1001"}

# token -> (username, audiences): what a TokenReview would say about each token.
TOKENS = {
    "executor-dso": (EXECUTOR, ["fake-dso"]),
    "executor-sms": (EXECUTOR, ["fake-sms"]),
    "executor-register": (EXECUTOR, ["fake-register"]),
    "sync-register": (REGISTER_SYNC, ["fake-register"]),
    "sync-dso": (REGISTER_SYNC, ["fake-dso"]),
}


def fake_token_review(token, audience):
    """The injected verifier: the username when the token is valid for this audience, else None."""
    user, audiences = TOKENS.get(token, (None, []))
    return user if audience in audiences else None


@pytest.fixture
def run_fake():
    started = []

    def _run(name, mode="compose", verifier=None, metrics=None):
        server = start_fake(FAKES[name], port=0, mode=mode, verifier=verifier, metrics=metrics, host="127.0.0.1")
        started.append(server)
        return server

    yield _run
    for server in started:
        server.shutdown()


def request(server, method, path, body=None, token=None, raw=None, headers=None):
    """(status, parsed JSON answer or None)."""
    data = raw if raw is not None else (None if body is None else json.dumps(body).encode())
    req = urllib.request.Request(f"http://127.0.0.1:{server.port}{path}", data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token is not None:
        req.add_header("Authorization", f"Bearer {token}")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, timeout=5) as answer:  # noqa: S310 (test, loopback only)
            return answer.status, json.loads(answer.read() or b"null")
    except urllib.error.HTTPError as err:
        return err.code, None


def recorded(server):
    return server.calls()


# --- who may call ---

K8S_CASES = {
    # case: (fake, method, path, body, token, expected status)
    "executor -> dso": ("dso", "POST", "/orders", ORDER, "executor-dso", 202),
    "executor -> sms": ("sms", "POST", "/messages", NOTICE, "executor-sms", 202),
    "register-sync -> register": ("register", "GET", "/protected", None, "sync-register", 200),
    "no token": ("dso", "POST", "/orders", ORDER, None, 401),
    "unknown token": ("dso", "POST", "/orders", ORDER, "made-up", 401),
    "executor token for another audience": ("dso", "POST", "/orders", ORDER, "executor-sms", 401),
    "register-sync token, right audience, wrong caller": ("dso", "POST", "/orders", ORDER, "sync-dso", 403),
    "executor token at the register": ("register", "GET", "/protected", None, "executor-register", 403),
}


@pytest.mark.parametrize("case", K8S_CASES)
def test_fakes_accept_only_their_caller_token(run_fake, case):
    name, method, path, body, token, expected = K8S_CASES[case]
    server = run_fake(name, mode="k8s", verifier=fake_token_review)
    status, _ = request(server, method, path, body, token=token)
    assert status == expected
    # Only an accepted call is recorded: a refused caller leaves no trace in what the fake "did".
    assert len(recorded(server)) == (1 if expected in (200, 202) else 0)


def test_compose_mode_has_the_network_as_its_wall(run_fake):
    # No token at all: in Compose only the caller's edge network reaches the fake.
    server = run_fake("dso", mode="compose")
    assert request(server, "POST", "/orders", ORDER)[0] == 202
    assert recorded(server) == [{"method": "POST", "path": "/orders", "caller": "network", "body": ORDER}]


def test_k8s_mode_without_a_verifier_refuses_to_start():
    with pytest.raises(ValueError, match="verifier"):
        start_fake(FAKES["dso"], port=0, mode="k8s", verifier=None, host="127.0.0.1")


def test_unknown_mode_refuses_to_start():
    with pytest.raises(ValueError, match="mode"):
        start_fake(FAKES["dso"], port=0, mode="open", host="127.0.0.1")


def test_token_is_checked_before_the_body_is_read(run_fake):
    # A refused caller is answered from the headers alone: the bad body is never looked at.
    server = run_fake("dso", mode="k8s", verifier=fake_token_review)
    assert request(server, "POST", "/orders", raw=b"{not json", token="sync-dso")[0] == 403
    assert request(server, "POST", "/orders", raw=b"{not json")[0] == 401


# --- what they record and answer ---

def test_each_fake_records_its_calls_in_order(run_fake):
    dso = run_fake("dso")
    request(dso, "POST", "/orders", ORDER)
    request(dso, "POST", "/orders", {**ORDER, "order_id": 4})
    assert [c["body"]["order_id"] for c in recorded(dso)] == [3, 4]
    status, answer = request(dso, "GET", "/calls")
    assert status == 200 and [c["body"]["order_id"] for c in answer["calls"]] == [3, 4]


def test_register_lists_the_protected_homes(run_fake, monkeypatch):
    monkeypatch.setenv("FAKE_REGISTER_PROTECTED", "SP-1003, SP-1002")
    register = run_fake("register")
    assert request(register, "GET", "/protected") == (200, {"protected": ["SP-1003", "SP-1002"]})
    assert recorded(register) == [{"method": "GET", "path": "/protected", "caller": "network", "body": None}]


def test_register_default_is_the_seeded_life_support_home(run_fake, monkeypatch):
    monkeypatch.delenv("FAKE_REGISTER_PROTECTED", raising=False)
    assert request(run_fake("register"), "GET", "/protected") == (200, {"protected": ["SP-1003"]})


BAD_BODIES = {
    "not json": b"{order",
    "a list": b"[1, 2]",
    "missing field": json.dumps({"request_id": 7, "order_id": 3}).encode(),
    "extra field": json.dumps({**ORDER, "phone": "+30 690 000 1001"}).encode(),
    "wrong type": json.dumps({**ORDER, "order_id": "3"}).encode(),
    "bool for int": json.dumps({**ORDER, "order_id": True}).encode(),
    "empty": b"",
}


@pytest.mark.parametrize("case", BAD_BODIES)
def test_bad_bodies_are_refused_and_not_recorded(run_fake, case):
    server = run_fake("dso")
    assert request(server, "POST", "/orders", raw=BAD_BODIES[case])[0] == 400
    assert recorded(server) == []


def test_body_over_the_limit_is_refused(run_fake):
    server = run_fake("dso")
    assert request(server, "POST", "/orders", raw=b"x" * 20_000)[0] == 413
    assert recorded(server) == []


def test_body_without_a_length_is_refused(run_fake):
    server = run_fake("dso")
    with socket.create_connection(("127.0.0.1", server.port), timeout=5) as sock:
        sock.sendall(b"POST /orders HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
        assert b" 411 " in sock.recv(64)
    assert recorded(server) == []


def test_unknown_path_and_wrong_method(run_fake):
    server = run_fake("dso")
    assert request(server, "GET", "/nothing")[0] == 404
    assert request(server, "GET", "/orders")[0] == 405
    assert request(server, "POST", "/calls", ORDER)[0] == 405
    assert recorded(server) == []


def test_the_record_keeps_only_the_latest_calls():
    # A caller flooding a fake cannot fill its memory: the record is a ring of the latest calls.
    assert fakes_module().MAX_CALLS == 1000
    server = start_fake(FAKES["dso"], port=0, host="127.0.0.1", max_calls=5)
    try:
        for i in range(8):
            request(server, "POST", "/orders", {**ORDER, "order_id": i})
        assert [c["body"]["order_id"] for c in recorded(server)] == [3, 4, 5, 6, 7]
    finally:
        server.shutdown()


def fakes_module():
    from app import fakes

    return fakes


def test_calls_list_needs_the_caller_in_k8s_mode_except_from_inside_the_pod(run_fake):
    # From another address the list is guarded like everything else; from loopback (kubectl exec
    # into the fake's own pod) it is open, so the walls can be checked without a token.
    server = run_fake("dso", mode="k8s", verifier=fake_token_review)
    request(server, "POST", "/orders", ORDER, token="executor-dso")
    assert request(server, "GET", "/calls")[0] == 200  # loopback
    handler_check = server.allows_calls_list
    assert handler_check("10.0.0.7", None) is False
    assert handler_check("10.0.0.7", "sync-dso") is False
    assert handler_check("10.0.0.7", "executor-dso") is True
    assert handler_check("127.0.0.1", None) is True
    assert handler_check("::1", None) is True


# --- logs and metrics: names and ids only ---

def test_fakes_never_log_request_bodies(run_fake, caplog):
    caplog.set_level(logging.DEBUG)
    server = run_fake("sms")
    request(server, "POST", "/messages", {**NOTICE, "supply_point_id": "SP-SECRET-1"})
    request(server, "POST", "/messages", raw=b'{"phone": "+30 690 999 9999"}')
    text = caplog.text
    assert "fake_call" in text  # the event is there
    assert "SP-SECRET-1" not in text and "+30 690" not in text


def test_fakes_count_outcomes(run_fake):
    metrics = Metrics()
    server = run_fake("dso", mode="k8s", verifier=fake_token_review, metrics=metrics)
    request(server, "POST", "/orders", ORDER, token="executor-dso")
    request(server, "POST", "/orders", ORDER, token="sync-dso")
    request(server, "POST", "/orders", ORDER)
    lines = metrics.render().splitlines()
    assert 'fake_requests_total{fake="dso",outcome="accepted"} 1' in lines
    assert 'fake_requests_total{fake="dso",outcome="forbidden"} 1' in lines
    assert 'fake_requests_total{fake="dso",outcome="unauthenticated"} 1' in lines


def test_every_fake_serves_ops(monkeypatch):
    # The chart probes /healthz on 9000 for every pod, fakes included.
    from app import fakes

    monkeypatch.delenv("CALLER_AUTH", raising=False)
    for name in FAKES:
        server, ops = fakes.run(FAKES[name], port=0, ops_port=0, block=False)
        try:
            for path in ("/healthz", "/metrics"):
                with urllib.request.urlopen(f"http://127.0.0.1:{ops.port}{path}", timeout=5) as answer:  # noqa: S310
                    assert answer.status == 200
        finally:
            ops.shutdown()
            server.shutdown()


def test_k8s_mode_builds_the_token_review_verifier(monkeypatch):
    from app import fakes

    monkeypatch.setenv("CALLER_AUTH", "k8s")
    server, ops = fakes.run(FAKES["dso"], port=0, ops_port=0, block=False)
    try:
        assert isinstance(server.verifier, TokenReviewVerifier) and server.mode == "k8s"
        # No cluster here, so the review fails and the call is refused: fail closed.
        assert request(server, "POST", "/orders", ORDER, token="anything")[0] == 401
    finally:
        ops.shutdown()
        server.shutdown()


def test_the_heartbeat_follows_the_http_thread():
    from app import fakes

    class Thread:
        alive = 3

        def is_alive(self):
            self.alive -= 1
            return self.alive > 0

    beats = []
    heartbeat = Heartbeat()
    heartbeat.beat = lambda: beats.append(1)
    with pytest.raises(SystemExit, match="stopped"):
        fakes._forever(Thread(), heartbeat, sleep=lambda s: None)
    assert len(beats) == 2


@pytest.mark.parametrize("name, port, caller", [("register", 8090, REGISTER_SYNC), ("dso", 8091, EXECUTOR),
                                                ("sms", 8092, EXECUTOR)])
def test_fake_ports_and_callers_are_the_contract_ones(name, port, caller):
    assert FAKES[name].port == port and FAKES[name].caller == caller and FAKES[name].audience == f"fake-{name}"


# --- the TokenReview verifier (Kubernetes) ---

def review_answer(authenticated=True, audiences=("fake-dso",), username=EXECUTOR):
    return {"status": {"authenticated": authenticated, "audiences": list(audiences),
                       "user": {"username": username}}}


def test_token_review_asks_for_the_audience_and_returns_the_username():
    sent = []
    verifier = TokenReviewVerifier(post=lambda body: sent.append(body) or review_answer())
    assert verifier("tok", "fake-dso") == EXECUTOR
    assert sent == [{"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview",
                     "spec": {"token": "tok", "audiences": ["fake-dso"]}}]


@pytest.mark.parametrize(
    "answer",
    [
        review_answer(authenticated=False),
        review_answer(audiences=("fake-sms",)),
        review_answer(audiences=()),
        review_answer(username=None),
        {"status": {}},
        {},
        "not a dict",
    ],
)
def test_token_review_fails_closed(answer):
    assert TokenReviewVerifier(post=lambda body: answer)("tok", "fake-dso") is None


def test_token_review_error_fails_closed():
    def broken(body):
        raise OSError("API server down")

    assert TokenReviewVerifier(post=broken)("tok", "fake-dso") is None


def test_token_review_never_sends_an_empty_token():
    sent = []
    verifier = TokenReviewVerifier(post=lambda body: sent.append(body) or review_answer())
    assert verifier("", "fake-dso") is None and sent == []


# --- the caller side: which token goes with a call ---

def test_caller_auth_is_the_token_whatever_the_environment_says(monkeypatch):
    monkeypatch.delenv("CALLER_AUTH", raising=False)
    for app_env in ("local", "", "kind", "azure"):
        monkeypatch.setenv("APP_ENV", app_env)
        assert calls.caller_auth_mode() == "k8s"
    monkeypatch.setenv("CALLER_AUTH", "k8s")
    assert calls.caller_auth_mode() == "k8s"
    for other in ("compose", "none"):
        monkeypatch.setenv("CALLER_AUTH", other)
        with pytest.raises(ValueError, match="CALLER_AUTH"):
            calls.caller_auth_mode()


def test_k8s_caller_sends_the_projected_token_for_the_audience(tmp_path):
    (tmp_path / "fake-dso").mkdir()
    (tmp_path / "fake-dso" / "token").write_text("projected-token\n", encoding="utf-8")
    assert calls.auth_headers("fake-dso", "k8s", token_dir=tmp_path) == {"Authorization": "Bearer projected-token"}
    with pytest.raises(ValueError, match="CALLER_AUTH"):
        calls.auth_headers("fake-dso", "compose", token_dir=tmp_path)
    with pytest.raises(OSError):
        calls.auth_headers("fake-sms", "k8s", token_dir=tmp_path)


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://x/y", "gopher://x", "x"])
def test_calls_go_only_to_http_urls(url):
    with pytest.raises(ValueError, match="http"):
        calls.post_json(url, {}, {}, timeout_s=1)
    with pytest.raises(ValueError, match="http"):
        calls.get_json(url, {}, timeout_s=1, max_bytes=10)


def test_k8s_caller_reaches_a_k8s_fake_end_to_end(run_fake, tmp_path):
    (tmp_path / "fake-dso").mkdir()
    (tmp_path / "fake-dso" / "token").write_text("executor-dso", encoding="utf-8")
    server = run_fake("dso", mode="k8s", verifier=fake_token_review)
    headers = calls.auth_headers("fake-dso", "k8s", token_dir=tmp_path)
    assert calls.post_json(f"http://127.0.0.1:{server.port}/orders", ORDER, headers, timeout_s=5) == 202
    assert recorded(server)[0]["caller"] == EXECUTOR


# --- how the components are put together ---

def test_components_that_talk_to_the_outside_do_not_load_the_agent_package():
    # The executor, the register sync and the fakes run with database rights or stand for outside
    # systems; none of them needs, or should carry, the agent's code.
    import subprocess
    import sys
    from pathlib import Path

    script = (
        "import sys\n"
        "import app.executor.main, app.register.sync, app.fakes.register, app.fakes.dso, app.fakes.sms, app.risk.main\n"
        "print(sorted(m for m in sys.modules if m == 'app.agent' or m.startswith('app.agent.')))\n"
    )
    root = Path(__file__).resolve().parent.parent
    done = subprocess.run([sys.executable, "-c", script], cwd=root, capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip() == "[]"


def test_the_agent_still_logs_security_events():
    from app.agent.events import security_event
    from app.common.events import security_event as common_security_event

    assert security_event is common_security_event

