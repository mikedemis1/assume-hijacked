import threading
import urllib.error
import urllib.request

import pytest

from app.common.ops import Heartbeat, Metrics, start_ops_server


class FakeClock:
    def __init__(self, now=1000.0):
        self.now = now

    def __call__(self):
        return self.now


def get(server, path):
    """(status, body) of a GET on the running ops server."""
    url = f"http://127.0.0.1:{server.port}{path}"
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            return response.status, response.read().decode()
    except urllib.error.HTTPError as err:
        return err.code, err.read().decode()


@pytest.fixture
def serve():
    started = []

    def _start(metrics, heartbeat):
        server = start_ops_server(0, metrics, heartbeat, host="127.0.0.1")
        started.append(server)
        return server

    yield _start
    for server in started:
        server.shutdown()


def test_metrics_render_prometheus_text():
    metrics = Metrics()
    metrics.inc("executor_requests_total", {"kind": "credit", "status": "executed"})
    metrics.inc("executor_requests_total", {"kind": "credit", "status": "executed"}, by=2)
    metrics.inc("executor_requests_total", {"kind": "move_out", "status": 'say "hi"\\\n'})
    metrics.set("executor_last_poll_timestamp_seconds", 1760000000.5)
    text = metrics.render()
    lines = text.splitlines()
    assert "# TYPE executor_requests_total counter" in lines
    assert "# TYPE executor_last_poll_timestamp_seconds gauge" in lines
    assert 'executor_requests_total{kind="credit",status="executed"} 3' in lines
    # label values are quoted and escape backslash, double quote and newline
    assert 'executor_requests_total{kind="move_out",status="say \\"hi\\"\\\\\\n"} 1' in lines
    assert "executor_last_poll_timestamp_seconds 1760000000.5" in lines
    assert text.endswith("\n")
    # one TYPE line per metric, written before its samples
    assert lines.index("# TYPE executor_requests_total counter") < lines.index(
        'executor_requests_total{kind="credit",status="executed"} 3'
    )


def test_metrics_gauge_overwrites_and_counter_cannot_go_down():
    metrics = Metrics()
    metrics.set("queue_depth", 5)
    metrics.set("queue_depth", 2)
    assert "queue_depth 2" in metrics.render().splitlines()
    with pytest.raises(ValueError):
        metrics.inc("queue_depth")  # a gauge is not a counter
    metrics.inc("calls_total")
    with pytest.raises(ValueError):
        metrics.inc("calls_total", by=-1)
    with pytest.raises(ValueError):
        metrics.set("calls_total", 0)  # a counter is not a gauge


@pytest.mark.parametrize("name", ["", "1bad", "has space", "a-b"])
def test_metrics_refuse_bad_names(name):
    with pytest.raises(ValueError):
        Metrics().inc(name)


def test_metrics_refuse_bad_label_names():
    with pytest.raises(ValueError):
        Metrics().inc("x_total", {"bad-label": "v"})


def test_metrics_are_safe_to_increment_from_many_threads():
    metrics = Metrics()

    def work():
        for _ in range(500):
            metrics.inc("hits_total")

    threads = [threading.Thread(target=work) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert "hits_total 4000" in metrics.render().splitlines()


def test_heartbeat_goes_stale_after_max_age_and_beat_revives_it():
    clock = FakeClock(1000.0)
    heartbeat = Heartbeat(max_age_s=60, clock=clock)
    assert heartbeat.alive(1000.0)  # starting counts as the first beat
    assert heartbeat.alive(1060.0)  # exactly max_age is still alive
    assert not heartbeat.alive(1060.1)
    clock.now = 1100.0
    heartbeat.beat()
    assert heartbeat.alive(1100.0)
    assert heartbeat.alive(1160.0)
    assert not heartbeat.alive(1161.0)


def test_healthz_503_when_heartbeat_stale(serve):
    clock = FakeClock(1000.0)
    heartbeat = Heartbeat(max_age_s=60, clock=clock)
    server = serve(Metrics(), heartbeat)
    assert get(server, "/healthz")[0] == 200
    clock.now = 1061.0  # 61 s without a beat
    status, body = get(server, "/healthz")
    assert status == 503
    assert "stale" in body


def test_healthz_200_after_beat(serve):
    clock = FakeClock(1000.0)
    heartbeat = Heartbeat(max_age_s=60, clock=clock)
    server = serve(Metrics(), heartbeat)
    clock.now = 1061.0
    assert get(server, "/healthz")[0] == 503
    heartbeat.beat()
    assert get(server, "/healthz") == (200, "ok\n")


def test_metrics_endpoint_serves_the_text_and_unknown_paths_404(serve):
    metrics = Metrics()
    metrics.inc("seen_total")
    server = serve(metrics, Heartbeat())
    status, body = get(server, "/metrics")
    assert status == 200
    assert "seen_total 1" in body.splitlines()
    assert get(server, "/")[0] == 404
    assert get(server, "/metrics/extra")[0] == 404


def test_ops_server_does_not_log_requests_to_stderr(serve, capsys):
    server = serve(Metrics(), Heartbeat())
    get(server, "/healthz")
    assert capsys.readouterr().err == ""
