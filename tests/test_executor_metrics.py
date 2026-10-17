"""The executor counts what it decided, by kind and status, and shows that it is still polling."""

from app.common.ops import Heartbeat, Metrics
from app.executor import main as executor_main
from app.executor.credits import process_credits
from app.executor.moveouts import process_moveouts
from tests.test_executor_credits import add_credit
from tests.test_executor_moveouts import add_moveout


def lines(metrics):
    return metrics.render().splitlines()


def test_credit_decisions_are_counted_by_status(admin, as_role, settings, now):
    add_credit(admin, 49, 2)  # real duplicate: executed
    add_credit(admin, 49, 2)  # same evidence again: rejected
    add_credit(admin, 49, 1)  # first of the pair, not a duplicate: needs_staff
    metrics = Metrics()
    process_credits(as_role("executor"), settings, now, metrics)
    out = lines(metrics)
    assert 'executor_requests_total{kind="credit",status="executed"} 1' in out
    assert 'executor_requests_total{kind="credit",status="rejected"} 1' in out
    assert 'executor_requests_total{kind="credit",status="needs_staff"} 1' in out


def test_move_out_decisions_are_counted_and_unchanged_requests_are_not(admin, as_role, settings, now):
    add_moveout(admin)
    metrics = Metrics()
    ex = as_role("executor")
    process_moveouts(ex, settings, now, metrics)
    assert 'executor_requests_total{kind="move_out",status="notice_sent"} 1' in lines(metrics)
    # Second pass: the notice is fresh, nothing is decided, so nothing is counted.
    process_moveouts(ex, settings, now, metrics)
    assert 'executor_requests_total{kind="move_out",status="notice_sent"} 1' in lines(metrics)
    assert sum(1 for line in lines(metrics) if line.startswith("executor_requests_total{")) == 1


def test_a_request_that_fails_is_counted_as_error(admin, as_role, settings, now, monkeypatch):
    add_credit(admin, 49, 2)

    def boom(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr("app.executor.credits.decide_credit", boom)
    metrics = Metrics()
    process_credits(as_role("executor"), settings, now, metrics)
    assert 'executor_requests_total{kind="credit",status="error"} 1' in lines(metrics)


def test_poll_beats_and_records_the_time(admin, as_role, settings, now):
    metrics = Metrics()
    clock = [100.0]
    heartbeat = Heartbeat(max_age_s=60, clock=lambda: clock[0])
    clock[0] = 200.0
    assert not heartbeat.alive(clock[0])  # 100 s since start: stale until the executor polls
    executor_main.poll(as_role("executor"), settings, now, metrics, heartbeat)
    assert heartbeat.alive(clock[0])
    assert f"executor_last_poll_timestamp_seconds {now.timestamp()!r}" in lines(metrics)
    # And in the database, where monitoring sees it without reaching the executor (db/sql/06-risk.sql).
    beat = admin.execute(
        "SELECT last_beat > now() - interval '1 minute' AS fresh FROM heartbeats WHERE component = 'executor'"
    ).fetchone()
    assert beat == {"fresh": True}
