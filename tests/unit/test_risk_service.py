"""The risk service (app/risk/service.py): POST /decide for every tool call, and the loop that
assesses every pending effect request. Plus the database objects it brings (db/sql/06-risk.sql):
heartbeats and beat(), risk_lease_facts, blocked_calls_on_ticket, home_protection, and the one
allowed effect call per lease.

The rules themselves are pure and tested in tests/test_risk_rules.py. Here: that the service
gathers the right facts from the database, writes what it decided, and fails closed.
"""

import hashlib

import psycopg
import pytest
from starlette.testclient import TestClient

from app.common.ops import Metrics
from app.risk import service
from app.risk.rules import ENGINE_VERSION
from tests.conftest import open_lease
from tests.unit.test_executor_credits import add_credit
from tests.unit.test_executor_moveouts import add_moveout

ANNA = "eeab6c5e-f5bc-5d16-af4b-813d9b88be01"


@pytest.fixture
def engine(as_role):
    """One risk_engine connection per test (CONNECTION LIMIT 5; the stack's engine holds two)."""
    return as_role("risk_engine")


def lease_hash(lease):
    return hashlib.sha256(lease.encode()).digest()


def calls(admin):
    return admin.execute(
        "SELECT lease_hash, tool, decision, reasons, actor FROM call_assessments ORDER BY id"
    ).fetchall()


def control(admin):
    return admin.execute("SELECT paused, reason FROM agent_control").fetchone()


def lines(metrics):
    return metrics.render().splitlines()


# --- POST /decide: the judgement on one tool call ---

def test_decide_allows_first_read_and_denies_second_effect(admin, engine):
    lease = open_lease(admin, 1)
    assert service.decide(engine, lease, "read_ticket") == ("allow", ())
    assert service.decide(engine, lease, "issue_bill_credit") == ("allow", ())
    # One effect per ticket: the second effect call on the lease is denied, whichever tool it is.
    assert service.decide(engine, lease, "request_disconnection") == ("deny", ("one_effect_per_ticket",))
    assert service.decide(engine, lease, "issue_bill_credit") == ("deny", ("one_effect_per_ticket",))
    rows = calls(admin)
    assert [(r["tool"], r["decision"], r["reasons"]) for r in rows] == [
        ("read_ticket", "allow", []),
        ("issue_bill_credit", "allow", []),
        ("request_disconnection", "deny", ["one_effect_per_ticket"]),
        ("issue_bill_credit", "deny", ["one_effect_per_ticket"]),
    ]
    # The database keeps sha256(lease), never the lease, and the engine as actor.
    assert {bytes(r["lease_hash"]) for r in rows} == {lease_hash(lease)}
    assert {r["actor"] for r in rows} == {"risk_engine"}


# --- the HTTP edge ---

class FakeDecider:
    def __init__(self, result=("allow", ()), error=None):
        self.result, self.error, self.seen = result, error, []

    def decide(self, lease, tool):
        self.seen.append((lease, tool))
        if self.error:
            raise self.error
        return self.result


def post(decider, body, **kwargs):
    client = TestClient(service.build_app(decider))
    if isinstance(body, (dict, list)):
        return client.post("/decide", json=body, **kwargs)
    return client.post("/decide", content=body, **kwargs)


BAD_BODIES = {
    "not json": b"{lease",
    "a list": ["x"],
    "no lease": {"tool": "read_ticket"},
    "no tool": {"lease": "a" * 64},
    "lease not a string": {"lease": 5, "tool": "read_ticket"},
    "tool not a string": {"lease": "a" * 64, "tool": ["read_ticket"]},
    "lease too long": {"lease": "a" * 257, "tool": "read_ticket"},
    "empty lease": {"lease": "", "tool": "read_ticket"},
    "tool with odd characters": {"lease": "a" * 64, "tool": "read_ticket; drop"},
    "body too large": b'{"lease": "' + b"a" * 5000 + b'", "tool": "read_ticket"}',
}


# --- assess_pending: a tier for every pending effect request ---

def assessments(admin):
    return {
        r["request_id"]: (r["tier"], r["reasons"])
        for r in admin.execute("SELECT request_id, tier, reasons FROM risk_assessments ORDER BY request_id")
    }


def test_assess_pending_gives_each_pending_request_one_assessment(admin, engine, settings, now):
    t0 = add_credit(admin, 49, 2, tier=None)  # a real duplicate charge, within the limit
    t1 = add_credit(admin, 10, 4, reason="outage", tier=None)  # no automatic evidence check
    t2 = add_credit(admin, 300, 999, tier=None)  # above both limits, no such charge
    protected = add_moveout(admin, account_id=3, ticket_id=3, tier=None)  # SP-1003, life support
    plain = add_moveout(admin, tier=None)  # SP-1001
    metrics = Metrics()
    assert service.assess_pending(engine, settings, now, metrics) == 5
    assert assessments(admin) == {
        t0: ("T0", []),
        t1: ("T1", ["no_auto_evidence"]),
        t2: ("T2", ["above_auto_limit", "above_200", "evidence_unconfirmed"]),
        protected: ("HUMAN_ONLY", ["protected_or_unknown_home"]),
        plain: ("T1", []),
    }
    rows = admin.execute("SELECT DISTINCT actor, engine_version FROM risk_assessments").fetchall()
    assert rows == [{"actor": "risk_engine", "engine_version": ENGINE_VERSION}]
    assert service.assess_pending(engine, settings, now, metrics) == 0  # nothing left to assess
    out = lines(metrics)
    assert 'risk_tiers_total{tier="T1"} 2' in out
    assert 'risk_tiers_total{tier="HUMAN_ONLY"} 1' in out


# --- database objects the service uses ---

def _login_roles(admin, *, exclude=()):
    rows = admin.execute("SELECT rolname FROM pg_roles WHERE rolcanlogin ORDER BY rolname").fetchall()
    return [r["rolname"] for r in rows if r["rolname"] not in ("postgres", *exclude)]


COMPONENTS = {
    "executor": "executor",
    "risk_engine": "risk-engine",
    "dispatcher": "dispatcher",
    "gateway": "tool-gateway",
}


def beats(admin):
    return {r["component"] for r in admin.execute("SELECT component FROM heartbeats")}


def test_risk_engine_cannot_read_leases_or_flags_directly(engine):
    for statement in ("SELECT token_hash FROM leases", "SELECT supply_point_id FROM flags",
                      "SELECT * FROM accounts",
                      "SELECT body FROM tickets"):
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            engine.execute(statement)


