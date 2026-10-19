"""The dispatcher's database access (role `dispatcher`, db/sql/05-lease.sql).

What the role can do: read ticket id and status, add and update agent_runs, add a reply, open and
revoke a lease, read a live lease's scope, and read reply_facts (the numbers of the ticket owner's
account and whether a credit or a move-out went through the gateway). It cannot read a ticket's text,
any customer data, or change a reply.

Every method here is one transaction. One connection, used by one thread at a time; a lost
connection fails the call in hand and the next call opens a new one.
"""

from __future__ import annotations

import hashlib
import threading
from collections.abc import Callable
from dataclasses import dataclass

import psycopg
from app.dispatcher import replies

# Every lease the dispatcher opens lists all five tools: what a run may actually do is decided by
# the gateway and the risk engine on each call, not by a shorter list here.
LEASE_TOOLS = ["read_ticket", "lookup_account", "request_disconnection", "issue_bill_credit", "set_temp_protection"]
CANDIDATES = 5  # open tickets without a run looked at in one claim


@dataclass(frozen=True)
class Scope:
    ticket_id: int
    bound_pod: str | None


@dataclass(frozen=True)
class Facts:
    account_text: str
    credit_asked: bool
    moveout_submitted: bool


def lease_hash(lease: str) -> bytes:
    """sha256 of the lease as UTF-8 text, the same value the database stores."""
    return hashlib.sha256(lease.encode()).digest()


class DispatcherDb:
    def __init__(self, connect: Callable[[], psycopg.Connection]) -> None:
        self._connect = connect
        self._conn: psycopg.Connection | None = None
        self._lock = threading.Lock()

    def _use(self, work: Callable[[psycopg.Connection], object]):
        with self._lock:
            if self._conn is None or self._conn.closed:
                self._conn = self._connect()
            try:
                with self._conn.transaction():
                    return work(self._conn)
            except psycopg.OperationalError:
                self._drop()
                raise

    def _drop(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:  # nosec B110 - closing a broken connection may fail; it is dropped anyway
                pass
            self._conn = None

    def close(self) -> None:
        with self._lock:
            self._drop()

    # --- claim ---

    def claim_next_open_ticket(self) -> tuple[int, str] | None:
        """Compose: the lowest open ticket without a run gets one, and a lease. Returns
        (ticket id, lease) or None. Two claims at once cannot get the same ticket: the run's
        ticket_id is unique, so the second insert finds the row taken and moves on."""

        def work(conn):
            for row in conn.execute(
                "SELECT t.id FROM tickets t WHERE t.status = 'open' "
                "AND NOT EXISTS (SELECT 1 FROM agent_runs r WHERE r.ticket_id = t.id) ORDER BY t.id LIMIT %s",
                (CANDIDATES,),
            ).fetchall():
                taken = conn.execute(
                    "INSERT INTO agent_runs (ticket_id, status) VALUES (%s, 'started') "
                    "ON CONFLICT (ticket_id) DO NOTHING RETURNING id",
                    (row["id"],),
                ).fetchone()
                if taken is not None:
                    return row["id"], self._lease_for_run(conn, taken["id"], row["id"], None)
            return None

        return self._use(work)

    def claim_job(self, job_name: str, pod: str) -> tuple[int, str] | None:
        """Kubernetes: the run of this Job, if it has not been claimed yet, is claimed by this pod:
        the lease is bound to the pod, which the gateway then compares with the pod that calls it.
        Returns (ticket id, lease) or None (no such run, or already claimed)."""

        def work(conn):
            run = conn.execute(
                "SELECT id, ticket_id FROM agent_runs WHERE job_name = %s AND status = 'started' FOR UPDATE",
                (job_name,),
            ).fetchone()
            if run is None:
                return None
            return run["ticket_id"], self._lease_for_run(conn, run["id"], run["ticket_id"], pod)

        return self._use(work)

    @staticmethod
    def _lease_for_run(conn, run_id: int, ticket_id: int, pod: str | None) -> str:
        lease = conn.execute(
            "SELECT open_lease(%s, %s, %s) AS lease", (ticket_id, LEASE_TOOLS, pod)
        ).fetchone()["lease"]
        changed = conn.execute(
            "UPDATE agent_runs SET lease_hash = %s, status = 'claimed' WHERE id = %s AND status = 'started'",
            (lease_hash(lease), run_id),
        ).rowcount
        if changed != 1:  # cannot happen inside this transaction; if it does, nothing is handed out
            raise RuntimeError("the run could not be marked claimed")
        return lease

    # --- reply ---

    def scope(self, lease: str) -> Scope | None:
        """The live lease's ticket and bound pod; None for an unknown, expired or revoked lease."""

        def work(conn):
            row = conn.execute("SELECT ticket_id, bound_pod FROM lease_scope(%s)", (lease,)).fetchone()
            return None if row is None else Scope(row["ticket_id"], row["bound_pod"])

        return self._use(work)

    def facts(self, lease: str) -> Facts | None:
        def work(conn):
            row = conn.execute(
                "SELECT account_text, credit_asked, moveout_submitted FROM reply_facts(%s)", (lease,)
            ).fetchone()
            return None if row is None else Facts(row["account_text"], row["credit_asked"], row["moveout_submitted"])

        return self._use(work)

    def store_reply(self, ticket_id: int, text: str, lease: str) -> bool:
        """Store the reply, mark the run replied and revoke the lease, in one transaction. False if
        the ticket already has a reply (the lease is revoked all the same: it has been used)."""

        def work(conn):
            stored = conn.execute(
                "INSERT INTO replies (ticket_id, text) VALUES (%s, %s) ON CONFLICT (ticket_id) DO NOTHING "
                "RETURNING ticket_id",
                (ticket_id, text),
            ).fetchone()
            if stored is not None:
                conn.execute(
                    "UPDATE agent_runs SET status = 'replied' WHERE ticket_id = %s AND status = 'claimed'",
                    (ticket_id,),
                )
            conn.execute("SELECT revoke_lease(%s)", (lease,))
            return stored is not None

        return self._use(work)

    def finish_reply(self, lease: str, pod: str | None, text: str):
        """Close the lease, read final facts, guard and store the reply in one transaction."""
        def work(conn):
            facts = conn.execute("SELECT * FROM finish_reply_facts(%s, %s)", (lease, pod)).fetchone()
            if facts is None:
                return "lease", None, None
            done = replies.finish(text, facts["account_text"], facts["credit_asked"], facts["moveout_submitted"])
            stored = conn.execute(
                "INSERT INTO replies (ticket_id, text) VALUES (%s, %s) ON CONFLICT (ticket_id) DO NOTHING RETURNING ticket_id",
                (facts["ticket_id"], done.text),
            ).fetchone()
            if stored:
                conn.execute("UPDATE agent_runs SET status = 'replied' WHERE ticket_id = %s AND status = 'claimed'",
                             (facts["ticket_id"],))
            return "stored" if stored else "duplicate", facts["ticket_id"], done.blocked
        return self._use(work)

    # --- Jobs (Kubernetes) ---

    def active_runs(self) -> int:
        """Runs that are not finished and are recent: started or claimed in the last 10 minutes. A run
        older than that has outlived its Job (300 s), so it no longer takes a place."""
        return self._use(
            lambda conn: conn.execute(
                "SELECT count(*) AS n FROM agent_runs WHERE status IN ('started', 'claimed') "
                "AND created_at > now() - interval '10 minutes'"
            ).fetchone()["n"]
        )

    def start_next_run(self, name_for: Callable[[int], str]) -> tuple[int, str] | None:
        """Give the lowest open ticket without a run a run, named `name_for(ticket id)`. Returns
        (ticket id, job name) or None if there is no such ticket (or another dispatcher took it)."""

        def work(conn):
            for row in conn.execute(
                "SELECT t.id FROM tickets t WHERE t.status = 'open' "
                "AND NOT EXISTS (SELECT 1 FROM agent_runs r WHERE r.ticket_id = t.id) ORDER BY t.id LIMIT %s",
                (CANDIDATES,),
            ).fetchall():
                job_name = name_for(row["id"])
                made = conn.execute(
                    "INSERT INTO agent_runs (ticket_id, job_name, status) VALUES (%s, %s, 'started') "
                    "ON CONFLICT (ticket_id) DO NOTHING RETURNING id",
                    (row["id"], job_name),
                ).fetchone()
                if made is not None:
                    return row["id"], job_name
            return None

        return self._use(work)

    def fail_run(self, job_name: str) -> None:
        self._use(
            lambda conn: conn.execute(
                "UPDATE agent_runs SET status = 'failed' WHERE job_name = %s AND status = 'started'", (job_name,)
            )
        )

    def beat(self) -> None:
        self._use(lambda conn: conn.execute("SELECT beat('dispatcher')"))
