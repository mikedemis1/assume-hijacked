"""The dispatcher built for tests: the real HTTP app with the real caller check (the Kubernetes token),
the real database role and the real store. Only the edges are replaced: the network by an ASGI
transport, the TokenReview by a function, the Kubernetes API by a recording fake.
"""

from __future__ import annotations

import asyncio
import copy
import json
from pathlib import Path

import httpx2

from app.agent import templates
from app.common.ops import Metrics
from app.common.tokenreview import Review
from app.dispatcher import k8s
from app.dispatcher import main as dispatcher_main
from app.dispatcher.main import Dispatcher, build_app, init_metrics
from app.dispatcher.store import DispatcherDb
from app.gateway.auth import AGENT_USER
from tests.conftest import TOOLS, open_lease
from tests.gatewayharness import AGENT_POD

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE_FILE = ROOT / "tests" / "fixtures" / "agent-job-template.json"
AGENT_IP = "10.250.2.5"  # the address a request comes from; the caller check does not read it
DEFAULT_POD = AGENT_POD  # the pod of a lease opened by hand (the tool gateway harness knows the same pod)
NO_RUN_POD = "agent-99-deadbeef-abcde"  # well formed, but no Job made it
EVENTS = "assume_hijacked.security"


# --- the harness ---------------------------------------------------------------------------------


def request(app, method, path, *, headers=None, content=None, ip=AGENT_IP):
    """One request to the app as if it came from `ip` (None: no peer address at all)."""

    async def go():
        client = None if ip is None else (ip, 50000)
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app, client=client), base_url="http://dispatcher.test"
        ) as http:
            return await http.request(method, path, headers=headers, content=content)

    return asyncio.run(go())


def post(app, path, *, lease=None, body=None, headers=None, ip=AGENT_IP, content=None):
    sent = dict(headers or {})
    if lease is not None:
        sent["X-Lease"] = lease
    if content is None and body is not None:
        content = json.dumps(body)
    return request(app, "POST", path, headers=sent, content=content, ip=ip)


class CountingStore(DispatcherDb):
    """The real store, counting how often it was used: a refused request must leave it at 0."""

    def __init__(self, connect):
        super().__init__(connect)
        self.used = 0

    def _use(self, work):
        self.used += 1
        return super()._use(work)


class FakeKube:
    """Stands in for the Kubernetes API: keeps every Job it was asked to create."""

    def __init__(self, answer=None, fail_for=()):
        self.created: list[dict] = []
        self._answer, self._fail_for = answer, set(fail_for)

    def post(self, path, body):
        assert path == "/apis/batch/v1/namespaces/ah-agent/jobs", path
        if int(body["metadata"]["labels"]["ah/ticket"]) in self._fail_for:
            raise OSError("403 Forbidden: jobs.batch is forbidden for dispatcher")
        self.created.append(copy.deepcopy(body))
        return self._answer(body) if self._answer else {"metadata": {"name": body["metadata"]["name"]}}

    def api(self):
        return k8s.KubeApi(api_url="https://kube.test", post=self.post)


def pod_of(job_name, suffix="x7k2p"):
    return f"{job_name}-{suffix}"


class Harness:
    """The dispatcher in Kubernetes mode, the only mode. By default the Kubernetes API is a FakeKube
    (`kube`) and the TokenReview knows the tokens put into `tokens` by `agent(pod)`."""

    def __init__(self, settings, as_role, *, mode="k8s", reviewer=None, api=None, max_active=3, template=None):
        self.metrics = Metrics()
        init_metrics(self.metrics)
        self.store = CountingStore(lambda: as_role("dispatcher"))
        self.tokens: dict = {}
        self.kube = None
        if api is None:
            self.kube = FakeKube()
            api = self.kube.api()
        self.api = api
        self.pods: dict[str, str] = {}  # lease -> the pod it was claimed or opened for
        self.last_pod: str | None = None
        self._taken: set[str] = set()
        self.dispatcher = Dispatcher(
            self.store,
            mode,
            self.metrics,
            template=template if template is not None else templates.load_template(TEMPLATE_FILE),
            api=api,
            max_active=max_active,
        )
        # The same function the process uses, so a wrong audience there is caught here.
        auth = dispatcher_main.caller_auth(mode, reviewer or reviewer_for(self.tokens))
        self.app = build_app(self.dispatcher, auth, self.metrics)

    def agent(self, pod, token=None, user=AGENT_USER):
        """The Authorization header of a caller the TokenReview knows as `user`, in `pod`."""
        token = token or f"token-of-{pod}"
        self.tokens[token] = (user, pod)
        return {"Authorization": f"Bearer {token}"}

    def owner(self, lease):
        """The headers of the pod the lease belongs to (the default pod for a lease nobody claimed)."""
        return self.agent(self.pods.get(lease, DEFAULT_POD))

    def lease_for(self, admin, ticket):
        """A lease as a claim would open it, bound to the default pod."""
        lease = open_lease(admin, ticket, tools=TOOLS, bound_pod=DEFAULT_POD)
        self.pods[lease] = DEFAULT_POD
        return lease

    def next_agent(self):
        """The headers (a function, as the agent's client wants them) of the pod of the next Job that
        nobody has claimed; Jobs are started when none is free. With no Job at all, of a pod that no
        run belongs to. The pod is kept in `last_pod`."""
        assert self.kube is not None, "next_agent needs the harness's own FakeKube"

        def free():
            names = [job["metadata"]["name"] for job in self.kube.created]
            return [name for name in names if name not in self._taken]

        if not free():
            self.dispatcher.dispatch_once()
        if free():
            job = free()[0]
            self._taken.add(job)
            pod = pod_of(job)
        else:
            pod = NO_RUN_POD
        self.last_pod = pod
        headers = self.agent(pod)
        return lambda: dict(headers)


def reviewer_for(tokens):
    """A TokenReview stand-in: token -> (service account user, pod name) or nothing."""

    def review(token, audience):
        assert audience == "dispatcher"
        found = tokens.get(token)
        return None if found is None else Review(username=found[0], pod=found[1])

    return review
