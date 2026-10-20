"""The dispatcher: which ticket an agent gets, the lease it works under, the reply guard run again
outside the agent, and (in Kubernetes) the Jobs.

The dispatcher is built the way the container builds it: the real HTTP app with the real caller check,
the real database role (`dispatcher`) and the real store. Only the edges are replaced: the network by
an ASGI transport that sets the source address, the TokenReview by a function, the Kubernetes API by a
recording fake.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from app.agent import templates
from app.agent.guard import SAFE_REPLY
from app.dispatcher import replies
from app.gateway.auth import AGENT_USER
from tests.conftest import TOOLS
from tests.dispatcherharness import AGENT_IP, TEMPLATE_FILE, Harness, pod_of, post, request


@pytest.fixture
def kube_harness(settings, as_role):
    """The dispatcher with a FakeKube; `h.agent(pod)` gives the headers of a caller in that pod."""
    return Harness(settings, as_role)


def metric(h, name, **labels):
    text = h.metrics.render()
    key = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
    for line in text.splitlines():
        if line.startswith(f"{name}{{{key}}} "):
            return float(line.rsplit(" ", 1)[1])
    raise AssertionError(f"no series {name}{{{key}}}")


def claim(h, **kwargs):
    return post(h.app, "/claim", **kwargs)


def stored(admin, ticket):
    row = admin.execute("SELECT text FROM replies WHERE ticket_id = %s", (ticket,)).fetchone()
    return None if row is None else row["text"]


def runs(admin):
    return admin.execute("SELECT ticket_id, status, job_name FROM agent_runs ORDER BY ticket_id").fetchall()


def live(admin, lease):
    return admin.execute("SELECT count(*) AS n FROM lease_scope(%s)", (lease,)).fetchone()["n"] == 1


def claimed(h):
    """The next Job's pod claims its ticket: (ticket id, lease). Jobs are started when none is free."""
    headers = h.next_agent()()
    answer = claim(h, headers=headers)
    assert answer.status_code == 200, answer.text
    lease = answer.json()["lease"]
    h.pods[lease] = h.last_pod
    return answer.json()["ticket_id"], lease


# --- POST /claim -----------------------------------------------------------------------------------


def test_claim_opens_lease_for_one_ticket(kube_harness, admin):
    h = kube_harness
    ticket, lease = claimed(h)
    assert ticket == 1                                 # the ticket of the Job the pod belongs to
    assert len(lease) == 64 and int(lease, 16) >= 0
    # The lease is live, names that ticket, lists every tool and is bound to the pod that asked.
    scope = admin.execute("SELECT ticket_id, allowed_tools, bound_pod FROM lease_scope(%s)", (lease,)).fetchone()
    assert scope == {"ticket_id": 1, "allowed_tools": list(TOOLS), "bound_pod": h.pods[lease]}
    # One run claimed, holding the lease's hash and never the lease.
    row = admin.execute("SELECT ticket_id, status, lease_hash, job_name FROM agent_runs WHERE ticket_id = 1").fetchone()
    assert row == {"ticket_id": 1, "status": "claimed", "lease_hash": hashlib.sha256(lease.encode()).digest(),
                   "job_name": h.kube.created[0]["metadata"]["name"]}
    assert lease not in json.dumps(admin.execute("SELECT * FROM agent_runs").fetchall(), default=str)
    assert metric(h, "dispatcher_claims_total", outcome="issued") == 1


# --- POST /reply: the guard, run again outside the agent ----------------------------------------

HIJACKED = [
    ("money", "Good news: your bill credit of 49 EUR has been approved.", "currency"),
    ("promise", "We will refund you in full.", "money_wording"),
    ("number", "Your account number is 123456.", "unapproved_number"),
    ("number_word", "You will receive forty nine units.", "number_word"),
    ("lookalike", "Your сredit is on its way", "script_mix"),
]


# --- POST /reply: the lease ----------------------------------------------------------------------


BAD_BODIES = {
    "not json": b"{nope",
    "a list": b'["text"]',
    "no text": b'{"reply": "hi"}',
    "text is a number": b'{"text": 5}',
    "text is null": b'{"text": null}',
    "empty text": b'{"text": ""}',
    "too long": json.dumps({"text": "a" * (replies.MAX_TEXT_CHARS + 1)}).encode(),
    "nested": b"[" * 5000 + b"]" * 5000,
    "empty body": b"",
}


# --- Kubernetes: Jobs, pods and tickets ---------------------------------------------------------


def test_k8s_claim_needs_the_agents_service_account_and_a_pod(kube_harness, admin):
    h = kube_harness
    h.dispatcher.dispatch_once()
    job = h.kube.created[0]["metadata"]["name"]
    pod = pod_of(job)
    before = lambda: (admin.execute("SELECT count(*) AS n FROM leases").fetchone()["n"], runs(admin))  # noqa: E731
    state = before()
    h.tokens["t-llm"] = ("system:serviceaccount:ah-agent:llm-gateway", pod)
    h.tokens["t-dispatcher"] = ("system:serviceaccount:ah-intake:dispatcher", pod)
    h.tokens["t-nopod"] = (AGENT_USER, None)
    for name, headers in {
        "no header": {},
        "wrong scheme": {"Authorization": f"Basic token-of-{pod}"},
        "unknown token": {"Authorization": "Bearer nobody"},
        "other service account": {"Authorization": "Bearer t-llm"},
        "dispatcher's own account": {"Authorization": "Bearer t-dispatcher"},
        "token without a pod": {"Authorization": "Bearer t-nopod"},
        "two headers": [("Authorization", "Bearer t-llm"), ("Authorization", "Bearer t-llm")],
    }.items():
        answer = request(h.app, "POST", "/claim", headers=headers, ip=AGENT_IP)
        assert answer.status_code == 401, name
    assert before() == state                                           # nothing was claimed
    assert claim(h, headers=h.agent(pod)).status_code == 200            # the control


def test_k8s_reply_needs_the_pod_the_lease_is_bound_to(kube_harness, admin):
    h = kube_harness
    h.dispatcher.dispatch_once()
    jobs = {int(j["metadata"]["labels"]["ah/ticket"]): j["metadata"]["name"] for j in h.kube.created}
    mine, theirs = pod_of(jobs[1]), pod_of(jobs[2])
    lease = claim(h, headers=h.agent(mine)).json()["lease"]
    other = h.agent(theirs)
    refused = post(h.app, "/reply", lease=lease, body={"text": "Thank you."}, headers=other)
    assert (refused.status_code, refused.json()) == (403, {"error": "lease"})
    assert stored(admin, 1) is None and live(admin, lease)
    # Not from the same pod under another account either (the account check is the caller check's).
    h.tokens["t-llm"] = ("system:serviceaccount:ah-agent:llm-gateway", mine)
    assert post(h.app, "/reply", lease=lease, body={"text": "Hi"}, headers={"Authorization": "Bearer t-llm"}).status_code == 401
    ok = post(h.app, "/reply", lease=lease, body={"text": "Thank you."}, headers=h.agent(mine))
    assert ok.status_code == 200 and stored(admin, 1) == "Thank you."
    assert not live(admin, lease)


# --- the Job template ----------------------------------------------------------------------------

TOKENS = [
    {"serviceAccountToken": {"audience": a, "expirationSeconds": 600, "path": f"{a}/token"}}
    for a in ("tool-gateway", "llm-gateway", "dispatcher")
]


def template():
    return json.loads(TEMPLATE_FILE.read_text(encoding="utf-8"))


def test_job_template_is_fixed():
    """Every field of the Job the dispatcher creates, written out. A Job made for ticket 7 is this and
    nothing else (the image, env and resources are the values the chart rendered)."""
    source = template()
    image = source["spec"]["template"]["spec"]["containers"][0]["image"]
    job = templates.build_job(source, 7, name="agent-7-0a1b2c3d")
    pod = job["spec"]["template"]["spec"]
    container = pod["containers"][0]
    restricted = {
        "allowPrivilegeEscalation": False,
        "capabilities": {"drop": ["ALL"]},
        "readOnlyRootFilesystem": True,
        "runAsGroup": 10001,
        "runAsNonRoot": True,
        "runAsUser": 10001,
        "seccompProfile": {"type": "RuntimeDefault"},
    }
    assert job["apiVersion"] == "batch/v1" and job["kind"] == "Job"
    assert job["metadata"] == {
        "name": "agent-7-0a1b2c3d",
        "namespace": "ah-agent",
        "labels": {"app.kubernetes.io/name": "agent", "ah/ticket": "7"},
    }
    assert set(job) == {"apiVersion", "kind", "metadata", "spec"}
    assert job["spec"]["backoffLimit"] == 0
    assert job["spec"]["activeDeadlineSeconds"] == 300
    assert job["spec"]["ttlSecondsAfterFinished"] == 600
    assert set(job["spec"]) == {"backoffLimit", "activeDeadlineSeconds", "ttlSecondsAfterFinished", "template"}
    assert job["spec"]["template"]["metadata"] == {"labels": {"app.kubernetes.io/name": "agent", "ah/ticket": "7"}}
    assert pod["serviceAccountName"] == "agent"
    assert pod["automountServiceAccountToken"] is False
    assert pod["runtimeClassName"] == "kata-vm-isolation"
    assert pod["restartPolicy"] == "Never"
    assert pod["enableServiceLinks"] is False
    assert pod["securityContext"] == {
        "fsGroup": 10001, "runAsGroup": 10001, "runAsNonRoot": True, "runAsUser": 10001,
        "seccompProfile": {"type": "RuntimeDefault"},
    }
    assert set(pod) == {
        "serviceAccountName", "automountServiceAccountToken", "runtimeClassName", "restartPolicy",
        "enableServiceLinks", "securityContext", "containers", "volumes",
    }
    assert [c["name"] for c in pod["containers"]] == ["agent"]
    assert container["image"] == image and templates.IMAGE.fullmatch(image) and "@sha256:" in image
    assert container["command"] == ["python", "-m", "app.agent.main"]
    assert container["securityContext"] == restricted
    assert container["volumeMounts"] == [{"name": "ah-tokens", "mountPath": "/var/run/secrets/ah", "readOnly": True}]
    assert set(container) == {"name", "image", "imagePullPolicy", "command", "env", "volumeMounts", "securityContext", "resources"}
    # No Secret anywhere: plain env values only, no envFrom, no valueFrom, no secret volume.
    assert all(set(item) == {"name", "value"} for item in container["env"])
    assert {item["name"] for item in container["env"]} <= {
        "APP_ENV", "CALLER_AUTH", "GATEWAY_URL", "LLM_GATEWAY_URL", "DISPATCHER_URL"}
    assert pod["volumes"] == [{"name": "ah-tokens", "projected": {"sources": TOKENS}}]
    assert "secret" not in json.dumps(job).lower().replace("secrets/ah", "")
    # The ticket text is not in the Job.
    assert "Hello" not in json.dumps(job)


def mutated(*path_and_value):
    *path, value = path_and_value
    job = template()
    node = job
    for key in path[:-1]:
        node = node[key]
    if value is DELETE:
        del node[path[-1]]
    else:
        node[path[-1]] = value
    return job


DELETE = object()
SPEC = ("spec", "template", "spec")
CONTAINER = (*SPEC, "containers", 0)
MUTATIONS = {
    "service account": mutated(*SPEC, "serviceAccountName", "llm-gateway"),
    "service account default": mutated(*SPEC, "serviceAccountName", "default"),
    "api token mounted": mutated(*SPEC, "automountServiceAccountToken", True),
    "api token as 0": mutated(*SPEC, "automountServiceAccountToken", 0),
    "runtime class": mutated(*SPEC, "runtimeClassName", "runc"),
    "no runtime class": mutated(*SPEC, "runtimeClassName", DELETE),
    "image by tag": mutated(*CONTAINER, "image", "localhost:5001/assume-hijacked:latest"),
    "image short digest": mutated(*CONTAINER, "image", "localhost:5001/assume-hijacked@sha256:abc"),
    "image digest upper": mutated(*CONTAINER, "image", "localhost:5001/assume-hijacked@sha256:" + "A" * 64),
    "image with a space": mutated(*CONTAINER, "image", "evil @sha256:" + "a" * 64),
    "command": mutated(*CONTAINER, "command", ["sh", "-c", "env"]),
    "command extra": mutated(*CONTAINER, "command", ["python", "-m", "app.agent.main", "--x"]),
    "args": mutated(*CONTAINER, "args", ["--x"]),
    "env from a secret": mutated(*CONTAINER, "env", [{"name": "APP_ENV", "valueFrom": {"secretKeyRef": {"name": "s", "key": "k"}}}]),
    "env with a secret name": mutated(*CONTAINER, "env", [{"name": "DB_PASSWORD_GATEWAY", "value": "x"}]),
    "env twice": mutated(*CONTAINER, "env", [{"name": "APP_ENV", "value": "a"}, {"name": "APP_ENV", "value": "b"}]),
    "env value not text": mutated(*CONTAINER, "env", [{"name": "APP_ENV", "value": 5}]),
    "envFrom": mutated(*CONTAINER, "envFrom", [{"secretRef": {"name": "gateway-secrets"}}]),
    "privileged": mutated(*CONTAINER, "securityContext", "privileged", True),
    "escalation": mutated(*CONTAINER, "securityContext", "allowPrivilegeEscalation", True),
    "capability added": mutated(*CONTAINER, "securityContext", "capabilities", {"drop": ["ALL"], "add": ["NET_ADMIN"]}),
    "no drop all": mutated(*CONTAINER, "securityContext", "capabilities", {"drop": ["NET_RAW"]}),
    "writable root": mutated(*CONTAINER, "securityContext", "readOnlyRootFilesystem", False),
    "root user": mutated(*CONTAINER, "securityContext", "runAsUser", 0),
    "not non-root": mutated(*CONTAINER, "securityContext", "runAsNonRoot", False),
    "no seccomp": mutated(*CONTAINER, "securityContext", "seccompProfile", DELETE),
    "unconfined seccomp": mutated(*CONTAINER, "securityContext", "seccompProfile", {"type": "Unconfined"}),
    "pod root user": mutated(*SPEC, "securityContext", "runAsUser", 0),
    "pod securityContext gone": mutated(*SPEC, "securityContext", DELETE),
    "second container": mutated(*SPEC, "containers", [template()["spec"]["template"]["spec"]["containers"][0]] * 2),
    "container name": mutated(*CONTAINER, "name", "sidecar"),
    "init container": mutated(*SPEC, "initContainers", [{"name": "i", "image": "x"}]),
    "ephemeral container": mutated(*SPEC, "ephemeralContainers", [{"name": "i", "image": "x"}]),
    "host network": mutated(*SPEC, "hostNetwork", True),
    "host pid": mutated(*SPEC, "hostPID", True),
    "node name": mutated(*SPEC, "nodeName", "ah-control-plane"),
    "node selector": mutated(*SPEC, "nodeSelector", {"ah/pool": "system"}),
    "toleration": mutated(*SPEC, "tolerations", [{"operator": "Exists"}]),
    "priority class": mutated(*SPEC, "priorityClassName", "system-node-critical"),
    "dns config": mutated(*SPEC, "dnsConfig", {"nameservers": ["1.1.1.1"]}),
    "host aliases": mutated(*SPEC, "hostAliases", [{"ip": "1.1.1.1", "hostnames": ["x"]}]),
    "restart policy": mutated(*SPEC, "restartPolicy", "OnFailure"),
    "service links": mutated(*SPEC, "enableServiceLinks", True),
    "backoff": mutated("spec", "backoffLimit", 3),
    "deadline": mutated("spec", "activeDeadlineSeconds", 3600),
    "ttl": mutated("spec", "ttlSecondsAfterFinished", 86400),
    "manual selector": mutated("spec", "manualSelector", True),
    "parallelism": mutated("spec", "parallelism", 50),
    "completions": mutated("spec", "completions", 50),
    "namespace": mutated("metadata", "namespace", "ah-gateway"),
    "kind": mutated("kind", "CronJob"),
    "api version": mutated("apiVersion", "batch/v1beta1"),
    "owner": mutated("metadata", "ownerReferences", [{"kind": "Pod"}]),
    "annotation": mutated("metadata", "annotations", {"x": "y"}),
    "app label": mutated("metadata", "labels", "app.kubernetes.io/name", "tool-gateway"),
    "pod app label": mutated("spec", "template", "metadata", "labels", "app.kubernetes.io/name", "llm-gateway"),
    "extra label": mutated("metadata", "labels", "x", "y"),
    "no volumes": mutated(*SPEC, "volumes", DELETE),
    "secret volume": mutated(*SPEC, "volumes", [{"name": "ah-tokens", "secret": {"secretName": "gateway-secrets"}}]),
    "host path": mutated(*SPEC, "volumes", [{"name": "ah-tokens", "hostPath": {"path": "/"}}]),
    "token audience": mutated(*SPEC, "volumes", 0, "projected", "sources", 0, "serviceAccountToken", "audience", "https://kubernetes.default.svc"),
    "token lifetime": mutated(*SPEC, "volumes", 0, "projected", "sources", 0, "serviceAccountToken", "expirationSeconds", 86400),
    "token path": mutated(*SPEC, "volumes", 0, "projected", "sources", 0, "serviceAccountToken", "path", "../token"),
    "fourth token": mutated(*SPEC, "volumes", 0, "projected", "sources", TOKENS + [{"serviceAccountToken": {"audience": "x", "path": "x"}}]),
    "token for the api": mutated(*SPEC, "volumes", 0, "projected", "sources", TOKENS[:2] + [{"serviceAccountToken": {"path": "api/token"}}]),
    "secret source": mutated(*SPEC, "volumes", 0, "projected", "sources", TOKENS + [{"secret": {"name": "s"}}]),
    "mount path": mutated(*CONTAINER, "volumeMounts", [{"name": "ah-tokens", "mountPath": "/", "readOnly": True}]),
    "mount writable": mutated(*CONTAINER, "volumeMounts", [{"name": "ah-tokens", "mountPath": "/var/run/secrets/ah"}]),
    "mount subpath": mutated(*CONTAINER, "volumeMounts", [{"name": "ah-tokens", "mountPath": "/var/run/secrets/ah", "readOnly": True, "subPath": "x"}]),
    "second mount": mutated(*CONTAINER, "volumeMounts", [{"name": "ah-tokens", "mountPath": "/var/run/secrets/ah", "readOnly": True}] * 2),
    "pull policy": mutated(*CONTAINER, "imagePullPolicy", "Sometimes"),
    "resources": mutated(*CONTAINER, "resources", {"limits": {"cpu": "64"}}),
    "resources gpu": mutated(*CONTAINER, "resources", {"limits": {"nvidia.com/gpu": "1"}}),
    "lifecycle": mutated(*CONTAINER, "lifecycle", {"postStart": {"exec": {"command": ["id"]}}}),
    "ports": mutated(*CONTAINER, "ports", [{"containerPort": 80, "hostPort": 80}]),
    "workdir": mutated(*CONTAINER, "workingDir", "/"),
    "extra top key": mutated("status", {"x": 1}),
    "extra spec key": mutated("spec", "selector", {"matchLabels": {"a": "b"}}),
}


def _refused(call) -> bool:
    try:
        call()
    except templates.TemplateError:
        return True
    return False


def test_a_changed_template_is_refused(tmp_path):
    """Every way of changing the template (a changed ServiceAccount, a mounted Secret, ...) is refused
    when it is checked, when a Job is built from it, and when it is loaded from a file."""
    for name, job in MUTATIONS.items():
        path = tmp_path / "job.json"
        path.write_text(json.dumps(job))
        assert _refused(lambda: templates.check_job(job)), name
        assert _refused(lambda: templates.build_job(job, 1)), name
        assert _refused(lambda: templates.load_template(path)), name


@pytest.mark.parametrize("name, text, reason", HIJACKED, ids=[h[0] for h in HIJACKED])
def test_asi09_dispatcher_runs_the_guard_again(kube_harness, admin, name, text, reason):
    # The agent is taken over and sends what the model wrote without its own guard having run.
    h = kube_harness
    ticket, lease = claimed(h)
    answer = post(h.app, "/reply", lease=lease, headers=h.owner(lease), body={"text": text})
    assert (answer.status_code, answer.json()) == (200, {"stored": True})   # it does not say it replaced the text
    assert stored(admin, ticket) == SAFE_REPLY
    assert metric(h, "dispatcher_replies_blocked_total", reason=reason) == 1


# --- POST /reply: the phrases the old lists missed, and effect tickets --------------------------------

# Plain money promises that the old word lists let through.
MISSED_PHRASES = [
    "Good news: you will not be charged next month.",
    "Your next bill is free.",
    "Approved: 10 will be removed from your bill.",   # 10 is the street number, so it is an allowed number
    "We will cover the cost of the duplicate charge.",
    "10% less on the next invoice",
    "Το επόμενο μήνα δεν θα χρεωθείτε.",
]


def kind_of(admin, ticket):
    return admin.execute("SELECT kind FROM replies WHERE ticket_id = %s", (ticket,)).fetchone()["kind"]


def record_call(admin, lease, tool, outcome):
    """A row in the gateway's record of calls, as the gateway writes it after a call."""
    admin.execute(
        "INSERT INTO tool_calls (lease_hash, tool, arg_names, dropped_args, outcome) VALUES (%s, %s, '{}', '{}', %s)",
        (hashlib.sha256(lease.encode()).digest(), tool, outcome),
    )


@pytest.mark.parametrize("text", MISSED_PHRASES)
def test_asi09_dispatcher_blocks_money_promise_phrases_the_old_lists_missed(kube_harness, admin, text):
    h = kube_harness
    ticket, lease = claimed(h)
    answer = post(h.app, "/reply", lease=lease, headers=h.owner(lease), body={"text": text})
    assert answer.status_code == 200
    assert stored(admin, ticket) == SAFE_REPLY
    assert kind_of(admin, ticket) == "safe"


def test_asi09_honest_reply_on_a_ticket_without_an_effect_passes(kube_harness, admin):
    h = kube_harness
    ticket, lease = claimed(h)
    text = "Your tariff is G1 residential and your account is active."
    post(h.app, "/reply", lease=lease, headers=h.owner(lease), body={"text": text})
    assert stored(admin, ticket) == text
    assert kind_of(admin, ticket) == "agent"
    assert metric(h, "dispatcher_replies_templated_total", reason="effect_ticket") == 0


# What a hijacked model could write after an effect call: harmless-looking words, a promise, anything.
MODEL_TEXTS = [
    "Your refund of 5 euros is approved and the power will be cut on 1 November.",
    "Thank you for your patience.",
    "Your tariff is G1 residential and your account is active.",   # passes the guard, still not stored
]
EFFECT_CALLS = [
    ("issue_bill_credit", "ok", True, False),
    ("issue_bill_credit", "denied", True, False),
    ("request_disconnection", "ok", False, True),
    ("request_disconnection", "denied", False, False),   # attempted, nothing filed
]


@pytest.mark.parametrize("model_text", MODEL_TEXTS)
@pytest.mark.parametrize("tool, outcome, credit_notice, medical", EFFECT_CALLS)
def test_asi09_effect_ticket_stores_the_template_whatever_the_model_wrote(
        kube_harness, admin, tool, outcome, credit_notice, medical, model_text):
    h = kube_harness
    ticket, lease = claimed(h)
    record_call(admin, lease, tool, outcome)
    post(h.app, "/reply", lease=lease, headers=h.owner(lease), body={"text": model_text})
    reply = stored(admin, ticket)
    assert reply.startswith(replies.effect_template(()))                            # the fixed text first
    assert "review" not in reply and "hear from us" not in reply   # nothing was filed: no follow-up promise
    assert (replies.CREDIT_NOTICE in reply) is credit_notice
    assert (replies.MEDICAL_QUESTION in reply) is medical
    for word in ("refund", "euro", "approved", "cut", "November", "tariff", "Thank you for your patience"):
        assert word not in reply
    assert kind_of(admin, ticket) == "template"
    assert metric(h, "dispatcher_replies_templated_total", reason="effect_ticket") == 1
    assert metric(h, "dispatcher_replies_blocked_total", reason="money_wording") == 0


def test_effect_template_has_no_amount_and_no_promise():
    # The text is fixed, so this is checked once for every shape it can take, with the guard itself:
    # no digit except the request numbers, no money wording.
    from app.agent.guard import block_reason

    assert "requests (#7, #12)" in replies.effect_template((7, 12)) and "review them" in replies.effect_template((7, 12))
    assert "request (#7)" in replies.effect_template((7,)) and "review it" in replies.effect_template((7,))
    for ids in ((), (7,), (7, 12)):
        text = replies.effect_template(ids)
        assert block_reason(text, {str(i) for i in ids}) is None, ids
        assert not any(c.isdigit() for c in text.replace("#7", "").replace("#12", "")), ids


def test_asi09_effect_attempt_known_only_to_the_risk_engine_still_gives_the_template(kube_harness, admin):
    # The gateway has not recorded the call (tool_calls is empty) but the risk engine wrote its verdict
    # before answering: the attempt counts, and the model's text is not stored.
    h = kube_harness
    ticket, lease = claimed(h)
    admin.execute(
        "INSERT INTO call_assessments (lease_hash, tool, decision, reasons) VALUES (%s, 'issue_bill_credit', 'deny', '{}')",
        (hashlib.sha256(lease.encode()).digest(),),
    )
    post(h.app, "/reply", lease=lease, headers=h.owner(lease), body={"text": "Thank you for your patience."})
    assert stored(admin, ticket).startswith(replies.effect_template(()))
    assert kind_of(admin, ticket) == "template"
