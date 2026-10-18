"""The agent Job: one fixed template, filled in with a ticket number and a name, and nothing else.

In Kubernetes every ticket gets its own Job in the namespace ah-agent, created by the dispatcher.
What a Job may look like is decided here and, a second time, by the admission policy
(ah-agent-job-template in the chart), so a dispatcher that is taken over still cannot start a pod
with another service account, another image, a Secret, a host mount or outside the sandbox.

The template itself is rendered by the chart (templates/agent.yaml) as JSON and mounted into the
dispatcher, because the image digest and the service URLs are only known at deploy time. This module
does not trust it either: `check_job` compares the whole Job with the one shape allowed. Only these
parts are taken from the file, each after its own check:

    image            a registry name pinned by digest (name@sha256:<64 hex>)
    imagePullPolicy  IfNotPresent, Always or Never
    env              plain name/value pairs, from a fixed list of names (no valueFrom, no Secret)
    resources        cpu and memory requests and limits

Everything else is the shape below, field by field: service account `agent`, no API token mounted,
the sandbox runtime class, one container `agent` running `python -m app.agent.main`, a read-only
root file system, a non-root user, no capabilities, and three projected service account tokens
(audiences tool-gateway, llm-gateway, dispatcher, 10 minutes each) and no other volume.

What a ticket can change: the Job's name and the label `ah/ticket`, both set by `build_job` from an
integer. The label is digits only (the policy accepts nothing else), so no ticket text, customer
input or caller input can reach any other field. The text of a ticket is never passed here at all.
"""

from __future__ import annotations

import copy
import json
import re
import secrets
from pathlib import Path

NAMESPACE = "ah-agent"
RUNTIME_CLASS = "kata-vm-isolation"
SERVICE_ACCOUNT = "agent"
APP_UID = 10001
TOKEN_AUDIENCES = ("tool-gateway", "llm-gateway", "dispatcher")
TOKEN_SECONDS = 600
TOKEN_MOUNT = "/var/run/secrets/ah"
COMMAND = ["python", "-m", "app.agent.main"]
# Settings the agent may be given. All plain values; none can be a secret.
ENV_NAMES = ("APP_ENV", "CALLER_AUTH", "GATEWAY_URL", "LLM_GATEWAY_URL", "DISPATCHER_URL")
PULL_POLICIES = ("IfNotPresent", "Always", "Never")
IMAGE = re.compile(r"[a-z0-9][a-z0-9._/:-]*@sha256:[0-9a-f]{64}")
TICKET_LABEL = re.compile(r"[0-9]{1,18}")
JOB_NAME = re.compile(r"agent-([0-9]{1,18})-[0-9a-f]{8}")
# The Job controller names a pod <job name>-<5 characters>.
POD_NAME = re.compile(r"(agent-[0-9]{1,18}-[0-9a-f]{8})-[a-z0-9]{5}")
MAX_CPU_MILLI = 2000
MAX_MEMORY_MI = 1024
DEFAULT_TEMPLATE_FILE = "/etc/ah/agent-job-template/job.json"
MAX_TEMPLATE_BYTES = 64 * 1024


class TemplateError(ValueError):
    """The template, or a Job built from it, is not the allowed shape."""


def ticket_label(ticket_id: object) -> str:
    """The value of the `ah/ticket` label: ASCII digits only. An int that is a real ticket number
    (not a bool, not negative, not zero) or a string of digits; anything else is refused before a
    Job is built."""
    if isinstance(ticket_id, bool):
        raise TemplateError("the ticket id is not a number")
    if isinstance(ticket_id, int):
        label = str(ticket_id)
    elif isinstance(ticket_id, str):
        label = ticket_id
    else:
        raise TemplateError("the ticket id is not a number")
    if not TICKET_LABEL.fullmatch(label) or int(label) < 1:
        raise TemplateError("the ticket id must be 1 to 18 digits")
    return label


def job_name(ticket_id: object, suffix: str | None = None) -> str:
    """agent-<ticket>-<8 hex>. The suffix is random; it keeps a name unique, nothing more."""
    suffix = secrets.token_hex(4) if suffix is None else suffix
    name = f"agent-{ticket_label(ticket_id)}-{suffix}"
    if not JOB_NAME.fullmatch(name):
        raise TemplateError("the job name suffix must be 8 lowercase hex digits")
    return name


def pod_job_name(pod: object) -> str | None:
    """The name of the Job a pod of the agent belongs to, or None if the pod name is not one a Job
    of this template creates."""
    match = POD_NAME.fullmatch(pod) if isinstance(pod, str) else None
    return match.group(1) if match else None


def _container_security() -> dict:
    return {
        "allowPrivilegeEscalation": False,
        "capabilities": {"drop": ["ALL"]},
        "readOnlyRootFilesystem": True,
        "runAsGroup": APP_UID,
        "runAsNonRoot": True,
        "runAsUser": APP_UID,
        "seccompProfile": {"type": "RuntimeDefault"},
    }


def _expected(image: str, pull_policy: str, env: list, resources: dict) -> dict:
    labels = {"ah/ticket": "", "app.kubernetes.io/name": "agent"}
    return {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {"labels": dict(labels), "namespace": NAMESPACE},
        "spec": {
            "activeDeadlineSeconds": 300,
            "backoffLimit": 0,
            "ttlSecondsAfterFinished": 600,
            "template": {
                "metadata": {"labels": dict(labels)},
                "spec": {
                    "automountServiceAccountToken": False,
                    "containers": [
                        {
                            "command": list(COMMAND),
                            "env": env,
                            "image": image,
                            "imagePullPolicy": pull_policy,
                            "name": "agent",
                            "resources": resources,
                            "securityContext": _container_security(),
                            "volumeMounts": [{"mountPath": TOKEN_MOUNT, "name": "ah-tokens", "readOnly": True}],
                        }
                    ],
                    "enableServiceLinks": False,
                    "restartPolicy": "Never",
                    "runtimeClassName": RUNTIME_CLASS,
                    "securityContext": {
                        "fsGroup": APP_UID,
                        "runAsGroup": APP_UID,
                        "runAsNonRoot": True,
                        "runAsUser": APP_UID,
                        "seccompProfile": {"type": "RuntimeDefault"},
                    },
                    "serviceAccountName": SERVICE_ACCOUNT,
                    "volumes": [
                        {
                            "name": "ah-tokens",
                            "projected": {
                                "sources": [
                                    {
                                        "serviceAccountToken": {
                                            "audience": audience,
                                            "expirationSeconds": TOKEN_SECONDS,
                                            "path": f"{audience}/token",
                                        }
                                    }
                                    for audience in TOKEN_AUDIENCES
                                ]
                            },
                        }
                    ],
                },
            },
        },
    }


def _milli_cpu(value: str) -> int | None:
    match = re.fullmatch(r"([0-9]+)(m?)", value)
    return None if match is None else int(match.group(1)) * (1 if match.group(2) else 1000)


def _mebibytes(value: str) -> int | None:
    match = re.fullmatch(r"([0-9]+)(Mi|Gi)", value)
    return None if match is None else int(match.group(1)) * (1024 if match.group(2) == "Gi" else 1)


def _resources_ok(resources: object) -> bool:
    """cpu and memory requests and limits within the caps (a Job cannot ask for more than a small pod)."""
    if not isinstance(resources, dict) or not set(resources) <= {"limits", "requests"}:
        return False
    for group in resources.values():
        if not isinstance(group, dict) or not set(group) <= {"cpu", "memory"}:
            return False
        for name, value in group.items():
            if not isinstance(value, str):
                return False
            amount = _milli_cpu(value) if name == "cpu" else _mebibytes(value)
            if amount is None or amount > (MAX_CPU_MILLI if name == "cpu" else MAX_MEMORY_MI):
                return False
    return True


def _loose_parts(job: dict) -> tuple[str, str, list, dict]:
    """The four things taken from the file, each checked. TemplateError if any is not allowed."""
    try:
        container = job["spec"]["template"]["spec"]["containers"][0]
        image, pull_policy = container["image"], container["imagePullPolicy"]
        env, resources = container["env"], container["resources"]
    except (KeyError, IndexError, TypeError):
        raise TemplateError("the Job has no container with an image, pull policy, env and resources") from None
    if not isinstance(image, str) or not IMAGE.fullmatch(image):
        raise TemplateError("the image must be pinned by digest (name@sha256:<64 hex digits>)")
    if pull_policy not in PULL_POLICIES:
        raise TemplateError("imagePullPolicy is not one of IfNotPresent, Always, Never")
    if not isinstance(env, list) or not all(
        isinstance(item, dict)
        and set(item) == {"name", "value"}
        and item["name"] in ENV_NAMES
        and isinstance(item["value"], str)
        for item in env
    ):
        raise TemplateError(f"env must be plain name/value pairs with names from {ENV_NAMES}")
    if len({item["name"] for item in env}) != len(env):
        raise TemplateError("an env name is listed twice")
    if not _resources_ok(resources):
        raise TemplateError(
            f"resources must be cpu and memory requests and limits, at most {MAX_CPU_MILLI}m and {MAX_MEMORY_MI}Mi"
        )
    return image, pull_policy, env, resources


def check_job(job: object) -> None:
    """Raise TemplateError unless `job` is exactly the allowed Job, apart from the name and the
    ticket label (which may be the empty placeholder or digits, the same on the Job and its pod
    template). Works on the template from the file and on a Job built from it."""
    if not isinstance(job, dict):
        raise TemplateError("the Job is not an object")
    image, pull_policy, env, resources = _loose_parts(job)
    probe = copy.deepcopy(job)
    try:
        metadata = probe["metadata"]
        name = metadata.pop("name", None)
        label = metadata["labels"]["ah/ticket"]
        pod_label = probe["spec"]["template"]["metadata"]["labels"]["ah/ticket"]
    except (KeyError, TypeError):
        raise TemplateError("the Job has no ah/ticket label") from None
    if not isinstance(label, str) or label != pod_label:
        raise TemplateError("the ah/ticket label differs between the Job and its pod template")
    if label != "":
        ticket_label(label)
        if not isinstance(name, str) or JOB_NAME.fullmatch(name) is None or JOB_NAME.fullmatch(name).group(1) != label:
            raise TemplateError("the Job name does not belong to the ticket")
    elif name is not None:
        raise TemplateError("a Job without a ticket label has a name")
    probe["metadata"]["labels"]["ah/ticket"] = ""
    probe["spec"]["template"]["metadata"]["labels"]["ah/ticket"] = ""
    wanted = _expected(image, pull_policy, env, resources)
    # Compared as JSON text, so 0 is not false and 10001.0 is not 10001 (Python's == would say they are).
    if _canonical(probe) != _canonical(wanted):
        raise TemplateError("the Job differs from the agent Job template: " + _first_difference(probe, wanted))


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _first_difference(found: object, wanted: object, path: str = "") -> str:
    """The path of the first field that differs, for the error message. Names the field, never its value."""
    if isinstance(found, dict) and isinstance(wanted, dict):
        for key in sorted(set(found) | set(wanted)):
            if key not in found:
                return f"{path}/{key} is missing"
            if key not in wanted:
                return f"{path}/{key} is not allowed"
            if _canonical(found[key]) != _canonical(wanted[key]):
                return _first_difference(found[key], wanted[key], f"{path}/{key}")
    if isinstance(found, list) and isinstance(wanted, list) and len(found) == len(wanted):
        for index, (a, b) in enumerate(zip(found, wanted)):
            if _canonical(a) != _canonical(b):
                return _first_difference(a, b, f"{path}[{index}]")
    return f"{path or '/'} has another value"


def load_template(path: str | Path = DEFAULT_TEMPLATE_FILE) -> dict:
    """Read and check the template the chart mounted. A missing, odd or changed file is an error."""
    file = Path(path)
    try:
        size = file.stat().st_size
    except OSError as err:
        raise TemplateError(f"the template file {file} cannot be read: {type(err).__name__}") from None
    if size > MAX_TEMPLATE_BYTES:
        raise TemplateError("the template file is too big")
    try:
        job = json.loads(file.read_text(encoding="utf-8"))
    except (OSError, ValueError) as err:
        raise TemplateError(f"the template file {file} cannot be read: {type(err).__name__}") from None
    check_job(job)
    if job["metadata"]["labels"]["ah/ticket"] != "" or "name" in job["metadata"]:
        raise TemplateError("the template must carry the empty ticket label and no name")
    return job


def build_job(template: dict, ticket_id: object, name: str | None = None) -> dict:
    """A copy of the template for one ticket. The only changes: metadata.name and the label
    `ah/ticket` on the Job and on its pod template. The result is checked again before it is
    returned."""
    label = ticket_label(ticket_id)
    check_job(template)
    job = copy.deepcopy(template)
    job["metadata"]["name"] = job_name(label) if name is None else name
    job["metadata"]["labels"]["ah/ticket"] = label
    job["spec"]["template"]["metadata"]["labels"]["ah/ticket"] = label
    check_job(job)
    return job
