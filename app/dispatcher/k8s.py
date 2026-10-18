"""The dispatcher's two dealings with Kubernetes.

1. It creates one agent Job per ticket (`create_agent_job`), from the fixed template in
   app/agent/templates.py, with the Kubernetes API over HTTPS using only the standard library. The
   service account `dispatcher` may do exactly this and nothing else in the cluster apart from
   TokenReview: `create` on `jobs` in the namespace ah-agent (Role dispatcher-create-agent-jobs).
   https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/job-v1/#create-create-a-job
2. It tells which ticket a calling agent belongs to. The caller's token is checked with a TokenReview
   by app/common/tokenreview.py, which names the pod; `run_name_of_pod` turns the pod's name into the
   name of the Job that made it. The Job name is the key of the run (agent_runs.job_name).

The API server's address and CA come from the pod's own environment and mounted service account, like
the TokenReview client. Nothing from a ticket reaches this module except its number, and that is
checked to be digits before a Job is built.
"""

from __future__ import annotations

import json
import os
import ssl
import urllib.request
from collections.abc import Callable
from pathlib import Path

from app.agent import templates

SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"
MAX_ANSWER_BYTES = 256 * 1024


class KubeError(Exception):
    """The API server did not create the Job. The message never holds the Job."""


class KubeApi:
    def __init__(
        self,
        api_url: str | None = None,
        sa_dir: str = SA_DIR,
        post: Callable[[str, dict], dict] | None = None,
        timeout_s: float = 10,
    ) -> None:
        host, port = os.environ.get("KUBERNETES_SERVICE_HOST"), os.environ.get("KUBERNETES_SERVICE_PORT", "443")
        self.api_url = api_url or (f"https://{host}:{port}" if host else "https://kubernetes.default.svc")
        self.sa_dir = Path(sa_dir)
        self.timeout_s = timeout_s
        self._post = post or self._post_to_api

    def create_job(self, job: dict) -> dict:
        """POST the Job into its namespace. Returns the API server's answer (the created Job)."""
        namespace = job["metadata"]["namespace"]
        if namespace != templates.NAMESPACE:  # the Role allows only this one, and so does this code
            raise KubeError("jobs are created in ah-agent only")
        return self._post(f"/apis/batch/v1/namespaces/{namespace}/jobs", job)

    def _post_to_api(self, path: str, body: dict) -> dict:
        own_token = (self.sa_dir / "token").read_text(encoding="utf-8").strip()
        context = ssl.create_default_context(cafile=str(self.sa_dir / "ca.crt"))
        request = urllib.request.Request(
            f"{self.api_url}{path}",
            data=json.dumps(body).encode(),
            method="POST",
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {own_token}"},
        )
        # The API server's https URL from the pod's own environment, its CA from the mounted bundle.
        with urllib.request.urlopen(request, timeout=self.timeout_s, context=context) as answer:  # nosec B310
            return json.loads(answer.read(MAX_ANSWER_BYTES))


def create_agent_job(ticket_id: object, template: dict, api: KubeApi, name: str | None = None) -> str:
    """Create the agent Job for one ticket and return its name.

    `ticket_id` must be a real ticket number (digits only, checked here before anything is built).
    The Job is the template with its name and the label `ah/ticket` filled in (templates.build_job
    checks the result against the allowed shape again). The API server's answer must name the Job we
    asked for."""
    job = templates.build_job(template, ticket_id, name)
    try:
        created = api.create_job(job)
    except KubeError:
        raise
    except Exception as err:  # HTTP error, network error, odd answer: one error, no details
        raise KubeError(f"the Job could not be created ({type(err).__name__})") from None
    created_name = created.get("metadata", {}).get("name") if isinstance(created, dict) else None
    if created_name != job["metadata"]["name"]:
        raise KubeError("the API server's answer does not name the Job that was asked for")
    return created_name


def run_name_of_pod(pod: object) -> str | None:
    """The name of the Job (and so the run) an agent pod belongs to, or None."""
    return templates.pod_job_name(pod)
