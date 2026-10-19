"""An idle dispatcher's configured Job still has network permissions to assess."""

import json

import pytest

from secops.permassess import CollectorError, collect_k8s
from tests.test_permassess import _cluster
from tests.test_permassess import CAN_I_PLAIN, CAN_I_SECRETS
from secops.permassess import diff


def cluster_with_job(raw):
    base, _ = _cluster([], extra_accounts=[("ah-agent", "agent")])
    def run(args):
        if args[1:3] == ["get", "configmaps"]:
            # The dispatcher mounts by name. This map deliberately has no component label.
            if "-l" in args:
                return json.dumps({"items": []})
            return json.dumps({"items": [{"metadata": {"name": "agent-job-template",
                "namespace": "ah-intake"}, "data": {"job.json": raw}}]})
        return base(args)
    return run


def test_a_configured_agent_job_is_assessed_without_a_running_job():
    job = {"apiVersion": "batch/v1", "kind": "Job", "metadata": {"namespace": "ah-agent"},
           "spec": {"template": {"metadata": {"labels": {"app.kubernetes.io/name": "agent"}},
                                 "spec": {"serviceAccountName": "agent"}}}}
    result = collect_k8s.collect(cluster_with_job(json.dumps(job)))
    assert "agent" in result.scope["components"]
    # No policies in this fixture: an unrestricted idle Job must expose its edges.
    assert "k8s agent -> tool-lookup-account" in result.lines


@pytest.mark.parametrize("raw", ["broken json", "[]", '{"kind":"Pod"}',
    '{"apiVersion":"batch/v1","kind":"Job","metadata":{"namespace":"kube-system"}}'])
def test_a_broken_or_out_of_scope_agent_template_is_an_assessment_error(raw):
    with pytest.raises(CollectorError, match="agent Job template"):
        collect_k8s.collect(cluster_with_job(raw))


def test_cross_namespace_permissions_keep_the_target_namespace():
    base, _ = _cluster([], extra_accounts=[("ah-intake", "dispatcher")])
    jobs = CAN_I_PLAIN + "jobs.batch                                      []                  []               [create]\n"
    def run(args):
        if args[1:4] == ["auth", "can-i", "--list"] and "--as=system:serviceaccount:ah-intake:dispatcher" in args:
            return jobs if args[-1] == "ah-agent" else CAN_I_PLAIN
        if args[1:3] == ["get", "namespaces"]:
            doc = json.loads(base(args))
            doc["items"].append({"metadata": {"name": "ah-agent"}})
            return json.dumps(doc)
        return base(args)
    result = collect_k8s.collect(run)
    assert "k8s serviceaccount dispatcher: create jobs.batch in ah-agent" in result.lines
    assert "k8s serviceaccount dispatcher: create jobs.batch in ah-intake" not in result.lines


def test_namespace_exclusion_is_explicit_and_reported():
    run, _ = _cluster([], extra_accounts=[("ah-monitoring", "prometheus")])
    result = collect_k8s.collect(run, excluded_namespaces={"ah-monitoring"})
    assert "prometheus" not in result.scope["service_accounts"]
    assert "k8s namespace ah-monitoring excluded explicitly" in result.info


def test_declared_network_names_reconcile_the_local_database_label():
    doc = {"edges": ["tool-read-ticket -> db", "db-migrate -> db"], "k8s": [],
           "components": {"db": {"k8s_network_names": ["db", "postgres"]},
                          "db-migrate": {"k8s_network_names": ["db-migrate", "postgres-init"]}}}
    from secops.permassess import PlaneResult
    result = PlaneResult(lines=["k8s tool-read-ticket -> postgres", "k8s postgres-init -> postgres"],
                         scope={"components": {"tool-read-ticket", "postgres", "postgres-init"}})
    assert diff.compare("k8s", doc, result).equal


def test_public_discovery_defaults_do_not_hide_write_or_secret_grants():
    table = CAN_I_SECRETS + (
        "clustertrustbundles.certificates.k8s.io         []                  []               [get list watch update]\n"
        "                                                [/openid/v1/jwks]   []               [get post]\n")
    assert collect_k8s.parse_can_i(table) == ["get secrets", "post /openid/v1/jwks",
                                             "update clustertrustbundles.certificates.k8s.io"]


def test_duplicate_nondefault_principals_cannot_supply_each_others_expected_grants():
    run, _ = _cluster([], extra_accounts=[("ah-intake", "dispatcher"), ("ah-tools", "dispatcher")])
    with pytest.raises(CollectorError, match="duplicate service account name"):
        collect_k8s.collect(run)
