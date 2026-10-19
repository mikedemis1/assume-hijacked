"""Permission assessment (secops/permassess): collectors, expected file, diff, report, CLI.

The database tests change privileges inside a transaction, collect from the same connection
and roll back, so nothing they grant outlives the test. The expected lines come from the
manifests in security/capabilities, which describe this repository's db/sql and compose.yaml.
tests/fixtures/permassess/compose-config.json is `docker compose --profile '*' config
--no-interpolate --format json` of compose.yaml with only the network fields kept; the test
that reads compose.yaml with PyYAML fails when the two drift apart.
"""
from __future__ import annotations

import copy
import json
import os
import shutil
from pathlib import Path

import psycopg
import pytest
import yaml

from secops.permassess import CollectorError, CommandMissing, PlaneResult, canon
from secops.permassess import __main__ as cli
from secops.permassess import (collect_azure, collect_compose, collect_k8s, collect_pg, diff,
                               expected, report)

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures" / "permassess"
CAPABILITIES = ROOT / "security" / "capabilities"
SOURCE = "security/capabilities"
COMPOSE_JSON = FIXTURES / "compose-config.json"
EXPECTED_FILE = ROOT / "security" / "expected-permissions.json"
MATRIX_DOC = ROOT / "docs" / "permission-matrix.md"
TOOL_ROLES = ("tool_read_ticket", "tool_lookup_account", "tool_request_disconnection",
              "tool_issue_bill_credit", "tool_set_temp_protection")


def every_role_but_the_superuser(expected_doc) -> list[str]:
    """PUBLIC reaches every role the database has, the bootstrap superuser aside."""
    roles = {line.split()[2].rstrip(":") for line in expected_doc["pg"] if ": ATTRIBUTES " in line}
    return sorted(roles - {"postgres"})


@pytest.fixture(scope="module")
def expected_doc() -> dict:
    return expected.build_expected(expected.load_manifests(CAPABILITIES), SOURCE)


@pytest.fixture
def tx(settings):
    """A superuser connection inside a transaction that is always rolled back."""
    conn = psycopg.connect(host=settings.db_host, port=settings.db_port, dbname=settings.db_name,
                           user="postgres", password=os.environ["POSTGRES_PASSWORD"])
    yield conn
    conn.rollback()
    conn.close()


def _pg_diff(conn, expected_doc) -> diff.PlaneDiff:
    return diff.compare("pg", expected_doc, PlaneResult(lines=collect_pg.collect(conn)))


def _manifests(tmp_path: Path, changes: dict[str, dict] | None = None) -> Path:
    """A copy of the fixture manifests, with some replaced."""
    target = tmp_path / "capabilities"
    shutil.copytree(CAPABILITIES, target)
    for name, data in (changes or {}).items():
        (target / f"{name}.json").write_text(json.dumps(data), encoding="utf-8")
    return target


# --- PostgreSQL ------------------------------------------------------------------------------

def test_current_schema_matches_the_expected_lines(tx, expected_doc):
    """Control: the database built by db/sql has exactly the declared permissions."""
    d = _pg_diff(tx, expected_doc)
    assert d.extra == [] and d.missing == []
    assert len(expected_doc["pg"]) > 100


def test_extra_grant_fails(tx, expected_doc):
    tx.execute("GRANT SELECT (phone) ON customers TO tool_lookup_account")
    tx.execute("GRANT DELETE ON flags TO executor")
    d = _pg_diff(tx, expected_doc)
    assert d.extra == ["pg role executor: DELETE ON public.flags",
                       "pg role tool_lookup_account: SELECT (phone) ON public.customers"]
    assert d.missing == []


def test_missing_grant_fails(tx, expected_doc):
    tx.execute("REVOKE EXECUTE ON FUNCTION api_set_temp_protection(text) FROM tool_set_temp_protection")
    d = _pg_diff(tx, expected_doc)
    assert d.extra == []
    assert d.missing == ["pg role tool_set_temp_protection: "
                         "EXECUTE ON FUNCTION public.api_set_temp_protection(text)"]


def test_public_execute_is_expanded(tx, expected_doc):
    tx.execute("GRANT EXECUTE ON FUNCTION api_set_temp_protection(text) TO PUBLIC")
    # The default privileges of db/sql take EXECUTE from PUBLIC on every new function, so a function
    # that PUBLIC may execute needs an explicit grant.
    tx.execute("CREATE FUNCTION public.leak() RETURNS int LANGUAGE sql AS 'SELECT 1'")
    tx.execute("GRANT EXECUTE ON FUNCTION public.leak() TO PUBLIC")
    d = _pg_diff(tx, expected_doc)
    roles = every_role_but_the_superuser(expected_doc)
    want = sorted(
        [f"pg role {r}: EXECUTE ON FUNCTION public.leak() (via PUBLIC)" for r in roles]
        + [f"pg role {r}: EXECUTE ON FUNCTION public.api_set_temp_protection(text) (via PUBLIC)"
           for r in roles])
    assert d.extra == want
    assert d.missing == []


def test_public_expansion_reaches_a_new_role_and_its_attributes_are_reported(tx, expected_doc):
    tx.execute("CREATE FUNCTION public.leak() RETURNS int LANGUAGE sql AS 'SELECT 1'")
    tx.execute("GRANT EXECUTE ON FUNCTION public.leak() TO PUBLIC")
    tx.execute("CREATE ROLE intruder LOGIN BYPASSRLS")
    d = _pg_diff(tx, expected_doc)
    assert "pg role intruder: ATTRIBUTES LOGIN, BYPASSRLS" in d.extra
    assert "pg role intruder: CONNECT ON DATABASE (via PUBLIC)" in d.extra
    assert "pg role intruder: EXECUTE ON FUNCTION public.leak() (via PUBLIC)" in d.extra


def test_role_membership_is_reported(tx, expected_doc):
    tx.execute("GRANT executor TO tool_read_ticket")
    tx.execute("GRANT pg_read_all_data TO tool_lookup_account WITH ADMIN OPTION")
    d = _pg_diff(tx, expected_doc)
    assert d.extra == [
        "pg role tool_lookup_account: MEMBER OF pg_read_all_data WITH ADMIN OPTION",
        "pg role tool_read_ticket: MEMBER OF executor"]


def test_role_attribute_change_is_reported(tx, expected_doc):
    tx.execute("ALTER ROLE tool_read_ticket CONNECTION LIMIT -1 CREATEROLE")
    d = _pg_diff(tx, expected_doc)
    assert d.extra == ["pg role tool_read_ticket: ATTRIBUTES LOGIN, CREATEROLE"]
    assert d.missing == ["pg role tool_read_ticket: ATTRIBUTES LOGIN, CONNECTION LIMIT 5"]


def test_security_definer_owner_is_reported(tx, expected_doc):
    tx.execute("ALTER FUNCTION api_set_temp_protection(text) OWNER TO executor")
    tx.execute("CREATE FUNCTION public.as_superuser() RETURNS int LANGUAGE sql "
               "SECURITY DEFINER AS 'SELECT 1'")
    tx.execute("REVOKE ALL ON FUNCTION public.as_superuser() FROM PUBLIC")
    d = _pg_diff(tx, expected_doc)
    assert "pg role executor: OWNS FUNCTION public.api_set_temp_protection(text) SECURITY DEFINER" in d.extra
    assert "pg role api_owner: OWNS FUNCTION public.api_set_temp_protection(text) SECURITY DEFINER" in d.missing
    # Owned by the superuser that runs the scripts: still listed, it runs with superuser rights.
    assert "pg role postgres: OWNS FUNCTION public.as_superuser() SECURITY DEFINER" in d.extra


def test_column_grants_are_one_line_per_column(tx, expected_doc):
    tx.execute("GRANT INSERT (reason, amount_eur) ON action_requests TO approver")
    d = _pg_diff(tx, expected_doc)
    assert d.extra == ["pg role approver: INSERT (amount_eur) ON public.action_requests",
                       "pg role approver: INSERT (reason) ON public.action_requests"]


def test_row_level_security_and_policies_are_reported(tx, expected_doc):
    tx.execute("CREATE TABLE public.rls_probe (id int)")
    tx.execute("ALTER TABLE rls_probe ENABLE ROW LEVEL SECURITY")
    tx.execute("ALTER TABLE rls_probe FORCE ROW LEVEL SECURITY")
    tx.execute("CREATE POLICY trusted_all ON rls_probe FOR ALL TO executor, approver "
               "USING (true) WITH CHECK (true)")
    tx.execute("CREATE POLICY everyone ON accounts AS RESTRICTIVE FOR SELECT USING (id > 0)")
    d = _pg_diff(tx, expected_doc)
    assert "pg table public.rls_probe: ROW LEVEL SECURITY, FORCED" in d.extra
    assert ("pg role executor: POLICY trusted_all ON public.rls_probe FOR ALL USING (true) "
            "WITH CHECK (true)") in d.extra
    # A policy without TO applies to PUBLIC: expanded like a grant.
    assert ("pg role tool_read_ticket: POLICY everyone ON public.accounts AS RESTRICTIVE "
            "FOR SELECT USING ((id > 0)) (via PUBLIC)") in d.extra


def test_default_privileges_are_reported(tx, expected_doc):
    tx.execute("ALTER DEFAULT PRIVILEGES FOR ROLE executor REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC")
    tx.execute("ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public "
               "GRANT SELECT ON TABLES TO approver")
    d = _pg_diff(tx, expected_doc)
    assert d.extra == [
        "pg role executor: DEFAULT PRIVILEGES ON FUNCTIONS REVOKE EXECUTE FROM PUBLIC",
        "pg role postgres: DEFAULT PRIVILEGES IN SCHEMA public ON TABLES GRANT SELECT TO approver"]


def test_functions_in_another_schema_and_their_owners_are_reported(tx, expected_doc):
    tx.execute("CREATE ROLE crypto_owner NOLOGIN")
    tx.execute("CREATE SCHEMA extras AUTHORIZATION crypto_owner")
    tx.execute("CREATE FUNCTION extras.rand(n int) RETURNS int LANGUAGE sql AS 'SELECT n'")
    tx.execute("REVOKE ALL ON FUNCTION extras.rand(int) FROM PUBLIC")
    tx.execute("GRANT USAGE ON SCHEMA extras TO executor")
    tx.execute("GRANT EXECUTE ON FUNCTION extras.rand(int) TO executor")
    d = _pg_diff(tx, expected_doc)
    assert "pg role crypto_owner: OWNS SCHEMA extras" in d.extra
    assert "pg role executor: USAGE ON SCHEMA extras" in d.extra
    assert "pg role executor: EXECUTE ON FUNCTION extras.rand(integer)" in d.extra


def test_the_collector_only_reads(tx, db_env):
    before = collect_pg.collect(tx)
    tx.rollback()
    assert collect_pg.collect(tx) == before
    # The command's own connection is read-only: the server refuses any write it might try.
    conn = cli._connect_pg(db_env)
    try:
        assert conn.execute("SHOW transaction_read_only").fetchone()[0] == "on"
        with pytest.raises(psycopg.errors.ReadOnlySqlTransaction):
            conn.execute("CREATE TABLE public.should_not_exist (id int)")
    finally:
        conn.close()


def test_database_owner_is_reported(tx, expected_doc):
    """Whoever owns the database also owns the public schema (pg_database_owner) and can drop
    or replace anything in it."""
    tx.execute("ALTER DATABASE supplier_test OWNER TO tool_read_ticket")
    d = _pg_diff(tx, expected_doc)
    assert d.extra == ["pg role tool_read_ticket: OWNS DATABASE",
                       "pg role tool_read_ticket: OWNS SCHEMA public"]
    assert d.missing == []


# --- expected file ---------------------------------------------------------------------------

def test_signatures_privileges_and_tables_are_normalised():
    assert canon.signature("api_request_credit(text, numeric,text , int)") == \
        "public.api_request_credit(text, numeric, text, integer)"
    assert canon.signature("crypto.gen_random_bytes(int4)") == "crypto.gen_random_bytes(integer)"
    assert canon.signature("open_lease(int, text[], text)") == "public.open_lease(integer, text[], text)"
    assert canon.signature("f(timestamptz, bool)") == \
        "public.f(timestamp with time zone, boolean)"
    assert canon.privilege("insert ( kind, detail )") == ("INSERT", ["kind", "detail"], False)
    assert canon.privilege("SELECT WITH GRANT OPTION") == ("SELECT", None, True)
    with pytest.raises(canon.CanonError):
        canon.privilege("SELEKT")


def test_generator_expands_public_and_rls_to_every_declared_role(tmp_path):
    caps = _manifests(tmp_path, {"db": {
        "component": "db",
        "db": {"role": None,
               "roles": [{"role": "api_owner", "login": False,
                          "owns": ["FUNCTION api_read_ticket(text) SECURITY DEFINER"],
                          "tables": {"leases": ["SELECT (token_hash, ticket_id)"]}},
                         {"role": "postgres", "bootstrap_superuser": True,
                          "default_privileges": ["ON FUNCTIONS REVOKE EXECUTE FROM PUBLIC"]}],
               "public": {"database": ["CONNECT"]},
               "rls": {"leases": {"forced": True, "policies": [
                   {"name": "trusted_all", "roles": ["api_owner", "PUBLIC"], "using": "true"}]}}}}})
    doc = expected.build_expected(expected.load_manifests(caps), "x")
    pg = doc["pg"]
    assert "pg role api_owner: ATTRIBUTES NOLOGIN" in pg
    assert "pg role api_owner: OWNS FUNCTION public.api_read_ticket(text) SECURITY DEFINER" in pg
    assert "pg role api_owner: SELECT (ticket_id) ON public.leases" in pg
    assert "pg role postgres: DEFAULT PRIVILEGES ON FUNCTIONS REVOKE EXECUTE FROM PUBLIC" in pg
    assert [ln for ln in pg if ln.startswith("pg role postgres: ATTRIBUTES")] == [
        "pg role postgres: ATTRIBUTES BOOTSTRAP SUPERUSER"]
    assert "pg role tool_read_ticket: CONNECT ON DATABASE (via PUBLIC)" in pg
    assert "pg role postgres: CONNECT ON DATABASE (via PUBLIC)" not in pg
    assert "pg table public.leases: ROW LEVEL SECURITY, FORCED" in pg
    assert "pg role api_owner: POLICY trusted_all ON public.leases FOR ALL USING (true)" in pg
    assert ("pg role executor: POLICY trusted_all ON public.leases FOR ALL USING (true) "
            "(via PUBLIC)") in pg


@pytest.mark.parametrize("change, message", [
    ({"component": "agent", "db": {"role": None}, "netwerk": {}}, r"unknown key\(s\) netwerk"),
    ({"component": "someone-else"}, "the file name says 'agent'"),
    ({"component": "agent", "db": {"role": "executor"}}, "role executor is already defined"),
    ({"component": "agent", "db": {"role": "x", "tables": {"t": ["SELEKT"]}}}, "unknown privilege"),
    ({"component": "agent", "db": {"role": None, "execute": ["f(int)"]}}, "role is null"),
    ({"component": "agent", "k8s": {"rbac": ["get pods"]}}, "without a service_account"),
])
def test_generator_rejects_manifests_it_cannot_read(tmp_path, change, message):
    caps = _manifests(tmp_path, {"agent": change})
    with pytest.raises(expected.ManifestError, match=message):
        expected.build_expected(expected.load_manifests(caps), "x")


def test_committed_expected_file_is_what_its_manifests_give():
    doc = json.loads(EXPECTED_FILE.read_text(encoding="utf-8"))
    assert cli.source_problem(doc, EXPECTED_FILE) is None
    assert doc["source"] == SOURCE


def test_a_hand_edited_expected_file_is_refused(tmp_path):
    doc = json.loads(EXPECTED_FILE.read_text(encoding="utf-8"))
    doc["pg"].append("pg role tool_read_ticket: SELECT ON public.flags")
    assert "is not what" in cli.source_problem(doc, EXPECTED_FILE)


def test_expected_check_mode_fails_on_a_stale_file(tmp_path):
    out = tmp_path / "expected.json"
    assert expected.main(["--capabilities", str(CAPABILITIES), "--out", str(out)]) == 0
    assert expected.main(["--capabilities", str(CAPABILITIES), "--out", str(out), "--check"]) == 0
    out.write_text(out.read_text(encoding="utf-8").replace("CONNECTION LIMIT 5", "CONNECTION LIMIT 9"),
                   encoding="utf-8")
    assert expected.main(["--capabilities", str(CAPABILITIES), "--out", str(out), "--check"]) == 1


# --- Compose ---------------------------------------------------------------------------------

def _compose() -> dict:
    return json.loads(COMPOSE_JSON.read_text(encoding="utf-8"))


def test_compose_fixture_matches_the_expected_edges(expected_doc):
    """Control: every pair on the one backend network is declared, and db's route out."""
    result = collect_compose.collect(_compose())
    d = diff.compare("compose", expected_doc, result)
    assert d.equal, (d.extra, d.missing)
    assert "compose db -> internet" in result.lines
    assert "db-migrate -> db" in d.not_deployed


def test_compose_yaml_read_as_ci_reads_it_gives_the_fixture_lines():
    """The CI job has no Docker CLI and reads compose.yaml with PyYAML (ci/permissions.sh). That
    must give the same lines as the fixture, which is `docker compose config` output, trimmed."""
    raw = yaml.safe_load((ROOT / "compose.yaml").read_text(encoding="utf-8"))
    from_yaml = collect_compose.collect(json.loads(json.dumps(raw)))
    from_fixture = collect_compose.collect(_compose())
    assert from_yaml.lines == from_fixture.lines
    assert from_yaml.scope == from_fixture.scope


def test_extra_network_edge_fails(expected_doc):
    config = _compose()
    config["networks"]["edge_x"] = {"internal": True}
    config["services"]["agent"]["networks"]["edge_x"] = None
    config["services"]["tool-read-ticket"]["networks"]["edge_x"] = None
    # A network that is not internal routes out; no other service is on it.
    config["networks"]["open"] = {}
    config["services"]["executor"]["networks"]["open"] = None
    d = diff.compare("compose", expected_doc, collect_compose.collect(config))
    assert d.extra == ["compose agent <-> tool-read-ticket", "compose executor -> internet"]
    assert d.missing == []


def test_missing_network_edge_fails(expected_doc):
    config = _compose()
    config["services"]["agent"]["networks"] = {"agent_only": None}
    config["networks"]["agent_only"] = {"internal": True}
    d = diff.compare("compose", expected_doc, collect_compose.collect(config))
    assert d.extra == []
    assert d.missing == ["compose agent <-> dispatcher", "compose agent <-> llm-gateway",
                         "compose agent <-> tool-gateway"]


def test_compose_network_modes():
    config = {"networks": {}, "services": {
        "a": {"network_mode": "host"}, "b": {"networks": {"n": None}},
        "c": {"network_mode": "service:b"}, "d": {"network_mode": "none"}, "e": {}}}
    config["networks"]["n"] = {"internal": True}
    lines = collect_compose.collect(config).lines
    assert lines == ["compose a -> internet", "compose b <-> c", "compose e -> internet"]


def test_compose_render_asks_for_every_profile_without_interpolation():
    calls = []

    def run(args):
        calls.append(list(args))
        return json.dumps(_compose())

    assert collect_compose.render("compose.yaml", run)["services"]
    assert calls == [["docker", "compose", "-f", "compose.yaml", "--profile", "*", "config",
                      "--no-interpolate", "--format", "json"]]
    with pytest.raises(CollectorError):
        collect_compose.render("compose.yaml", lambda args: "not json")


# --- Kubernetes ------------------------------------------------------------------------------

def _np(name, ns, selector, types, ingress=None, egress=None):
    spec = {"podSelector": selector, "policyTypes": types}
    if ingress is not None:
        spec["ingress"] = ingress
    if egress is not None:
        spec["egress"] = egress
    return {"metadata": {"name": name, "namespace": ns}, "spec": spec}


def _sel(name):
    return {"matchExpressions": [{"key": "app.kubernetes.io/name", "operator": "In", "values": [name]}]}


def _peer(ns, name):
    return {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": ns}},
            "podSelector": _sel(name)}


CAN_I_GATEWAY = """\
Resources                                       Non-Resource URLs   Resource Names   Verbs
selfsubjectreviews.authentication.k8s.io        []                  []               [create]
tokenreviews.authentication.k8s.io              []                  []               [create]
selfsubjectaccessreviews.authorization.k8s.io   []                  []               [create]
selfsubjectrulesreviews.authorization.k8s.io    []                  []               [create]
                                                [/api/*]            []               [get]
                                                [/healthz]          []               [get]
                                                [/version]          []               [get]
"""
CAN_I_PLAIN = "\n".join(CAN_I_GATEWAY.splitlines()[:2] + CAN_I_GATEWAY.splitlines()[3:]) + "\n"


def _cluster(policies, can_i=None, extra_pods=(), extra_accounts=()):
    def ns(name):
        return {"metadata": {"name": name, "labels": {"kubernetes.io/metadata.name": name}}}

    def deploy(name, namespace, sa):
        return {"kind": "Deployment", "metadata": {"name": name, "namespace": namespace},
                "spec": {"template": {"metadata": {"labels": {"app.kubernetes.io/name": name}},
                                      "spec": {"serviceAccountName": sa}}}}

    cron = {"kind": "CronJob", "metadata": {"name": "nightly", "namespace": "ah-core"},
            "spec": {"jobTemplate": {"spec": {"template": {
                "metadata": {"labels": {"app.kubernetes.io/name": "register-sync"}},
                "spec": {"serviceAccountName": "register-sync"}}}}}}
    data = {
        ("get", "namespaces"): {"items": [ns("ah-gateway"), ns("ah-tools"), ns("ah-core"),
                                          ns("kube-system")]},
        ("get", "pods"): {"items": [{"kind": "Pod", "metadata": {
            "name": "x", "namespace": "kube-system", "labels": {"app.kubernetes.io/name": "coredns"}},
            "spec": {}}]},
        ("get", "deployments,statefulsets,daemonsets,jobs,cronjobs"): {"items": [
            deploy("tool-gateway", "ah-gateway", "tool-gateway"),
            deploy("tool-lookup-account", "ah-tools", "tool-lookup-account"), cron]},
        ("get", "networkpolicies"): {"items": policies},
        ("get", "ciliumnetworkpolicies"): {"items": []},
        ("get", "configmaps"): {"items": []},
        ("get", "serviceaccounts"): {"items": [
            {"metadata": {"name": sa, "namespace": namespace}}
            for namespace, sa in (("ah-gateway", "default"), ("ah-tools", "default"),
                                  ("ah-core", "default"), ("kube-system", "default"),
                                  ("ah-gateway", "tool-gateway"), ("ah-tools", "tool-lookup-account"),
                                  ("ah-core", "register-sync"), *extra_accounts)]},
    }
    data[("get", "pods")]["items"].extend(extra_pods)
    can_i = can_i or {}
    calls = []

    def run(args):
        calls.append(list(args))
        if args[1:2] == ["api-resources"]:
            return "tokenreviews.authentication.k8s.io\nclustertrustbundles.certificates.k8s.io\n"
        if args[1:4] == ["auth", "can-i", "--list"]:
            sa = args[4].rsplit(":", 1)[1]
            own_namespace = args[4].split(":")[-2]
            return can_i.get(sa, CAN_I_PLAIN) if args[-1] == own_namespace else CAN_I_PLAIN
        return json.dumps(data[tuple(args[1:3])])

    return run, calls


DEFAULT_DENY = [_np("default-deny", n, {}, ["Ingress", "Egress"]) for n in ("ah-gateway", "ah-tools", "ah-core")]
GATEWAY_TO_TOOL = [
    _np("e1-out", "ah-gateway", _sel("tool-gateway"), ["Egress"],
        egress=[{"to": [_peer("ah-tools", "tool-lookup-account")]}]),
    _np("e1-in", "ah-tools", _sel("tool-lookup-account"), ["Ingress"],
        ingress=[{"from": [_peer("ah-gateway", "tool-gateway")]}]),
]


def test_networkpolicy_edges_need_both_halves():
    run, _ = _cluster(DEFAULT_DENY + GATEWAY_TO_TOOL)
    result = collect_k8s.collect(run)
    assert [ln for ln in result.lines if "->" in ln] == ["k8s tool-gateway -> tool-lookup-account"]
    assert result.scope["components"] == {"tool-gateway", "tool-lookup-account", "register-sync"}
    # Only the egress half: no edge.
    run, _ = _cluster(DEFAULT_DENY + GATEWAY_TO_TOOL[:1])
    assert not [ln for ln in collect_k8s.collect(run).lines if "->" in ln]


def test_no_policy_means_every_pod_reaches_every_pod():
    run, _ = _cluster([])
    edges = [ln for ln in collect_k8s.collect(run).lines if "->" in ln]
    assert len(edges) == 6  # three components, both directions


def test_extra_k8s_edge_and_rbac_fail(expected_doc):
    doc = copy.deepcopy(expected_doc)
    doc["edges"].append("tool-gateway -> tool-lookup-account")
    doc["k8s"] = ["k8s serviceaccount tool-gateway: create tokenreviews.authentication.k8s.io"]
    run, calls = _cluster(DEFAULT_DENY + GATEWAY_TO_TOOL, {"tool-gateway": CAN_I_GATEWAY})
    assert diff.compare("k8s", doc, collect_k8s.collect(run)).equal
    extra_policy = _np("leak", "ah-core", {}, ["Egress"], egress=[{}])
    open_tools = _np("open", "ah-tools", {}, ["Ingress"], ingress=[{}])
    run, _ = _cluster(DEFAULT_DENY + GATEWAY_TO_TOOL + [extra_policy, open_tools],
                      {"tool-gateway": CAN_I_GATEWAY, "register-sync": CAN_I_GATEWAY})
    d = diff.compare("k8s", doc, collect_k8s.collect(run))
    assert d.extra == ["k8s register-sync -> tool-lookup-account",
                       "k8s serviceaccount register-sync: create tokenreviews.authentication.k8s.io"]
    # The service account is impersonated with its groups, in its own namespace.
    assert ["kubectl", "auth", "can-i", "--list", "--as=system:serviceaccount:ah-gateway:tool-gateway",
            "--as-group=system:serviceaccounts", "--as-group=system:serviceaccounts:ah-gateway",
            "--as-group=system:authenticated", "-n", "ah-gateway"] in calls


CAN_I_SECRETS = CAN_I_PLAIN + (
    "secrets                                         []                  []               [get]\n")


def test_service_account_without_a_running_pod_is_still_assessed(expected_doc):
    """The agent's account is used only by the Jobs the dispatcher starts per ticket: at
    collection time there may be no pod and no template, but its rights still count."""
    run, calls = _cluster(DEFAULT_DENY, {"agent": CAN_I_SECRETS},
                          extra_accounts=[("ah-agent", "agent")])
    d = diff.compare("k8s", expected_doc, collect_k8s.collect(run))
    assert d.extra == ["k8s serviceaccount agent: get secrets in ah-agent"]
    assert any(c[4:5] == ["--as=system:serviceaccount:ah-agent:agent"] for c in calls)


def test_declared_rbac_of_a_service_account_missing_from_the_cluster_fails(expected_doc):
    doc = copy.deepcopy(expected_doc)
    doc["edges"] = []  # only the account is under test: the three-component cluster has no real edges
    doc["k8s"] = ["k8s serviceaccount dispatcher: create jobs.batch"]
    run, _ = _cluster(DEFAULT_DENY)
    d = diff.compare("k8s", doc, collect_k8s.collect(run))
    assert d.missing == ["k8s serviceaccount dispatcher: create jobs.batch"]


def test_unlabelled_pod_in_an_assessed_namespace_is_a_line_not_skipped(expected_doc):
    stray = {"kind": "Pod", "metadata": {"name": "debug", "namespace": "ah-core", "labels": {}},
             "spec": {"serviceAccountName": "default"}}
    run, _ = _cluster(DEFAULT_DENY, extra_pods=[stray])
    d = diff.compare("k8s", expected_doc, collect_k8s.collect(run))
    assert d.extra == ["k8s unlabelled Pod ah-core/debug"]


def test_can_i_table_drops_only_the_default_discovery_rules():
    table = CAN_I_GATEWAY + (
        "secrets                                         []                  [db-pw]          [get list]\n"
        "                                                [/metrics]          []               [get]\n")
    assert collect_k8s.parse_can_i(table) == [
        "create tokenreviews.authentication.k8s.io", "get /metrics", "get secrets/db-pw",
        "list secrets/db-pw"]
    with pytest.raises(CollectorError):
        collect_k8s.parse_can_i("error: something\n")


# --- Azure -----------------------------------------------------------------------------------

def test_azure_is_skipped_with_a_message_when_not_logged_in():
    def run(args):
        raise CollectorError("az account show failed: Please run 'az login' to setup account.")

    result = collect_azure.collect(run)
    assert result.skipped and "not logged in" in result.skipped and "never logs in" in result.skipped

    def missing(args):
        raise CommandMissing("az is not installed")

    assert "not installed" in collect_azure.collect(missing).skipped


def test_azure_role_assignments_of_workload_identities(expected_doc):
    kv = "/subscriptions/s/resourceGroups/rg-base/providers/Microsoft.KeyVault/vaults/kv-exec-1a2b"
    replies = {
        ("account", "show"): {"id": "s"},
        ("identity", "list"): [{"name": "id-executor", "principalId": "p1"},
                               {"name": "id-console", "principalId": "p2"}],
        ("resource", "list"): [{"id": kv, "name": "kv-exec-1a2b", "tags": {"workload": "kv-executor"}}],
        ("role", "assignment"): [
            {"principalId": "p1", "roleDefinitionName": "Key Vault Secrets User", "scope": kv},
            {"principalId": "p2", "roleDefinitionName": "Contributor",
             "scope": "/subscriptions/s/resourceGroups/rg-lab"},
            {"principalId": "someone", "roleDefinitionName": "Owner", "scope": "/subscriptions/s"}],
    }
    result = collect_azure.collect(lambda args: json.dumps(replies[tuple(args[1:3])]))
    d = diff.compare("azure", expected_doc, result)
    assert d.extra == ["azure identity id-console: Contributor on resource group rg-lab"]
    assert d.missing == ["azure identity id-console: Key Vault Secrets User on kv-console"]


# --- report ----------------------------------------------------------------------------------

def test_report_lists_blast_radius_per_component(expected_doc):
    md = report.render_expected(expected_doc, "security/expected-permissions.json")
    for component in ("tool-read-ticket", "tool-set-temp-protection", "executor", "console", "db"):
        assert f"### {component}" in md
    section = md.split("### tool-set-temp-protection")[1].split("\n### ")[0]
    assert "api_set_temp_protection(text), runs as api_owner" in section
    assert "Through functions owned by api_owner" in section
    assert "reads flags" in section and "writes INSERT flags" in section
    assert "| Connects to | db |" in section
    assert "| Accepts connections from | tool-gateway |" in section
    lookup = md.split("### tool-lookup-account")[1].split("\n### ")[0]
    assert "customers (id, name)" in lookup and "phone" not in lookup
    assert "Key Vault Secrets User on kv-tool-lookup-account" in lookup
    assert "Generated file, do not edit" in md
    assert "python -m secops.permassess.report --expected security/expected-permissions.json" in md
    assert "```mermaid" in md


def _section(md: str, component: str) -> str:
    return md.split(f"### {component}\n")[1].split("\n### ")[0]


def _row(section: str, name: str) -> str:
    return next(line for line in section.splitlines() if line.startswith(f"| {name} |"))


def _render_with(expected_doc, *lines) -> str:
    doc = copy.deepcopy(expected_doc)
    doc["pg"] = sorted(doc["pg"] + list(lines))
    return report.render_expected(doc, "security/expected-permissions.json")


def test_report_follows_public_execute_into_security_definer_functions(expected_doc):
    md = _render_with(expected_doc, *(
        f"pg role {r}: EXECUTE ON FUNCTION public.api_set_temp_protection(text) (via PUBLIC)"
        for r in ("tool_read_ticket", "executor")))
    section = _section(md, "tool-read-ticket")
    assert "api_set_temp_protection(text) (via PUBLIC), runs as api_owner" in _row(section, "Executes")
    assert "writes INSERT flags" in _row(section, "Through functions owned by api_owner")


def test_report_counts_inherited_privileges(expected_doc):
    md = _render_with(expected_doc, "pg role tool_read_ticket: MEMBER OF executor",
                      "pg role executor: MEMBER OF pg_read_all_data",
                      "pg role tool_lookup_account: MEMBER OF executor WITH INHERIT FALSE")
    section = _section(md, "tool-read-ticket")
    assert "flags" in _row(section, "Reads") and "INSERT credits" in _row(section, "Writes")
    assert "every table, view and sequence (pg_read_all_data)" in _row(section, "Reads")
    assert "inherits from executor, pg_read_all_data" in _row(section, "Member of")
    # WITH INHERIT FALSE: only SET ROLE reaches executor's rights, so they are not counted.
    assert "flags" not in _row(_section(md, "tool-lookup-account"), "Reads")


def test_report_counts_owned_tables_as_read_and_written(expected_doc):
    md = _render_with(expected_doc, "pg role tool_read_ticket: OWNS TABLE public.customers")
    section = _section(md, "tool-read-ticket")
    assert "customers" in _row(section, "Reads")
    assert "customers (owner: every privilege)" in _row(section, "Writes")
    summary = next(ln for ln in md.splitlines() if ln.startswith("| tool-read-ticket |"))
    assert "customers" in summary


def test_report_definer_function_owned_by_a_superuser_reaches_everything(expected_doc):
    md = _render_with(expected_doc,
                      "pg role postgres: OWNS FUNCTION public.as_superuser() SECURITY DEFINER",
                      "pg role tool_read_ticket: EXECUTE ON FUNCTION public.as_superuser()")
    section = _section(md, "tool-read-ticket")
    assert _row(section, "Through functions owned by postgres") == \
        "| Through functions owned by postgres | everything (superuser) |"


def test_permission_matrix_doc_is_up_to_date():
    assert report.main(["--expected", "security/expected-permissions.json",
                        "--out", str(MATRIX_DOC), "--check"]) == 0


# --- command line ----------------------------------------------------------------------------

@pytest.fixture
def db_env(settings) -> dict[str, str]:
    return {"DB_HOST": settings.db_host, "DB_PORT": str(settings.db_port),
            "DB_NAME": settings.db_name, "POSTGRES_PASSWORD": os.environ["POSTGRES_PASSWORD"]}


def _run_cli(tmp_path, env, *extra, expected_file=EXPECTED_FILE, **kw) -> tuple[int, dict]:
    out = tmp_path / "out"
    code = cli.main(["--planes", "pg,compose", "--compose-json", str(COMPOSE_JSON),
                     "--expected", str(expected_file), "--out", str(out), *extra], env=env, **kw)
    result = json.loads((out / "diff.json").read_text(encoding="utf-8")) if (out / "diff.json").exists() else {}
    return code, result


def test_cli_exits_0_when_every_plane_matches(tmp_path, db_env):
    code, result = _run_cli(tmp_path, db_env)
    assert code == 0, (tmp_path / "out" / "summary.txt").read_text(encoding="utf-8")
    assert result["planes"]["pg"]["extra"] == [] and result["exit_code"] == 0
    for name in ("actual.json", "summary.txt", "matrix.md"):
        assert (tmp_path / "out" / name).exists()


def test_cli_exits_1_on_an_extra_or_missing_line(tmp_path, db_env):
    doc = json.loads(EXPECTED_FILE.read_text(encoding="utf-8"))
    doc["pg"].remove("pg role approver: SELECT ON public.action_requests")
    doc["pg"].append("pg role approver: SELECT ON public.flags")
    tampered = tmp_path / "expected.json"
    tampered.write_text(json.dumps(doc), encoding="utf-8")
    code, result = _run_cli(tmp_path, db_env, "--no-source-check", expected_file=tampered)
    assert code == 1
    assert result["planes"]["pg"]["extra"] == ["pg role approver: SELECT ON public.action_requests"]
    assert result["planes"]["pg"]["missing"] == ["pg role approver: SELECT ON public.flags"]
    # Without --no-source-check a hand-edited expected file is refused outright.
    code, _ = _run_cli(tmp_path, db_env, expected_file=tampered)
    assert code == 2


def test_cli_exits_2_when_a_plane_cannot_be_read(tmp_path, db_env):
    def unreachable(env):
        raise CollectorError("cannot connect to PostgreSQL: connection refused")

    code, result = _run_cli(tmp_path, db_env, connect=unreachable)
    assert code == 2 and "pg" in result["errors"]
    code, _ = _run_cli(tmp_path, db_env, "--planes", "pg,nosuchplane")
    assert code == 2


def test_cli_skips_azure_when_not_logged_in_and_still_passes(tmp_path, db_env, capsys):
    def run(args):
        raise CollectorError("az account show failed: Please run 'az login'")

    out = tmp_path / "out"
    code = cli.main(["--planes", "compose,azure", "--compose-json", str(COMPOSE_JSON),
                     "--out", str(out)], env=db_env, run=run)
    assert code == 0
    assert "azure: skipped" in capsys.readouterr().out


def test_cli_exits_2_when_every_plane_is_skipped(tmp_path, db_env, capsys):
    """Nothing assessed is not "equal"."""
    def run(args):
        raise CollectorError("az account show failed: Please run 'az login'")

    out = tmp_path / "out"
    code = cli.main(["--planes", "azure", "--out", str(out)], env=db_env, run=run)
    assert code == 2
    assert "nothing was assessed" in capsys.readouterr().out
    assert json.loads((out / "diff.json").read_text(encoding="utf-8"))["exit_code"] == 2


class _BrokenCursor:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql):
        raise psycopg.OperationalError("server closed the connection unexpectedly\nmore detail")


class _BrokenConnection:
    def cursor(self, row_factory=None):
        return _BrokenCursor()

    def close(self):
        pass


@pytest.mark.parametrize("connect, what", [
    (lambda env: _BrokenConnection(), "OperationalError: server closed the connection unexpectedly"),
    (cli._connect_pg, "ValueError: invalid literal for int()"),
])
def test_cli_exits_2_with_reports_when_a_collector_raises_anything(tmp_path, db_env, connect, what):
    env = {**db_env, "DB_PORT": "not-a-port"}
    code, result = _run_cli(tmp_path, env, connect=connect)
    assert code == 2
    assert result["errors"]["pg"].startswith(what)
    assert "more detail" not in result["errors"]["pg"], "first line of the message only"
    assert result["planes"]["compose"]["extra"] == [], "the other plane is still assessed"
    for name in ("actual.json", "diff.json", "summary.txt", "matrix.md"):
        assert (tmp_path / "out" / name).exists(), name


def test_cli_exits_2_on_a_malformed_tool_calls_log(tmp_path, db_env):
    calls = tmp_path / "tool_calls.json"
    calls.write_text("[1, 2]", encoding="utf-8")
    code, result = _run_cli(tmp_path, db_env, "--tool-calls", str(calls))
    assert code == 2 and "AttributeError" in result["errors"]["tool_calls"]


def test_unused_grant_warns_but_does_not_fail(tmp_path, db_env):
    calls = tmp_path / "tool_calls.json"
    calls.write_text("\n".join(json.dumps({"tool": t, "outcome": "ok"}) for t in
                               ("read_ticket", "lookup_account", "issue_bill_credit",
                                "request_disconnection")), encoding="utf-8")
    code, result = _run_cli(tmp_path, db_env, "--tool-calls", str(calls))
    assert code == 0
    assert result["warnings"] == [
        "warning: tool-set-temp-protection is granted tool set_temp_protection (holds EXECUTE ON "
        "FUNCTION public.api_set_temp_protection(text)), but no call in the tool_calls log used it"]
