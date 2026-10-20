"""The Helm chart (deploy/helm/assume-hijacked) renders every wall the same way on kind and AKS.

These tests need the helm binary only, not the cluster: they run `helm lint` and `helm template`
and read the output. So they carry no `k8s` marker and run in the default `pytest`; on a machine
without helm they are skipped, with the reason shown (-rs).
"""

import json
import re
import shutil
import subprocess
import tempfile
from functools import cache
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "deploy" / "helm" / "assume-hijacked"
HELM = shutil.which("helm")

pytestmark = pytest.mark.skipif(HELM is None, reason="helm is not installed")

ENVS = ["kind", "azure"]
DIGEST = re.compile(r"^[a-z0-9][a-z0-9._/:-]*@sha256:[a-f0-9]{64}$")
SANDBOX_RUNTIME = "kata-vm-isolation"
APP_UID = 10001
AGENT_AUDIENCES = ["tool-gateway", "llm-gateway", "dispatcher"]
TOOLS = ["read_ticket", "lookup_account", "request_disconnection", "issue_bill_credit",
         "set_temp_protection"]
TOOL_COMPONENTS = {f"tool-{t.replace('_', '-')}" for t in TOOLS}

# One namespace per trust zone, and the DB role of each component ("" = none).
COMPONENTS = {
    **{f"tool-{t.replace('_', '-')}": ("ah-tools", f"tool_{t}") for t in TOOLS},
    "tool-gateway": ("ah-gateway", "gateway"),
    "risk-engine": ("ah-core", "risk_engine"),
    "dispatcher": ("ah-intake", "dispatcher"),
    "llm-gateway": ("ah-agent", ""),
    "executor": ("ah-core", "executor"),
    "console": ("ah-staff", "approver"),
}
# The demo UI (templates/demo.yaml) runs where demo.enabled is true: kind. It logs in as two roles.
DEMO_ROLES = ("demo_portal", "demo_ops")
# Every role has a password in the kind Secret, as the roles exist in every database.
DB_ROLES = sorted({role for _, role in COMPONENTS.values() if role} | set(DEMO_ROLES))
# Components that call the Kubernetes API: TokenReview of their callers' tokens (the three the
# agent calls); the dispatcher also creates Jobs.
API_CALLERS = {"tool-gateway", "llm-gateway", "dispatcher"}
NAMESPACES = {"ah-intake", "ah-agent", "ah-gateway", "ah-tools", "ah-core", "ah-staff",
              "ah-data", "ah-demo"}
PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\ntest-only\n-----END PUBLIC KEY-----\n"


def db_files() -> dict:
    """What the deploy script passes with --set-file: db/init/init.sh and every db/sql file."""
    return {
        "initSh": (ROOT / "db" / "init" / "init.sh").read_text(encoding="utf-8"),
        "sql": {p.stem: p.read_text(encoding="utf-8") for p in sorted((ROOT / "db" / "sql").glob("*.sql"))},
    }


def install_values(env: str) -> dict:
    """The per-install values a deploy adds on top of values-<env>.yaml (test stand-ins)."""
    values = {"gateway": {"publicKeyPem": PUBLIC_KEY}, "dbFiles": db_files()}
    if env == "kind":
        values["secrets"] = {
            "postgresPassword": "test-postgres",
            "dbPasswords": {role: f"test-{role}" for role in DB_ROLES},
            "gatewaySigningKeyPem": "-----BEGIN EC PRIVATE KEY-----\ntest-only\n-----END EC PRIVATE KEY-----\n",
        }
    else:
        vault_users = [name for name, (_, role) in COMPONENTS.items() if role] + ["db-migrate"]
        values["db"] = {"host": "psql-ah.privatelink.postgres.database.azure.com"}
        values["console"] = {"redirectUri": "https://console.example/auth/callback",
                             "entra": {"tenantId": "t-1", "clientId": "c-console-app"}}
        values["azure"] = {
            "tenantId": "t-1",
            "dbAdmin": "id-db-migrate",
            "clientIds": {name: f"client-{name}" for name in vault_users + ["llm-gateway"]},
            "keyVaults": {name: f"kv-{name[:10]}-abc123" for name in vault_users + ["llm-gateway"]},
        }
    return values


@cache
def install_values_file(env: str) -> str:
    path = Path(tempfile.mkdtemp(prefix="ah-chart-")) / f"install-values-{env}.json"
    # JSON is valid YAML, so helm reads it as a values file.
    path.write_text(json.dumps(install_values(env)), encoding="utf-8")
    return str(path)


def helm(command: str, env: str, *extra: str, install: bool = True) -> subprocess.CompletedProcess:
    args = [HELM, command]
    if command == "template":
        args.append("ah")
    args += [str(CHART), "-f", str(CHART / f"values-{env}.yaml")]
    if install:
        args += ["-f", install_values_file(env)]
    return subprocess.run([*args, *extra], capture_output=True, text=True, encoding="utf-8",
                          timeout=120, check=False)


@cache
def rendered(env: str, *sets: str) -> tuple:
    result = helm("template", env, *[a for s in sets for a in ("--set", s)])
    assert result.returncode == 0, result.stderr
    return tuple(doc for doc in yaml.safe_load_all(result.stdout) if doc)


def objects(env: str, kind: str) -> list[dict]:
    return [o for o in rendered(env) if o["kind"] == kind]


def find(env: str, kind: str, name: str) -> dict:
    matches = [o for o in objects(env, kind) if o["metadata"]["name"] == name]
    assert len(matches) == 1, f"{kind}/{name}: {len(matches)} rendered"
    return matches[0]


def agent_job(env: str) -> dict:
    """The agent Job template the dispatcher uses (JSON in a ConfigMap; no Job is rendered)."""
    return json.loads(find(env, "ConfigMap", "agent-job-template")["data"]["job.json"])


def pod_specs(env: str) -> list[tuple[str, dict]]:
    """(name, pod spec) of every workload, including the agent Job template."""
    specs = [(o["metadata"]["name"], o["spec"]["template"]["spec"])
             for o in rendered(env) if o["kind"] in ("Deployment", "StatefulSet", "Job")]
    return [*specs, ("agent", agent_job(env)["spec"]["template"]["spec"])]


def containers(spec: dict) -> list[dict]:
    return spec.get("initContainers", []) + spec["containers"]


# --- lint and render ----------------------------------------------------------------------------

@pytest.mark.parametrize("env", ENVS)
def test_helm_lint(env):
    result = helm("lint", env, "--strict")
    assert result.returncode == 0, result.stdout + result.stderr


# --- rendered walls -----------------------------------------------------------------------------

@pytest.mark.parametrize("env", ENVS)
def test_asi04_all_images_pinned_by_digest(env):
    images = [(name, c["image"]) for name, spec in pod_specs(env) for c in containers(spec)]
    assert len(images) >= len(COMPONENTS) + 2
    for name, image in images:
        assert DIGEST.match(image), f"{name}: {image}"


@pytest.mark.parametrize("env", ENVS)
def test_agent_and_tools_use_sandbox_runtime(env):
    runtime = {name: spec.get("runtimeClassName") for name, spec in pod_specs(env)}
    sandboxed = {name for name, rc in runtime.items() if rc}
    assert sandboxed == TOOL_COMPONENTS | {"agent"}
    assert {runtime[name] for name in sandboxed} == {SANDBOX_RUNTIME}


@pytest.mark.parametrize("env", ENVS)
def test_agent_job_template_is_the_fixed_one(env):
    job = agent_job(env)
    assert job["kind"] == "Job"
    assert job["metadata"]["namespace"] == "ah-agent"
    assert set(job["metadata"]["labels"]) == {"app.kubernetes.io/name", "ah/ticket"}
    assert job["metadata"]["labels"]["app.kubernetes.io/name"] == "agent"
    assert {k: job["spec"][k] for k in ("backoffLimit", "activeDeadlineSeconds", "ttlSecondsAfterFinished")} \
        == {"backoffLimit": 0, "activeDeadlineSeconds": 300, "ttlSecondsAfterFinished": 600}
    spec = job["spec"]["template"]["spec"]
    assert spec["serviceAccountName"] == "agent"
    assert spec["automountServiceAccountToken"] is False
    assert spec["runtimeClassName"] == SANDBOX_RUNTIME
    assert spec["restartPolicy"] == "Never"
    [container] = spec["containers"]
    assert container["name"] == "agent"
    assert DIGEST.match(container["image"])
    assert container["command"] == ["python", "-m", "app.agent.main"]
    assert "envFrom" not in container
    assert all("valueFrom" not in e for e in container.get("env", []))
    [volume] = spec["volumes"]
    tokens = [s["serviceAccountToken"] for s in volume["projected"]["sources"]]
    assert tokens == [{"audience": a, "expirationSeconds": 600, "path": f"{a}/token"} for a in AGENT_AUDIENCES]
    [mount] = container["volumeMounts"]
    assert mount == {"name": volume["name"], "mountPath": "/var/run/secrets/ah", "readOnly": True}
    assert_restricted(spec, container, APP_UID)


@pytest.mark.parametrize("env", ENVS)
def test_the_chart_never_starts_an_agent(env):
    for obj in rendered(env):
        if obj["kind"] in ("Job", "Deployment", "Pod", "CronJob"):
            assert obj["metadata"]["namespace"] != "ah-agent" or obj["metadata"]["name"] == "llm-gateway"
            assert obj["metadata"]["name"] != "agent"


@pytest.mark.parametrize("env", ENVS)
def test_dispatcher_may_only_create_jobs_in_agent_namespace(env):
    roles = objects(env, "Role")
    assert [(r["metadata"]["namespace"], r["metadata"]["name"]) for r in roles] == \
        [("ah-agent", "dispatcher-create-agent-jobs")]
    assert roles[0]["rules"] == [{"apiGroups": ["batch"], "resources": ["jobs"], "verbs": ["create"]}]
    [binding] = objects(env, "RoleBinding")
    assert binding["metadata"]["namespace"] == "ah-agent"
    assert binding["subjects"] == [{"kind": "ServiceAccount", "name": "dispatcher", "namespace": "ah-intake"}]
    # The only cluster-wide right: TokenReview, for the three services the agent calls.
    [cluster_role] = objects(env, "ClusterRole")
    assert cluster_role["rules"] == [{"apiGroups": ["authentication.k8s.io"], "resources": ["tokenreviews"],
                                      "verbs": ["create"]}]
    [cluster_binding] = objects(env, "ClusterRoleBinding")
    assert {s["name"] for s in cluster_binding["subjects"]} == API_CALLERS


def assert_restricted(spec: dict, container: dict, uid: int) -> None:
    pod = spec["securityContext"]
    assert pod["runAsNonRoot"] is True
    assert pod["runAsUser"] == uid
    assert pod["seccompProfile"] == {"type": "RuntimeDefault"}
    sc = container["securityContext"]
    assert sc["runAsNonRoot"] is True
    assert sc["runAsUser"] == uid
    assert sc["allowPrivilegeEscalation"] is False
    assert sc["readOnlyRootFilesystem"] is True
    assert sc["capabilities"] == {"drop": ["ALL"]}
    assert sc["seccompProfile"] == {"type": "RuntimeDefault"}


@pytest.mark.parametrize("env", ENVS)
def test_every_container_is_restricted_and_non_root(env):
    for name, spec in pod_specs(env):
        # Only the database server runs as its image's own user (postgres, UID 70).
        uid = 70 if name == "postgres" else APP_UID
        for container in containers(spec):
            assert_restricted(spec, container, uid)
        # Host namespaces of the workloads are checked by Trivy in the lint job (KSV-0008, 0009,
        # 0010); the agent Job template is JSON inside a ConfigMap, which Trivy does not read.
        # hostPath is not left to Trivy: its HIGH rule (KSV-0121) knows only a list of paths.
        assert all("hostPath" not in v for v in spec.get("volumes", []))
        if name == "agent":
            assert not spec.get("hostNetwork") and not spec.get("hostPID") and not spec.get("hostIPC")


@pytest.mark.parametrize("env", ENVS)
def test_each_component_gets_only_its_own_db_password(env):
    for d in objects(env, "Deployment"):
        name = d["metadata"]["name"]
        roles = list(DEMO_ROLES) if name == "demo" else [COMPONENTS[name][1]] if COMPONENTS[name][1] else []
        [container] = d["spec"]["template"]["spec"]["containers"]
        assert "envFrom" not in container
        from_secrets = [e for e in container["env"] if "valueFrom" in e]
        expected = [f"DB_PASSWORD_{role.upper()}" for role in roles]
        assert [e["name"] for e in from_secrets] == expected, name
        for e in from_secrets:
            assert e["valueFrom"]["secretKeyRef"]["name"] == f"{name}-secrets"


# --- network walls -------------------------------------------------------------------------
# The communication matrix (final architecture, section 4), rows that run inside the cluster:
# (caller namespace, caller pods, callee namespace or DB, callee pods, ports). DB is Postgres in
# ah-data on kind and the private endpoint subnet on Azure.
DB = "db"
AZURE_DB_CIDR = "10.20.2.0/26"
TOOL_PODS = tuple(sorted(TOOL_COMPONENTS))
MATRIX = {
    ("ah-intake", ("dispatcher",), DB, (), (5432,)),                                   # 4
    ("ah-agent", ("agent",), "ah-gateway", ("tool-gateway",), (8080,)),                # 5
    ("ah-agent", ("agent",), "ah-agent", ("llm-gateway",), (8083,)),                   # 6
    ("ah-agent", ("agent",), "ah-intake", ("dispatcher",), (8081,)),                   # 7
    ("ah-gateway", ("tool-gateway",), "ah-core", ("risk-engine",), (8082,)),           # 8
    ("ah-gateway", ("tool-gateway",), "ah-tools", TOOL_PODS, (8000,)),                 # 9
    ("ah-gateway", ("tool-gateway",), DB, (), (5432,)),                                # 11
    ("ah-tools", TOOL_PODS, DB, (), (5432,)),                                          # 12
    ("ah-core", ("risk-engine",), DB, (), (5432,)),                                    # 13
    ("ah-core", ("executor",), DB, (), (5432,)),                                       # 14
    ("ah-staff", ("console",), DB, (), (5432,)),                                       # 18
}
DB_SETUP = {"kind": ("ah-data", ("postgres-init",)), "azure": ("ah-core", ("db-migrate",))}
OPS_NAMESPACES = {"ah-intake", "ah-agent", "ah-gateway", "ah-tools", "ah-core", "ah-staff"}
ENTRA = "login.microsoftonline.com"
POLICIES = {"ah-images-pinned", "ah-no-host-access", "ah-sandbox-runtime", "ah-agent-job-template"}


def chart_namespaces(env: str) -> set[str]:
    return NAMESPACES if env == "kind" else NAMESPACES - {"ah-data", "ah-demo"}


def name_values(selector: dict) -> tuple:
    """app.kubernetes.io/name values a pod selector picks; () for every pod."""
    if not selector:
        return ()
    [expr] = selector["matchExpressions"]
    assert expr["key"] == "app.kubernetes.io/name" and expr["operator"] == "In"
    return tuple(sorted(expr["values"]))


def expected_edges(env: str) -> set:
    edges = set(MATRIX) | {(*DB_SETUP[env], DB, (), (5432,))}
    if env == "kind":  # the demo UI: one edge, to the database
        edges.add(("ah-demo", ("demo",), DB, (), (5432,)))
    target = {"kind": ("ah-data", ("postgres",)), "azure": (AZURE_DB_CIDR, ())}[env]
    return {(a, b, *(target if c == DB else (c, d)), e) for a, b, c, d, e in edges}


def network_policies(env: str, *sets: str) -> list[dict]:
    return [o for o in rendered(env, *sets) if o["kind"] == "NetworkPolicy"]


def cilium_policies(env: str, *sets: str) -> list[dict]:
    return [o for o in rendered(env, *sets) if o["kind"] == "CiliumNetworkPolicy"]


@pytest.mark.parametrize("env", ENVS)
def test_asi03_every_namespace_renders_default_deny(env):
    deny = {p["metadata"]["namespace"]: p["spec"] for p in network_policies(env)
            if p["metadata"]["name"] == "default-deny"}
    assert set(deny) == chart_namespaces(env)
    for spec in deny.values():
        assert spec == {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}


@pytest.mark.parametrize("env", ENVS)
def test_network_edges_are_exactly_the_matrix(env):
    """Every egress half is a matrix edge, every matrix edge has both halves, nothing else."""
    egress, ingress = set(), set()
    for p in network_policies(env):
        name, ns, spec = p["metadata"]["name"], p["metadata"]["namespace"], p["spec"]
        if name == "default-deny":
            continue
        pods = name_values(spec["podSelector"])
        if name.endswith("-out"):
            assert spec["policyTypes"] == ["Egress"] and "ingress" not in spec, name
            [rule] = spec["egress"]
            [peer] = rule["to"]
            assert all(x["protocol"] == "TCP" for x in rule["ports"]), name
            ports = tuple(sorted(x["port"] for x in rule["ports"]))
            if "ipBlock" in peer:
                assert env == "azure" and peer == {"ipBlock": {"cidr": AZURE_DB_CIDR}}, name
                egress.add((ns, pods, AZURE_DB_CIDR, (), ports))
            else:
                callee_ns = peer["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"]
                egress.add((ns, pods, callee_ns, name_values(peer.get("podSelector", {})), ports))
        else:
            assert name.endswith("-in"), name
            assert spec["policyTypes"] == ["Ingress"] and "egress" not in spec, name
            [rule] = spec["ingress"]
            [peer] = rule["from"]
            caller_ns = peer["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"]
            ports = tuple(sorted(x["port"] for x in rule["ports"]))
            ingress.add((caller_ns, name_values(peer.get("podSelector", {})), ns, pods, ports))
    expected = expected_edges(env)
    assert egress == expected
    # Ingress halves: the same edges where the callee is in the cluster, plus Prometheus
    # (ah-monitoring, its own chart) to the ops port of every namespace with ops endpoints.
    metrics = {("ah-monitoring", (), ns, (), (9000,)) for ns in OPS_NAMESPACES | ({"ah-demo"} if env == "kind" else set())}
    assert ingress == {e for e in expected if e[2] != AZURE_DB_CIDR} | metrics


@pytest.mark.parametrize("env", ENVS)
def test_no_networkpolicy_allows_dns_or_open_egress(env):
    """DNS goes only through Cilium's DNS rule: an L4 allow on port 53 would switch it off."""
    for p in network_policies(env):
        for rule in p["spec"].get("egress", []):
            assert rule.get("to"), p["metadata"]["name"]
            assert rule.get("ports"), p["metadata"]["name"]
            assert all(x["port"] not in (53, "53") for x in rule["ports"]), p["metadata"]["name"]


def external_names(env: str, *sets: str) -> dict:
    """component -> (names it may resolve besides cluster.local, names it may reach on 443)."""
    out = {}
    for p in cilium_policies(env, *sets):
        spec = p["spec"]
        names = [r["matchName"] for e in spec.get("egress", []) for r in e.get("toFQDNs", [])]
        if not names:
            continue
        component = spec["endpointSelector"]["matchLabels"]["app.kubernetes.io/name"]
        [dns_rule, fqdn_rule] = spec["egress"]
        resolvable = [r["matchName"] for r in dns_rule["toPorts"][0]["rules"]["dns"]]
        assert fqdn_rule["toPorts"] == [{"ports": [{"port": "443", "protocol": "TCP"}]}]
        out[component] = (resolvable, names)
    return out


def search_names(host: str, namespace: str) -> list[str]:
    """What a pod's resolver asks for (ndots:5 search list first), all of which must be allowed."""
    return [host, f"{host}.{namespace}.svc.cluster.local", f"{host}.svc.cluster.local", f"{host}.cluster.local"]


def test_asi02_only_named_components_reach_names_outside_the_cluster():
    # kind defaults (scripted backend, dev console): nothing outside the cluster at all.
    assert external_names("kind") == {}
    assert external_names("kind", "llm.backend=anthropic", "secrets.anthropicApiKey=test-only") == {
        "llm-gateway": (search_names("api.anthropic.com", "ah-agent"), ["api.anthropic.com"])}
    # db-migrate: Entra, and the vault of every workload with a database role (it writes their
    # passwords there).
    vault_hosts = sorted({f"{install_values('azure')['azure']['keyVaults'][c]}.vault.azure.net"
                          for c, (_, role) in COMPONENTS.items() if role})
    migrate_hosts = [ENTRA, *vault_hosts]
    assert external_names("azure") == {
        "console": (search_names(ENTRA, "ah-staff"), [ENTRA]),
        "db-migrate": ([n for h in migrate_hosts for n in search_names(h, "ah-core")], migrate_hosts)}
    # No other Cilium egress to the world: no CIDR allow, no entity but the API server.
    for env in ENVS:
        for p in cilium_policies(env):
            for rule in p["spec"].get("egress", []):
                assert "toCIDR" not in rule and "toCIDRSet" not in rule, p["metadata"]["name"]
                assert set(rule.get("toEntities", [])) <= {"kube-apiserver"}, p["metadata"]["name"]


@pytest.mark.parametrize("env", ENVS)
def test_asi03_instance_metadata_denied_in_every_namespace(env):
    deny = {p["metadata"]["namespace"]: p["spec"] for p in cilium_policies(env)
            if p["metadata"]["name"] == "deny-instance-metadata"}
    assert set(deny) == chart_namespaces(env)
    for spec in deny.values():
        assert spec == {"endpointSelector": {}, "egressDeny": [{"toCIDR": ["169.254.169.254/32"]}]}


# --- admission walls -----------------------------------------------------------------------

@pytest.mark.parametrize("env", ENVS)
def test_namespaces_enforce_restricted_pod_security(env):
    namespaces = objects(env, "Namespace")
    assert {n["metadata"]["name"] for n in namespaces} == chart_namespaces(env)
    for ns in namespaces:
        labels = ns["metadata"]["labels"]
        for mode in ("enforce", "warn", "audit"):
            assert labels[f"pod-security.kubernetes.io/{mode}"] == "restricted", ns["metadata"]["name"]


def admission_policies(env: str, *sets: str) -> dict:
    return {o["metadata"]["name"]: o for o in rendered(env, *sets) if o["kind"] == "ValidatingAdmissionPolicy"}


def policy_text(env: str, name: str, *sets: str) -> str:
    """All CEL expressions of a policy, one per line."""
    spec = admission_policies(env, *sets)[name]["spec"]
    return "\n".join([v["expression"] for v in spec.get("variables", [])]
                     + [v["expression"] for v in spec["validations"]])


@pytest.mark.parametrize("env", ENVS)
def test_admission_policies_are_bound_and_deny(env):
    policies = admission_policies(env)
    assert set(policies) == POLICIES
    bindings = {o["metadata"]["name"]: o["spec"] for o in objects(env, "ValidatingAdmissionPolicyBinding")}
    assert bindings == {n: {"policyName": n, "validationActions": ["Deny"]} for n in POLICIES}
    scope = {}
    for name, p in policies.items():
        assert p["apiVersion"] == "admissionregistration.k8s.io/v1"
        assert p["spec"]["failurePolicy"] == "Fail"
        [expr] = p["spec"]["matchConstraints"]["namespaceSelector"]["matchExpressions"]
        assert expr["key"] == "kubernetes.io/metadata.name" and expr["operator"] == "In"
        scope[name] = set(expr["values"])
    assert scope == {"ah-images-pinned": chart_namespaces(env), "ah-no-host-access": chart_namespaces(env),
                     "ah-sandbox-runtime": {"ah-agent", "ah-tools"}, "ah-agent-job-template": {"ah-agent"}}


@pytest.mark.parametrize("env", ENVS)
def test_agent_job_policy_pins_the_template(env):
    """The Job policy takes image, command and env from the template the dispatcher uses."""
    registry = {"kind": "localhost:5001/", "azure": "acrplaceholder.azurecr.io/"}[env]
    app = f"{registry}assume-hijacked@sha256:" + "c" * 64
    text = policy_text(env, "ah-agent-job-template", f"images.app={app}")
    [o] = [o for o in rendered(env, f"images.app={app}")
           if o["kind"] == "ConfigMap" and o["metadata"]["name"] == "agent-job-template"]
    [container] = json.loads(o["data"]["job.json"])["spec"]["template"]["spec"]["containers"]
    assert container["image"] == app
    assert f"variables.c.image == '{app}'" in text
    assert 'variables.c.command == ["python","-m","app.agent.main"]' in text
    env_list = [f"{e['name']}={e['value']}" for e in container["env"]]
    assert "== " + json.dumps(env_list, separators=(",", ":")) in text
    assert "variables.pod.serviceAccountName == 'agent'" in text
    assert f"variables.pod.runtimeClassName == '{SANDBOX_RUNTIME}'" in text
    for audience in AGENT_AUDIENCES:
        assert f"{audience} 600 {audience}/token" in text


# --- database setup order and the Azure password rotation ----------------------------------


ROTATE = ROOT / "scripts" / "azure-rotate-db-passwords.sh"


# --- the chart against the manifests (permissions/) ----------------------------------------------

MANIFESTS = {p.stem: json.loads(p.read_text(encoding="utf-8"))
             for p in sorted((ROOT / "permissions").glob("*.json"))}
# The namespace of each component the manifests name (COMPONENTS lacks the agent and db-migrate).
MANIFEST_NAMESPACES = {**{n: ns for n, (ns, _) in COMPONENTS.items()},
                       "agent": "ah-agent", "db-migrate": "ah-core", "demo": "ah-demo"}


@pytest.mark.parametrize("env", ENVS)
def test_every_manifest_has_its_service_account_in_its_namespace(env):
    """The database has no workload of its own in the chart (a managed server on Azure, the
    postgres StatefulSet on kind), and db-migrate runs on Azure only; every other manifest names
    a ServiceAccount the chart creates in that component's namespace."""
    accounts = {(o["metadata"]["namespace"], o["metadata"]["name"]) for o in objects(env, "ServiceAccount")}
    for name, manifest in MANIFESTS.items():
        if name == "db" or (name == "db-migrate" and env == "kind") or (name == "demo" and env == "azure"):
            continue
        assert (MANIFEST_NAMESPACES[name], manifest["k8s"]["service_account"]) in accounts, (env, name)


@pytest.mark.parametrize("env", ENVS)
def test_only_the_tool_gateway_gets_the_signing_key(env):
    """The manifests give a Key Vault Secrets User role on the tool gateway's vault to the tool
    gateway alone; the chart must hand the signing key to exactly those pods, and the agent
    gets none."""
    holders = {n for n, m in MANIFESTS.items()
               if any(r["role"] == "Key Vault Secrets User" and r["scope"] == "kv-tool-gateway"
                      for r in m["azure"]["roles"])}
    assert holders == {"tool-gateway"}
    mounted = {name for name, spec in pod_specs(env)
               if any(e["name"] == "GATEWAY_SIGNING_KEY_FILE" for c in containers(spec) for e in c.get("env", []))}
    assert mounted == holders
    if env == "kind":
        with_key = {s["metadata"]["name"] for s in objects(env, "Secret") if "signing-key.pem" in s.get("stringData", {})}
        assert with_key == {f"{n}-secrets" for n in holders}
    else:
        with_key = {s["metadata"]["name"] for s in objects(env, "SecretProviderClass")
                    if "gateway-signing-key" in s["spec"]["parameters"]["objects"]}
        assert with_key == holders


def dev_staff_seeded(env: str) -> list[str]:
    """Names of the pods whose containers turn the dev staff seed on (db/init/init.sh, SEED_DEV_STAFF)."""
    return [name for name, spec in pod_specs(env)
            for c in containers(spec)
            for e in c.get("env", []) if e["name"] == "SEED_DEV_STAFF" and e.get("value") == "yes"]


def test_dev_staff_are_seeded_on_kind_and_never_on_azure():
    """The dev oids are public; on the staff list they would let anyone who can send the console a
    dev sign-in approve. Only the kind database setup Job turns the seed on."""
    assert dev_staff_seeded("kind") == ["postgres-init"]
    assert dev_staff_seeded("azure") == []
    migrate = [c for name, spec in pod_specs("azure") if name == "db-migrate" for c in containers(spec)]
    assert migrate and not any(e["name"] == "SEED_DEV_STAFF" and e.get("value") != "no"
                               for c in migrate for e in c.get("env", []))


def test_init_script_seeds_dev_staff_only_when_asked():
    # Opt-in: a manual init.sh run against Azure, or a dropped env line, must not seed the dev oids.
    script = (ROOT / "db" / "init" / "init.sh").read_text(encoding="utf-8")
    assert '[ "${SEED_DEV_STAFF:-no}" = yes ]' in script
    assert script.count("09-dev-staff.sql") == 1


# --- the demo UI (templates/demo.yaml) ------------------------------------------------------------

def values_file(name: str) -> dict:
    return yaml.safe_load((CHART / name).read_text(encoding="utf-8"))


def demo_objects(docs) -> list[dict]:
    return [o for o in docs if o["metadata"].get("namespace") == "ah-demo" or o["metadata"]["name"] in ("demo", "ah-demo")
            or o["metadata"]["name"].startswith("demo-")]


def test_the_demo_is_on_in_kind_and_off_by_default_and_in_azure():
    assert values_file("values.yaml")["demo"] == {"enabled": False}
    assert values_file("values-kind.yaml")["demo"] == {"enabled": True}
    assert values_file("values-azure.yaml")["demo"] == {"enabled": False}


@pytest.mark.parametrize("env", ENVS)
def test_without_demo_enabled_nothing_of_the_demo_is_rendered(env):
    docs = rendered(env, "demo.enabled=false")
    assert demo_objects(docs) == []
    assert chart_namespaces(env) - {"ah-demo"} == {o["metadata"]["name"] for o in docs if o["kind"] == "Namespace"}
    assert "DEMO_LLM_BACKEND" not in json.dumps(docs)


def test_the_demo_is_one_cluster_ip_service_in_its_own_namespace_reached_by_port_forward_only():
    deployment = find("kind", "Deployment", "demo")
    assert deployment["metadata"]["namespace"] == "ah-demo"
    service = find("kind", "Service", "demo")
    assert service["spec"].get("type", "ClusterIP") == "ClusterIP"
    assert {p["port"] for p in service["spec"]["ports"]} == {8085, 9000}
    assert not {o["kind"] for o in rendered("kind")} & {"Ingress", "Gateway", "HTTPRoute"}
    assert all(o["spec"].get("type", "ClusterIP") == "ClusterIP" for o in objects("kind", "Service"))


def test_the_demo_pod_is_restricted_has_no_token_and_runs_the_app_image_by_digest():
    deployment = find("kind", "Deployment", "demo")
    spec = deployment["spec"]["template"]["spec"]
    [container] = spec["containers"]
    assert spec["serviceAccountName"] == "demo" and spec["automountServiceAccountToken"] is False
    assert not spec.get("runtimeClassName")
    dispatcher = find("kind", "Deployment", "dispatcher")["spec"]["template"]["spec"]["containers"][0]
    assert DIGEST.match(container["image"]) and container["image"] == dispatcher["image"]
    assert container["command"] == ["python", "-m", "app.demo.main"]
    assert_restricted(spec, container, APP_UID)
    assert "kube-api-token" not in {v["name"] for v in spec["volumes"]}
    env = {e["name"]: e.get("value") for e in container["env"]}
    assert env["DEMO_LLM_BACKEND"] == "scripted" and env["DEMO_LLM_MODEL"]
    # Its two database passwords, from its own Secret, and no other secret.
    assert sorted(e["name"] for e in container["env"] if "valueFrom" in e) == ["DB_PASSWORD_DEMO_OPS", "DB_PASSWORD_DEMO_PORTAL"]
    assert find("kind", "Secret", "demo-secrets")["stringData"].keys() == {"DB_PASSWORD_DEMO_PORTAL", "DB_PASSWORD_DEMO_OPS"}


def test_the_demo_may_reach_only_the_database_and_default_denies_everything_else():
    mine = [p for p in network_policies("kind") if p["metadata"]["namespace"] == "ah-demo"]
    assert sorted(p["metadata"]["name"] for p in mine) == [
        "default-deny", "edge-21-monitoring-to-metrics-in", "edge-23-demo-to-db-out"]
    [out] = [p for p in mine if p["metadata"]["name"].endswith("-out")]
    [rule] = out["spec"]["egress"]
    assert [x["port"] for x in rule["ports"]] == [5432]
    assert rule["to"][0]["namespaceSelector"]["matchLabels"] == {"kubernetes.io/metadata.name": "ah-data"}
    assert name_values(out["spec"]["podSelector"]) == ("demo",)
    assert "demo" not in external_names("kind")


def test_the_demo_on_azure_needs_its_own_identity_and_vault_and_reaches_the_database_subnet_only():
    sets = ("demo.enabled=true", "azure.clientIds.demo=client-demo", "azure.keyVaults.demo=kv-demo-abc123")
    docs = rendered("azure", *sets)
    assert len([o for o in docs if o["kind"] == "Deployment" and o["metadata"]["name"] == "demo"]) == 1
    [provider] = [o for o in docs if o["kind"] == "SecretProviderClass" and o["metadata"]["name"] == "demo"]
    read = provider["spec"]["parameters"]["objects"]
    assert "db-password-demo-portal" in read and "db-password-demo-ops" in read
    [out] = [p for p in network_policies("azure", *sets)
             if p["metadata"]["namespace"] == "ah-demo" and p["metadata"]["name"].endswith("-out")]
    assert out["spec"]["egress"][0]["to"] == [{"ipBlock": {"cidr": AZURE_DB_CIDR}}]
    # db-migrate writes the demo's passwords into its vault, so it may reach that vault.
    assert "kv-demo-abc123.vault.azure.net" in external_names("azure", *sets)["db-migrate"][1]
