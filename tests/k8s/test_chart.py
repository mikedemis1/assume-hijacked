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

# Contract: one namespace per trust zone, and the DB role of each component ("" = none).
COMPONENTS = {
    **{f"tool-{t.replace('_', '-')}": ("ah-tools", f"tool_{t}") for t in TOOLS},
    "tool-gateway": ("ah-gateway", "gateway"),
    "risk-engine": ("ah-core", "risk_engine"),
    "dispatcher": ("ah-intake", "dispatcher"),
    "llm-gateway": ("ah-agent", ""),
    "executor": ("ah-core", "executor"),
    "register-sync": ("ah-core", "register_sync"),
    "console": ("ah-staff", "approver"),
    "fake-register": ("ah-fakes", ""),
    "fake-dso": ("ah-fakes", ""),
    "fake-sms": ("ah-fakes", ""),
}
DB_ROLES = sorted({role for _, role in COMPONENTS.values() if role})
# Components that call the Kubernetes API (TokenReview; the dispatcher also creates Jobs).
API_CALLERS = {"tool-gateway", "llm-gateway", "dispatcher"}
CLUSTER_SCOPED = {"Namespace", "ClusterRole", "ClusterRoleBinding", "ValidatingAdmissionPolicy",
                  "ValidatingAdmissionPolicyBinding"}
NAMESPACES = {"ah-intake", "ah-agent", "ah-gateway", "ah-tools", "ah-core", "ah-staff", "ah-fakes",
              "ah-data"}
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
        values["console"] = {"entra": {"tenantId": "t-1", "clientId": "c-console-app"}}
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


@pytest.mark.parametrize("env", ENVS)
def test_helm_template_puts_every_object_in_a_contract_namespace(env):
    for obj in rendered(env):
        if obj["kind"] in CLUSTER_SCOPED:
            assert "namespace" not in obj["metadata"], obj["metadata"]["name"]
        else:
            assert obj["metadata"].get("namespace") in NAMESPACES, (obj["kind"], obj["metadata"]["name"])


@pytest.mark.parametrize("env", ENVS)
def test_every_component_has_a_deployment_in_its_namespace(env):
    deployments = {d["metadata"]["name"]: d for d in objects(env, "Deployment")}
    assert set(deployments) == set(COMPONENTS)
    for name, (namespace, _) in COMPONENTS.items():
        d = deployments[name]
        assert d["metadata"]["namespace"] == namespace, name
        assert d["spec"]["template"]["metadata"]["labels"]["app.kubernetes.io/name"] == name


def test_install_values_are_required_on_kind():
    """Without the deploy-time values (secrets, key, db files) the kind render stops."""
    result = helm("template", "kind", install=False)
    assert result.returncode != 0
    assert "is required" in result.stderr


# --- values schema walls ------------------------------------------------------------------------

def test_values_schema_rejects_dev_auth_in_azure():
    result = helm("template", "azure", "--set", "console.authMode=dev")
    assert result.returncode != 0
    assert "authMode" in result.stderr
    # Control: entra on Azure and dev on kind both render.
    assert helm("template", "azure", "--set", "console.authMode=entra").returncode == 0
    assert helm("template", "kind", "--set", "console.authMode=dev").returncode == 0


@pytest.mark.parametrize("key", ["postgresPassword", "gatewaySigningKeyPem", "anthropicApiKey",
                                 "dbPasswords.gateway"])
def test_values_schema_rejects_secret_material_in_azure(key):
    result = helm("template", "azure", "--set", f"secrets.{key}=leaked")
    assert result.returncode != 0
    assert "secrets" in result.stderr


@pytest.mark.parametrize(("env", "image"), [("kind", "app"), ("kind", "postgres"),
                                            ("azure", "app"), ("azure", "postgres"),
                                            ("azure", "azureCli")])
def test_values_schema_rejects_an_image_without_digest(env, image):
    result = helm("template", env, "--set", f"images.{image}=registry.example/thing:1.0")
    assert result.returncode != 0
    assert image in result.stderr
    # Control: the same image with a digest renders (on Azure from ACR: images outside the
    # registry are refused there, test_azure_refuses_images_outside_the_registry).
    registry = "acrplaceholder.azurecr.io/" if env == "azure" else "registry.example/"
    pinned = f"{registry}thing:1.0@sha256:" + "a" * 64
    assert helm("template", env, "--set", f"images.{image}={pinned}").returncode == 0


# --- rendered walls -----------------------------------------------------------------------------

@pytest.mark.parametrize("env", ENVS)
def test_all_images_pinned_by_digest(env):
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
def test_no_pod_automounts_sa_token(env):
    for sa in objects(env, "ServiceAccount"):
        assert sa["automountServiceAccountToken"] is False, sa["metadata"]["name"]
    for name, spec in pod_specs(env):
        assert spec["automountServiceAccountToken"] is False, name
        # The API server token is mounted explicitly, and only where the API is called.
        api_tokens = [s for v in spec.get("volumes", []) for s in v.get("projected", {}).get("sources", [])
                      if "serviceAccountToken" in s and "audience" not in s["serviceAccountToken"]]
        assert bool(api_tokens) == (name in API_CALLERS), name


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
            assert not spec.get("hostNetwork") and not spec.get("hostPID") and not spec.get("hostIPC")
            assert all("hostPath" not in v for v in spec.get("volumes", []))


@pytest.mark.parametrize("env", ENVS)
def test_every_container_has_requests_and_limits(env):
    for name, spec in pod_specs(env):
        for container in containers(spec):
            for part in ("requests", "limits"):
                assert set(container["resources"][part]) == {"cpu", "memory"}, (name, container["name"])


@pytest.mark.parametrize("env", ENVS)
def test_each_component_gets_only_its_own_db_password(env):
    for d in objects(env, "Deployment"):
        name = d["metadata"]["name"]
        _, role = COMPONENTS[name]
        [container] = d["spec"]["template"]["spec"]["containers"]
        assert "envFrom" not in container
        from_secrets = [e for e in container["env"] if "valueFrom" in e]
        expected = [f"DB_PASSWORD_{role.upper()}"] if role else []
        assert [e["name"] for e in from_secrets] == expected, name
        for e in from_secrets:
            assert e["valueFrom"]["secretKeyRef"]["name"] == f"{name}-secrets"


def test_kind_secrets_come_from_values():
    assert objects("kind", "SecretProviderClass") == []
    secrets = {s["metadata"]["name"] for s in objects("kind", "Secret")}
    assert secrets == {f"{n}-secrets" for n, (_, role) in COMPONENTS.items() if role} | {"postgres-secrets"}
    assert find("kind", "Secret", "tool-gateway-secrets")["stringData"]["signing-key.pem"].startswith("-----BEGIN")


def test_azure_secrets_come_from_key_vault_with_workload_identity():
    assert objects("azure", "Secret") == []
    deployments = {d["metadata"]["name"]: d for d in objects("azure", "Deployment")}
    spcs = {s["metadata"]["name"]: s for s in objects("azure", "SecretProviderClass")}
    with_secrets = {n for n, (_, role) in COMPONENTS.items() if role}
    assert set(spcs) == with_secrets | {"db-migrate"}
    for name, spc in spcs.items():
        assert spc["apiVersion"] == "secrets-store.csi.x-k8s.io/v1"
        assert spc["spec"]["provider"] == "azure"
        assert spc["spec"]["parameters"]["clientID"] == f"client-{name}"
        assert spc["spec"]["secretObjects"][0]["secretName"] == f"{name}-secrets"
    service_accounts = {s["metadata"]["name"]: s for s in objects("azure", "ServiceAccount")}
    for name, d in deployments.items():
        pod = d["spec"]["template"]
        csi = [v for v in pod["spec"].get("volumes", []) if "csi" in v]
        annotated = "azure.workload.identity/client-id" in service_accounts[name]["metadata"].get("annotations", {})
        # The CSI driver reads the vault with its own token request; the app process gets no
        # Azure token (webhook label) unless it calls Azure itself.
        assert "azure.workload.identity/use" not in pod["metadata"]["labels"], name
        if name in with_secrets:
            assert csi[0]["csi"] == {"driver": "secrets-store.csi.k8s.io", "readOnly": True,
                                     "volumeAttributes": {"secretProviderClass": name}}
            assert annotated, name
        else:
            assert not csi and not annotated, name
    # db-migrate calls Entra itself, so it gets the injected token.
    migrate = find("azure", "Job", "db-migrate")["spec"]["template"]["metadata"]["labels"]
    assert migrate["azure.workload.identity/use"] == "true"
    # The agent never gets an Azure identity.
    assert "annotations" not in service_accounts["agent"]["metadata"]


def test_llm_gateway_gets_azure_identity_only_for_foundry():
    def llm_pod(*sets):
        [d] = [o for o in rendered("azure", *sets)
               if o["kind"] == "Deployment" and o["metadata"]["name"] == "llm-gateway"]
        return d["spec"]["template"]
    assert "azure.workload.identity/use" not in llm_pod()["metadata"]["labels"]
    foundry = llm_pod("llm.backend=foundry", "llm.foundryEndpoint=https://ai.example.test")
    assert foundry["metadata"]["labels"]["azure.workload.identity/use"] == "true"
    env = {e["name"]: e.get("value") for e in foundry["spec"]["containers"][0]["env"]}
    assert env["FOUNDRY_ENDPOINT"] == "https://ai.example.test"


def test_database_objects_per_environment():
    kind_names = {(o["kind"], o["metadata"]["name"]) for o in rendered("kind")}
    azure_names = {(o["kind"], o["metadata"]["name"]) for o in rendered("azure")}
    assert {("StatefulSet", "postgres"), ("Job", "postgres-init"), ("Namespace", "ah-data")} <= kind_names
    assert ("Job", "db-migrate") not in kind_names
    assert ("Job", "db-migrate") in azure_names
    assert not any(n in {"postgres", "postgres-init", "ah-data"} for _, n in azure_names)
    for env, job in (("kind", "postgres-init"), ("azure", "db-migrate")):
        annotations = find(env, "Job", job)["metadata"]["annotations"]
        assert annotations["helm.sh/hook"] == "post-install", "init.sh is not idempotent: run once"


@pytest.mark.parametrize("env", ENVS)
def test_db_setup_job_gets_init_sh_and_every_sql_file(env):
    sql = find(env, "ConfigMap", "db-sql")["data"]
    assert set(sql) == {p.name for p in (ROOT / "db" / "sql").glob("*.sql")}
    init = find(env, "ConfigMap", "db-init")["data"]["init.sh"]
    assert init == (ROOT / "db" / "init" / "init.sh").read_text(encoding="utf-8")


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
    ("ah-core", ("executor",), "ah-fakes", ("fake-dso",), (8091,)),                    # 15
    ("ah-core", ("executor",), "ah-fakes", ("fake-sms",), (8092,)),                    # 15
    ("ah-core", ("register-sync",), "ah-fakes", ("fake-register",), (8090,)),          # 16
    ("ah-core", ("register-sync",), DB, (), (5432,)),                                  # 16
    ("ah-staff", ("console",), DB, (), (5432,)),                                       # 18
}
DB_SETUP = {"kind": ("ah-data", ("postgres-init",)), "azure": ("ah-core", ("db-migrate",))}
OPS_NAMESPACES = {"ah-intake", "ah-agent", "ah-gateway", "ah-tools", "ah-core", "ah-staff"}
CLUSTER_DNS_PATTERNS = ["*.*.svc.cluster.local.", "*.*.svc.cluster.local.*.svc.cluster.local.",
                        "*.*.svc.cluster.local.svc.cluster.local.", "*.*.svc.cluster.local.cluster.local."]
ENTRA = "login.microsoftonline.com"
POLICIES = {"ah-images-pinned", "ah-no-host-access", "ah-sandbox-runtime", "ah-agent-job-template"}


def chart_namespaces(env: str) -> set[str]:
    return NAMESPACES if env == "kind" else NAMESPACES - {"ah-data"}


def name_values(selector: dict) -> tuple:
    """app.kubernetes.io/name values a pod selector picks; () for every pod."""
    if not selector:
        return ()
    [expr] = selector["matchExpressions"]
    assert expr["key"] == "app.kubernetes.io/name" and expr["operator"] == "In"
    return tuple(sorted(expr["values"]))


def expected_edges(env: str) -> set:
    edges = set(MATRIX) | {(*DB_SETUP[env], DB, (), (5432,))}
    target = {"kind": ("ah-data", ("postgres",)), "azure": (AZURE_DB_CIDR, ())}[env]
    return {(a, b, *(target if c == DB else (c, d)), e) for a, b, c, d, e in edges}


def network_policies(env: str, *sets: str) -> list[dict]:
    return [o for o in rendered(env, *sets) if o["kind"] == "NetworkPolicy"]


def cilium_policies(env: str, *sets: str) -> list[dict]:
    return [o for o in rendered(env, *sets) if o["kind"] == "CiliumNetworkPolicy"]


@pytest.mark.parametrize("env", ENVS)
def test_every_namespace_renders_default_deny(env):
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
    metrics = {("ah-monitoring", (), ns, (), (9000,)) for ns in OPS_NAMESPACES}
    assert ingress == {e for e in expected if e[2] != AZURE_DB_CIDR} | metrics


@pytest.mark.parametrize("env", ENVS)
def test_the_agent_reaches_only_its_three_services(env):
    """The blocking view of the same walls: no edge from the agent to a tool, the database, the
    risk engine or a fake, and the tools reach nothing but the database."""
    edges = expected_edges(env)
    assert {(c, d) for a, b, c, d, _ in edges if b == ("agent",)} == {
        ("ah-gateway", ("tool-gateway",)), ("ah-agent", ("llm-gateway",)), ("ah-intake", ("dispatcher",))}
    db = {"kind": "ah-data", "azure": AZURE_DB_CIDR}[env]
    assert {c for a, _, c, _, _ in edges if a == "ah-tools"} == {db}


@pytest.mark.parametrize("env", ENVS)
def test_no_networkpolicy_allows_dns_or_open_egress(env):
    """DNS goes only through Cilium's DNS rule: an L4 allow on port 53 would switch it off."""
    for p in network_policies(env):
        for rule in p["spec"].get("egress", []):
            assert rule.get("to"), p["metadata"]["name"]
            assert rule.get("ports"), p["metadata"]["name"]
            assert all(x["port"] not in (53, "53") for x in rule["ports"]), p["metadata"]["name"]


@pytest.mark.parametrize("env", ENVS)
def test_dns_rule_allows_cluster_names_only(env):
    dns = {p["metadata"]["namespace"]: p["spec"] for p in cilium_policies(env)
           if p["metadata"]["name"] == "edge-22-dns-cluster-names-only"}
    assert set(dns) == chart_namespaces(env)
    for namespace, spec in dns.items():
        assert spec["endpointSelector"] == {}
        [rule] = spec["egress"]
        assert rule["toEndpoints"] == [{"matchLabels": {"k8s:io.kubernetes.pod.namespace": "kube-system",
                                                        "k8s:k8s-app": "kube-dns"}}]
        [to_ports] = rule["toPorts"]
        assert to_ports["ports"] == [{"port": "53", "protocol": "ANY"}]
        patterns = [r["matchPattern"] for r in to_ports["rules"]["dns"]]
        # Plus the first search form of a short name <service>.<namespace> (search list of a pod
        # in this namespace).
        assert patterns == [*CLUSTER_DNS_PATTERNS, f"*.*.{namespace}.svc.cluster.local."]
        # `*` matches one label only (Cilium docs), so every allowed name ends in cluster.local.
        assert all(p.endswith(".cluster.local.") for p in patterns)


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


def test_only_named_components_reach_names_outside_the_cluster():
    # kind defaults (scripted backend, dev console): nothing outside the cluster at all.
    assert external_names("kind") == {}
    assert external_names("kind", "llm.backend=anthropic", "secrets.anthropicApiKey=test-only") == {
        "llm-gateway": (search_names("api.anthropic.com", "ah-agent"), ["api.anthropic.com"])}
    assert external_names("azure") == {"console": (search_names(ENTRA, "ah-staff"), [ENTRA]),
                                       "db-migrate": (search_names(ENTRA, "ah-core"), [ENTRA])}
    # The endpoint's port is not part of the name.
    for endpoint in ("https://ai-ah.openai.azure.com/", "https://ai-ah.openai.azure.com:443/openai"):
        foundry = external_names("azure", "llm.backend=foundry", f"llm.foundryEndpoint={endpoint}")
        assert foundry["llm-gateway"] == (
            search_names("ai-ah.openai.azure.com", "ah-agent") + search_names(ENTRA, "ah-agent"),
            ["ai-ah.openai.azure.com", ENTRA])
    # No other Cilium egress to the world: no CIDR allow, no entity but the API server.
    for env in ENVS:
        for p in cilium_policies(env):
            for rule in p["spec"].get("egress", []):
                assert "toCIDR" not in rule and "toCIDRSet" not in rule, p["metadata"]["name"]
                assert set(rule.get("toEntities", [])) <= {"kube-apiserver"}, p["metadata"]["name"]


@pytest.mark.parametrize("env", ENVS)
def test_instance_metadata_denied_in_every_namespace(env):
    deny = {p["metadata"]["namespace"]: p["spec"] for p in cilium_policies(env)
            if p["metadata"]["name"] == "deny-instance-metadata"}
    assert set(deny) == chart_namespaces(env)
    for spec in deny.values():
        assert spec == {"endpointSelector": {}, "egressDeny": [{"toCIDR": ["169.254.169.254/32"]}]}


@pytest.mark.parametrize("env", ENVS)
def test_only_api_callers_reach_kube_apiserver(env):
    callers = set()
    for p in cilium_policies(env):
        for rule in p["spec"].get("egress", []):
            if "kube-apiserver" in rule.get("toEntities", []):
                callers.add((p["metadata"]["namespace"],
                             p["spec"]["endpointSelector"]["matchLabels"]["app.kubernetes.io/name"]))
    assert callers == {("ah-intake", "dispatcher"), ("ah-gateway", "tool-gateway"), ("ah-agent", "llm-gateway")}
    assert {name for _, name in callers} == API_CALLERS


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


def test_image_policy_allows_only_the_registry_and_pinned_upstream_images():
    kind = policy_text("kind", "ah-images-pinned")
    assert "i.startsWith('localhost:5001/')" in kind
    # The Postgres image keeps its public digest on kind: allowed exactly as written.
    postgres = find("kind", "StatefulSet", "postgres")["spec"]["template"]["spec"]["containers"][0]["image"]
    assert f'!(i in ["{postgres}"])' in kind
    azure = policy_text("azure", "ah-images-pinned")
    assert "i.startsWith('acrplaceholder.azurecr.io/')" in azure
    assert "!(i in [])" in azure


def test_azure_refuses_images_outside_the_registry():
    upstream = "docker.io/library/postgres@sha256:" + "b" * 64
    result = helm("template", "azure", "--set", f"images.postgres={upstream}")
    assert result.returncode != 0
    assert "must come from the registry" in result.stderr
    # Control: the same image imported into ACR renders.
    acr = "acrplaceholder.azurecr.io/postgres@sha256:" + "b" * 64
    assert helm("template", "azure", "--set", f"images.postgres={acr}").returncode == 0


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


def test_values_schema_pins_sandbox_runtime_in_azure():
    result = helm("template", "azure", "--set", "sandbox.runtimeClass=runc")
    assert result.returncode != 0
    assert "runtimeClass" in result.stderr
    # Control: the AKS Kata class renders.
    assert helm("template", "azure", "--set", f"sandbox.runtimeClass={SANDBOX_RUNTIME}").returncode == 0


@pytest.mark.parametrize(("env", "registry"), [("kind", "docker.io/"), ("azure", "localhost:5001/"),
                                               ("azure", "evil.example/")])
def test_values_schema_rejects_another_registry(env, registry):
    result = helm("template", env, "--set", f"registry={registry}")
    assert result.returncode != 0
    assert "registry" in result.stderr


def test_console_template_refuses_dev_auth_in_azure_without_the_schema():
    """helm --skip-schema-validation skips values.schema.json; the template still refuses."""
    result = helm("template", "azure", "--skip-schema-validation", "--set", "console.authMode=dev")
    assert result.returncode != 0
    assert "console.authMode must be entra with env=azure" in result.stderr
    # Control: entra renders without the schema too.
    assert helm("template", "azure", "--skip-schema-validation").returncode == 0


@pytest.mark.parametrize("endpoint", ["ai-ah.openai.azure.com", "https:///openai"])
def test_foundry_endpoint_without_a_host_is_refused(endpoint):
    """A scheme-less or host-less endpoint would give an empty DNS name."""
    result = helm("template", "azure", "--set", "llm.backend=foundry", "--set", f"llm.foundryEndpoint={endpoint}")
    assert result.returncode != 0
    assert "llm.foundryEndpoint must be a URL with a host" in result.stderr


@pytest.mark.parametrize("env", ENVS)
def test_db_callers_resolve_the_database_name_on_azure_only(env):
    """On Azure the database is reached by name (db.host, private DNS zone): its callers, and only
    they, may resolve that one name. DNS only; the connection is the ipBlock edge."""
    policies = [p for p in cilium_policies(env) if p["metadata"]["name"] == "edge-22-db-host-dns"]
    if env == "kind":
        assert policies == []
        return
    host = install_values("azure")["db"]["host"]
    callers = {}
    for p in policies:
        ns, spec = p["metadata"]["namespace"], p["spec"]
        [rule] = spec["egress"]
        assert set(rule) == {"toEndpoints", "toPorts"}
        assert rule["toPorts"][0]["ports"] == [{"port": "53", "protocol": "ANY"}]
        assert [r["matchName"] for r in rule["toPorts"][0]["rules"]["dns"]] == search_names(host, ns)
        callers[ns] = name_values(spec["endpointSelector"])
    expected = {}
    for a, b, c, _, _ in expected_edges("azure"):
        if c == AZURE_DB_CIDR:
            expected[a] = tuple(sorted(set(expected.get(a, ())) | set(b)))
    assert callers == expected
    # Blocking view: the agent and llm-gateway namespace and the fakes never resolve it.
    assert not {"ah-agent", "ah-fakes"} & set(callers)


@pytest.mark.parametrize(("env", "setting", "message"), [
    ("azure", "sandbox.runtimeClass=runc", "sandbox.runtimeClass must be kata-vm-isolation"),
    ("azure", "registry=docker.io/", "registry must be the ACR login server"),
    ("azure", "registry=localhost:5001/", "registry must be the ACR login server"),
    ("kind", "registry=docker.io/", "registry must be localhost:5001/"),
    ("azure", "network.databaseCidr=0.0.0.0/0", "network.databaseCidr must be a private"),
])
def test_template_refuses_what_the_schema_refuses_without_the_schema(env, setting, message):
    """helm --skip-schema-validation skips values.schema.json, and the admission and network
    policies enforce these values, so the templates check them as well."""
    result = helm("template", env, "--skip-schema-validation", "--set", setting)
    assert result.returncode != 0
    assert message in result.stderr
    # Control: the environment's own values render without the schema.
    assert helm("template", env, "--skip-schema-validation").returncode == 0


@pytest.mark.parametrize("cidr", ["0.0.0.0/0", "8.8.8.0/24", "10.0.0.0/8", "10.20.2.0/23", "172.32.0.0/24",
                                  "192.169.1.0/24"])
def test_database_cidr_must_be_private_and_narrow(cidr):
    # The schema refuses it ...
    result = helm("template", "azure", "--set", f"network.databaseCidr={cidr}")
    assert result.returncode != 0
    assert "/network/databaseCidr" in result.stderr and "does not match pattern" in result.stderr
    # ... and so does the template when the schema is skipped.
    result = helm("template", "azure", "--skip-schema-validation", "--set", f"network.databaseCidr={cidr}")
    assert result.returncode != 0
    assert "network.databaseCidr must be a private (RFC 1918) range of /24 or longer" in result.stderr


@pytest.mark.parametrize("cidr", ["10.20.2.0/26", "172.16.5.0/24", "192.168.1.0/28"])
def test_database_cidr_accepts_a_private_subnet(cidr):
    result = helm("template", "azure", "--set", f"network.databaseCidr={cidr}")
    assert result.returncode == 0, result.stderr
    assert f"cidr: {cidr}" in result.stdout
