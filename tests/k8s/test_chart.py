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
CLUSTER_SCOPED = {"Namespace", "ClusterRole", "ClusterRoleBinding"}
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
    # Control: the same image with a digest renders.
    pinned = "registry.example/thing:1.0@sha256:" + "a" * 64
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
def test_agent_job_template_matches_ruling_r7(env):
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
