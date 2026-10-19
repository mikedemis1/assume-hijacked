"""Operator commands use fake tools here. No Azure mutation is executed by these tests."""

import copy
import hashlib
import json
from pathlib import Path

import pytest

from secops.activation import Activation, Refused, provider_manifest, validate_config


@pytest.fixture(autouse=True)
def fresh_db():
    pass


@pytest.fixture
def config():
    return {"azure": {"subscription_id": "11111111-1111-1111-1111-111111111111",
                      "tenant_id": "22222222-2222-2222-2222-222222222222"},
            "model": {"backend": "scripted"},
            "cost": {"estimated_session_eur": 15, "approved_session_eur": 20,
                     "budget_soft_eur": 20, "budget_alert_eur": 50},
            "base": {"state_storage_account_name": "stahtest001"}, "net": {}, "lab": {}, "console": {}}


class FakeTools:
    def __init__(self, config):
        self.config, self.calls = config, []
        self.account = {"id": config["azure"]["subscription_id"],
                        "tenantId": config["azure"]["tenant_id"], "state": "Enabled"}
        self.state = {"version": 4, "resources": []}

    def __call__(self, args):
        self.calls.append(args)
        if args[:3] == ["az", "account", "show"]:
            return json.dumps(self.account)
        if "pull" in args:
            return json.dumps(self.state)
        return "{}"


def operator(tmp_path, config):
    for stack in ("base", "net", "lab"):
        path = tmp_path / "infra" / stack
        path.mkdir(parents=True)
        (path / "main.tf").write_text("# fixture\n", encoding="utf-8")
    tools = FakeTools(config)
    return Activation(tmp_path, config, tools), tools


def approved_plan(op, stack="lab", destroy=False):
    path = op.work / f"{stack}.{'destroy' if destroy else 'apply'}.tfplan"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"reviewed saved plan")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    op.write_plan_record(stack, destroy, path)
    return path, digest


def test_wrong_subscription_stops_before_any_mutation(tmp_path, config):
    op, tools = operator(tmp_path, config)
    tools.account["id"] = "33333333-3333-3333-3333-333333333333"
    with pytest.raises(Refused, match="subscription"):
        op.identity()
    assert len(tools.calls) == 1


@pytest.mark.parametrize("change", ["no-confirmation", "wrong-hash", "changed-plan", "changed-config", "changed-source"])
def test_install_refuses_unreviewed_inputs(tmp_path, config, change):
    op, tools = operator(tmp_path, config)
    path, digest = approved_plan(op)
    confirmation = f"INSTALL lab {config['azure']['subscription_id']}"
    if change == "no-confirmation":
        confirmation = ""
    elif change == "wrong-hash":
        digest = "0" * 64
    elif change == "changed-plan":
        path.write_bytes(b"changed")
    elif change == "changed-config":
        op.config["cost"]["approved_session_eur"] = 25
    else:
        (tmp_path / "infra" / "lab" / "main.tf").write_text("# changed\n", encoding="utf-8")
    with pytest.raises(Refused):
        op.apply("lab", digest, confirmation)
    assert not any("apply" in call for call in tools.calls)


def test_install_applies_only_the_exact_saved_plan(tmp_path, config):
    op, tools = operator(tmp_path, config)
    path, digest = approved_plan(op)
    op.apply("lab", digest, f"INSTALL lab {config['azure']['subscription_id']}")
    applies = [call for call in tools.calls if "apply" in call]
    assert len(applies) == 1 and applies[0][-1] == str(path)
    assert "-auto-approve" not in applies[0]


def test_teardown_net_refuses_while_lab_still_manages_resources(tmp_path, config):
    op, tools = operator(tmp_path, config)
    _, digest = approved_plan(op, "net", True)
    tools.state["resources"] = [{"mode": "managed", "type": "azurerm_kubernetes_cluster"}]
    with pytest.raises(Refused, match="lab"):
        op.apply("net", digest, f"TEARDOWN net {config['azure']['subscription_id']}", destroy=True)
    assert not any("apply" in call for call in tools.calls)


def test_complete_decommission_requires_external_backup_and_separate_confirmation(tmp_path, config):
    op, tools = operator(tmp_path, config)
    with pytest.raises(Refused, match="backup"):
        op.prepare_decommission(tmp_path / "backups", "")
    assert not any("apply" in call for call in tools.calls)


@pytest.mark.parametrize("backend", ["scripted", "anthropic", "foundry"])
def test_provider_manifest_has_only_selected_provider_authority(backend):
    manifest = {"network": {"egress_to": [], "dns": ["cluster"]},
                "azure": {"roles": [{"role": "Key Vault Secrets User", "scope": "kv-llm-gateway"},
                                    {"role": "Cognitive Services User", "scope": "foundry-resource"}]}}
    model = {"backend": backend, "foundry_resource_id": "/subscriptions/example/providers/Microsoft.CognitiveServices/accounts/model"}
    result = provider_manifest(copy.deepcopy(manifest), model)
    assert ("internet" in result["network"]["egress_to"]) == (backend != "scripted")
    foundry = [r for r in result["azure"]["roles"] if r["role"] == "Cognitive Services User"]
    assert bool(foundry) == (backend == "foundry")
    if foundry:
        assert foundry[0]["scope"] == model["foundry_resource_id"]


def test_plan_cannot_exceed_the_operator_session_cost_approval(config):
    config["cost"]["estimated_session_eur"] = 21
    with pytest.raises(Refused, match="cost"):
        validate_config(config)


def test_stack_inputs_cannot_override_the_checked_subscription(config):
    config["lab"]["subscription_id"] = "33333333-3333-3333-3333-333333333333"
    with pytest.raises(Refused, match="override"):
        validate_config(config)


def test_dependency_state_is_rebound_to_the_configured_backend(tmp_path, config):
    op, tools = operator(tmp_path, config)
    op.require_empty("lab")
    assert any("init" in call and "-backend-config=storage_account_name=stahtest001" in call for call in tools.calls)


def test_base_without_migration_marker_refuses_an_existing_remote_backend(tmp_path, config):
    op, tools = operator(tmp_path, config)
    (tmp_path / "infra/base/zz_backend_override.tf").write_text('terraform { backend "azurerm" {} }')
    with pytest.raises(Refused, match="backend"):
        op.initialize("base")
    assert not any("init" in call for call in tools.calls)


def test_output_rebinds_the_backend_before_reading(tmp_path, config):
    op, tools = operator(tmp_path, config)
    assert op.output("lab") == {}
    assert "init" in tools.calls[0]
    assert "output" in tools.calls[1]


def test_saved_plan_is_invalidated_by_container_build_changes(tmp_path, config):
    op, tools = operator(tmp_path, config)
    (tmp_path / "Dockerfile").write_text("FROM original\n")
    _, digest = approved_plan(op)
    (tmp_path / "Dockerfile").write_text("FROM changed\n")
    with pytest.raises(Refused, match="changed"):
        op.apply("lab", digest, f"INSTALL lab {config['azure']['subscription_id']}")
    assert not any("apply" in call for call in tools.calls)


def test_migration_refuses_an_occupied_remote_state(tmp_path, config):
    op, tools = operator(tmp_path, config)
    original = tools.__call__
    def run(args):
        if args[:4] == ["az", "storage", "blob", "exists"]:
            return '{"exists":true}'
        return original(args)
    op.run = run
    with pytest.raises(Refused, match="destination"):
        op.migrate_base(f"MIGRATE base {config['azure']['subscription_id']}")
    assert not any("-force-copy" in call for call in tools.calls)


def test_application_values_replace_all_placeholder_images_and_render(tmp_path, config):
    import shutil
    import subprocess
    root = Path(__file__).resolve().parents[1]
    fixture = json.loads((root / "ci/chart-values/azure.json").read_text(encoding="utf-8"))
    key = tmp_path / "public.pem"
    key.write_text(fixture["gateway"]["publicKeyPem"], encoding="ascii")
    config["console"] = {"client_id": fixture["console"]["entra"]["clientId"],
                         "redirect_uri": "https://localhost:8443/auth/callback"}
    config["deployment"] = {"gateway_public_key_file": str(key)}
    for name in ("app", "postgres", "azure_cli"):
        config["deployment"][f"{name}_image"] = f"example.azurecr.io/{name}:reviewed@sha256:" + "a" * 64
    op = Activation(root, config)
    op.work = tmp_path / "work"
    outputs = {"base": {"acr_login_server": "example.azurecr.io"},
               "net": {"spoke_subnet_address_prefixes": {"snet-pe": "10.20.2.0/26"}},
               "lab": {"postgres_host": "db.postgres.database.azure.com", "postgres_entra_admin": "db-migrate",
                       "workload_client_ids": fixture["azure"]["clientIds"],
                       "component_key_vaults": fixture["azure"]["keyVaults"]}}
    op.output = lambda stack: outputs[stack]
    path = op.application_values()
    values = json.loads(path.read_text(encoding="utf-8"))
    assert values["registry"] == "example.azurecr.io/"
    assert set(values["images"]) == {"app", "postgres", "azureCli"}
    assert all("placeholder" not in value for value in values["images"].values())
    if shutil.which("helm"):
        rendered = subprocess.run(["helm", "template", "ah", str(root / "deploy/helm/assume-hijacked"),
            "-f", str(root / "deploy/helm/assume-hijacked/values-azure.yaml"), "-f", str(path)],
            capture_output=True, text=True, encoding="utf-8", timeout=90, check=False)
        assert rendered.returncode == 0, rendered.stderr
        assert "acrplaceholder" not in rendered.stdout


def test_decommission_keeps_recoverable_state_outside_its_backend(tmp_path, config):
    op, tools = operator(tmp_path / "repo", config)
    original = tools.__call__
    def run(args):
        if "pull" in args and any("base" in part for part in args):
            return json.dumps({"version": 4, "lineage": "base-fixture", "serial": 7,
                               "resources": [{"mode": "managed", "type": "azurerm_storage_account", "instances": [{}]}]})
        return original(args)
    op.run = run
    external = tmp_path / "recoverable"
    op.prepare_decommission(external, f"DECOMMISSION {config['azure']['subscription_id']}")
    assert (external / "base-before-retirement.tfstate").is_file()
    directory = op.retirement_directory()
    assert 'backend "local"' in (directory / "zz_backend_override.tf").read_text()
    assert "prevent_destroy = false" in (directory / "zz_retirement_override.tf").read_text()
    assert json.loads((directory / "terraform.tfstate").read_text())["lineage"] == "base-fixture"
    assert not any("apply" in call for call in tools.calls)
    with pytest.raises(Refused, match="fresh backup"):
        op.prepare_decommission(external, f"DECOMMISSION {config['azure']['subscription_id']}")


@pytest.mark.parametrize("drift", ["config", "live-state"])
def test_retirement_refuses_drift_before_its_first_apply(tmp_path, config, drift):
    op, tools = operator(tmp_path / "repo", config)
    original = tools.__call__
    state = {"version": 4, "lineage": "base-test", "serial": 7,
             "resources": [{"mode": "managed", "instances": [{}]}]}
    def run(args):
        if "pull" in args and any("base" in part for part in args):
            return json.dumps(state)
        return original(args)
    op.run = run
    op.prepare_decommission(tmp_path / "backup", f"DECOMMISSION {config['azure']['subscription_id']}")
    if drift == "config":
        op.config["cost"]["approved_session_eur"] += 1
    else:
        state["serial"] += 1
    with pytest.raises(Refused, match="different|changed"):
        op.retirement_directory()
        op.verify_retirement_state()
    assert not any("apply" in call for call in tools.calls)


def test_retirement_recovery_uses_external_progress_after_the_remote_backend_is_gone(tmp_path, config):
    op, tools = operator(tmp_path / "repo", config)
    original = tools.__call__
    base_state = {"version": 4, "lineage": "base-test", "serial": 7,
                  "resources": [{"mode": "managed", "instances": [{}]}]}
    backend_gone = False
    def run(args):
        if backend_gone and args[0] == "terraform" and args[1] != f"-chdir={tmp_path / 'backup/base-retirement'}":
            raise Refused("all remote states no longer exist")
        if "pull" in args and any("base" in part for part in args):
            if backend_gone:
                raise Refused("remote backend no longer exists")
            return json.dumps(base_state)
        if "apply" in args:
            working = Path(args[1].removeprefix("-chdir="))
            assert working == tmp_path / "backup/base-retirement"
        return original(args)
    op.run = run
    op.prepare_decommission(tmp_path / "backup", f"DECOMMISSION {config['azure']['subscription_id']}")
    _, plan_hash = approved_plan(op, "base", True)
    op.apply("base", plan_hash, f"TEARDOWN base {config['azure']['subscription_id']}", destroy=True)
    # Simulate persisted partial progress after storage was removed.
    backend_gone = True
    base_state["serial"] += 1
    (tmp_path / "backup/base-retirement/terraform.tfstate").write_text(json.dumps(base_state))
    op.verify_retirement_state()
    _, new_hash = approved_plan(op, "base", True)
    op.apply("base", new_hash, f"TEARDOWN base {config['azure']['subscription_id']}", destroy=True)
