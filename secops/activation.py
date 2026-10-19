"""Explicit operator commands for a saved-plan Azure installation. Importing runs nothing."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tomllib
import uuid
from pathlib import Path
from urllib.parse import urlsplit


class Refused(ValueError):
    """An input or approval does not match the operation."""


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def validate_config(config):
    for stack in ("base", "net", "lab"):
        for key in ("subscription_id", "tenant_id", "location"):
            if key in config.get(stack, {}) and config[stack][key] != config["azure"].get(key):
                raise Refused(f"{stack}.{key} cannot override the checked Azure identity or region")
    for key in ("subscription_id", "tenant_id"):
        if not re.fullmatch(r"[a-fA-F0-9]{8}-(?:[a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}", config["azure"][key]):
            raise Refused(f"azure.{key} must be a GUID")
    cost = config["cost"]
    for key in ("estimated_session_eur", "approved_session_eur", "budget_soft_eur", "budget_alert_eur"):
        value = cost[key]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 < value < 100000:
            raise Refused(f"invalid cost.{key}")
    if cost["estimated_session_eur"] > cost["approved_session_eur"]:
        raise Refused("estimated session cost exceeds operator approval")
    if cost["budget_soft_eur"] >= cost["budget_alert_eur"]:
        raise Refused("early budget alert must be below the upper alert")
    model = config["model"]
    if model["backend"] not in ("scripted", "anthropic", "foundry"):
        raise Refused("unknown model backend")
    if model["backend"] != "scripted" and model.get("spending_controls_reviewed") is not True:
        raise Refused("review provider spending controls before enabling a paid model")
    if model["backend"] == "foundry":
        endpoint = urlsplit(model.get("foundry_endpoint", ""))
        if endpoint.scheme != "https" or not endpoint.hostname or endpoint.path not in ("", "/") or endpoint.port:
            raise Refused("Foundry needs an exact HTTPS origin without a port")
        prefix = f"/subscriptions/{config['azure']['subscription_id']}/resourceGroups/"
        if not model.get("foundry_resource_id", "").startswith(prefix):
            raise Refused("Foundry resource must be in the selected subscription")


def provider_manifest(manifest, model):
    manifest["network"]["egress_to"] = [] if model["backend"] == "scripted" else ["internet"]
    manifest["network"]["dns"] = ["cluster"]
    roles = [r for r in manifest["azure"]["roles"] if r["role"] != "Cognitive Services User"]
    if model["backend"] == "anthropic":
        manifest["network"]["dns"].append("api.anthropic.com")
    elif model["backend"] == "foundry":
        manifest["network"]["dns"] += [urlsplit(model.get("foundry_endpoint", "")).hostname,
                                         "login.microsoftonline.com"]
        roles.append({"role": "Cognitive Services User", "scope": model["foundry_resource_id"]})
    manifest["azure"]["roles"] = roles
    return manifest


def run_command(args):
    result = subprocess.run(args, capture_output=True, text=True, encoding="utf-8", timeout=3600, check=False)
    if result.returncode:
        # Tool output can contain state, secret values or rendered SQL. Keep it out of logs.
        raise Refused(f"{Path(args[0]).name} failed with exit {result.returncode}; inspect the tool locally")
    return result.stdout


class Activation:
    def __init__(self, root, config, run=run_command):
        validate_config(config)
        self.root, self.config, self.run = Path(root).resolve(), copy.deepcopy(config), run
        self.work = self.root / ".activation"

    def identity(self):
        account = json.loads(self.run(["az", "account", "show", "-o", "json"]))
        expected = self.config["azure"]
        if account.get("id", "").lower() != expected["subscription_id"].lower():
            raise Refused("current Azure subscription differs from the configuration")
        if account.get("tenantId", "").lower() != expected["tenant_id"].lower() or account.get("state") != "Enabled":
            raise Refused("wrong tenant or disabled subscription")

    def source_digest(self):
        paths = []
        for folder in ("infra", "app", "secops", "deploy", "security", "scripts", "db", "ci"):
            paths += [p for p in (self.root / folder).rglob("*") if p.is_file()
                      and not any(part in (".terraform", "__pycache__") for part in p.parts)
                      and not p.name.endswith((".tfstate", ".tfstate.backup", ".tfplan"))
                      and not p.name.endswith("_override.tf") and p.suffix not in (".pyc", ".log")]
        paths += [p for name in ("Dockerfile", "pyproject.toml", "requirements.lock", "requirements-dev.lock", "compose.yaml")
                  if (p := self.root / name).is_file()]
        return digest({p.relative_to(self.root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                       for p in sorted(paths)})

    def tf(self, stack, *args):
        if stack not in ("base", "net", "lab"):
            raise Refused("stack must be base, net or lab")
        return self.run(["terraform", f"-chdir={self.root / 'infra' / stack}", *args])

    def output(self, stack):
        self.initialize(stack)
        return {key: value["value"] for key, value in json.loads(self.tf(stack, "output", "-json")).items()}

    def prepare(self):
        self.work.mkdir(exist_ok=True)
        capabilities = self.work / "capabilities"
        capabilities.mkdir(exist_ok=True)
        for source in (self.root / "security" / "capabilities").glob("*.json"):
            doc = json.loads(source.read_text(encoding="utf-8"))
            if doc["component"] == "llm-gateway":
                doc = provider_manifest(doc, self.config["model"])
            (capabilities / source.name).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        common = {**self.config["azure"], "capabilities_dir": str(capabilities).replace("\\", "/")}
        for stack in ("base", "net", "lab"):
            values = {**self.config.get(stack, {}), **common}
            if stack == "base":
                values.update(budget_soft_amount=self.config["cost"]["budget_soft_eur"],
                              budget_hard_amount=self.config["cost"]["budget_alert_eur"])
            else:
                values["state_storage_account_name"] = self.config["base"]["state_storage_account_name"]
            if stack == "lab":
                model = self.config["model"]
                values.update(foundry_enabled=model["backend"] == "foundry",
                              anthropic_enabled=model["backend"] == "anthropic",
                              foundry_fqdn=urlsplit(model.get("foundry_endpoint", "")).hostname,
                              foundry_resource_id=model.get("foundry_resource_id"))
            allowed = set()
            for file in (self.root / "infra" / stack).glob("*.tf"):
                allowed.update(re.findall(r'^variable\s+"([^"]+)"', file.read_text(encoding="utf-8"), re.M))
            values = {k: v for k, v in values.items() if k in allowed}
            (self.work / f"{stack}.tfvars.json").write_text(json.dumps(values, indent=2) + "\n", encoding="utf-8")

    def preflight(self):
        for tool in ("az", "terraform", "helm", "kubectl", "kubelogin", "docker", "openssl"):
            if shutil.which(tool) is None:
                raise Refused(f"missing tool: {tool}")
        self.identity()
        self.prepare()

    def initialize(self, stack):
        args = ["init", "-input=false", "-lockfile=readonly"]
        if stack != "base" or (self.work / "base-migrated").exists():
            (self.root / "infra" / stack / "zz_backend_override.tf").write_text(
                'terraform {\n  backend "azurerm" {}\n}\n', encoding="utf-8")
            args += ["-reconfigure", "-backend-config=resource_group_name=rg-base",
                     f"-backend-config=storage_account_name={self.config['base']['state_storage_account_name']}",
                     "-backend-config=container_name=tfstate", f"-backend-config=key={stack}.tfstate",
                     "-backend-config=use_azuread_auth=true",
                     f"-backend-config=subscription_id={self.config['azure']['subscription_id']}",
                     f"-backend-config=tenant_id={self.config['azure']['tenant_id']}"]
        else:
            # Bootstrap must be demonstrably local. A lost migration marker must
            # never silently select an old cached remote backend.
            directory = self.root / "infra" / stack
            if (directory / "zz_backend_override.tf").exists():
                raise Refused("base backend override exists without its migration marker; inspect state before recovery")
            cached = directory / ".terraform" / "terraform.tfstate"
            if cached.exists() and json.loads(cached.read_text(encoding="utf-8")).get("backend", {}).get("type") != "local":
                raise Refused("base cached backend is not the local bootstrap backend")
            args += ["-reconfigure"]
        self.tf(stack, *args)

    def write_plan_record(self, stack, destroy, path):
        record = {"config": digest(self.config), "source": self.source_digest(),
                  "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "destroy": destroy,
                  "subscription": self.config["azure"]["subscription_id"]}
        if stack == "base" and destroy:
            directory = self.retirement_directory()
            self.verify_retirement_state()
            record["retirement_source"] = self.retirement_digest(directory)
            record["retirement_state"] = hashlib.sha256((directory / "terraform.tfstate").read_bytes()).hexdigest()
        path.with_suffix(".json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        return record["sha256"]

    def plan(self, stack, destroy=False):
        self.identity()
        self.prepare()
        if destroy and stack == "base" and not (self.work / "decommission-backup.json").exists():
            raise Refused("base retirement needs a confirmed external state backup")
        if stack == "base" and destroy:
            directory = self.retirement_directory()
            execute = lambda *args: self.run(["terraform", f"-chdir={directory}", *args])
            execute("init", "-input=false", "-lockfile=readonly")
        else:
            execute = lambda *args: self.tf(stack, *args)
            self.initialize(stack)
        path = self.work / f"{stack}.{'destroy' if destroy else 'apply'}.tfplan"
        args = ["plan", "-input=false", f"-var-file={self.work / (stack + '.tfvars.json')}", f"-out={path}"]
        if destroy:
            args.append("-destroy")
        execute(*args)
        readable = execute("show", "-no-color", str(path))
        path.with_suffix(".txt").write_text(readable, encoding="utf-8")
        return self.write_plan_record(stack, destroy, path)

    def require_empty(self, stack):
        self.initialize(stack)
        state = json.loads(self.tf(stack, "state", "pull"))
        if not isinstance(state.get("version"), int) or not isinstance(state.get("resources"), list):
            raise Refused(f"{stack} state is not a readable Terraform state")
        if any(r.get("mode") == "managed" and r.get("instances") != [] for r in state.get("resources", [])):
            raise Refused(f"{stack} still manages resources; destroy it first")

    def apply(self, stack, approved_hash, confirmation, destroy=False):
        verb = "TEARDOWN" if destroy else "INSTALL"
        if confirmation != f"{verb} {stack} {self.config['azure']['subscription_id']}":
            raise Refused("missing exact confirmation")
        self.identity()
        path = self.work / f"{stack}.{'destroy' if destroy else 'apply'}.tfplan"
        try:
            record = json.loads(path.with_suffix(".json").read_text(encoding="utf-8"))
            if (approved_hash != record["sha256"] or hashlib.sha256(path.read_bytes()).hexdigest() != approved_hash
                    or record["config"] != digest(self.config) or record["source"] != self.source_digest()
                    or record["destroy"] != destroy or record["subscription"] != self.config["azure"]["subscription_id"]):
                raise Refused("saved plan, source or configuration changed; review a new plan")
        except (OSError, KeyError, json.JSONDecodeError) as exc:
            raise Refused("missing or invalid reviewed saved plan") from exc
        recovering = False
        if destroy and stack == "base":
            self.retirement_directory()
            backup = json.loads((self.work / "decommission-backup.json").read_text(encoding="utf-8"))
            recovering = backup.get("started") is True and backup.get("dependencies_empty") is True
        if destroy and stack in ("net", "base") and not recovering:
            self.require_empty("lab")
        if destroy and stack == "base":
            if not recovering:
                self.require_empty("net")
            directory = self.retirement_directory()
            self.verify_retirement_state()
            if record.get("retirement_source") != self.retirement_digest(directory):
                raise Refused("retirement configuration changed; review a new plan")
            if record.get("retirement_state") != hashlib.sha256((directory / "terraform.tfstate").read_bytes()).hexdigest():
                raise Refused("retirement state changed; review a new plan")
            # From this point the remote backend itself may be removed, even if
            # another deletion fails. Recovery must preserve the local progress.
            marker = self.work / "decommission-backup.json"
            backup = json.loads(marker.read_text(encoding="utf-8"))
            backup["started"] = True
            backup["dependencies_empty"] = True
            marker.write_text(json.dumps(backup), encoding="utf-8")
            self.run(["terraform", f"-chdir={directory}", "apply", "-input=false", str(path)])
        else:
            if stack == "base" and (self.work / "decommission-backup.json").exists():
                raise Refused("base retirement has started; regular base installation is refused")
            self.tf(stack, "apply", "-input=false", str(path))
        path.with_suffix(".applied").write_text(approved_hash + "\n", encoding="ascii")

    def prepare_decommission(self, backup_dir, confirmation):
        backup_dir = Path(backup_dir).resolve()
        if self.root == backup_dir or self.root in backup_dir.parents:
            raise Refused("state backup must be outside the repository")
        if confirmation != f"DECOMMISSION {self.config['azure']['subscription_id']}":
            raise Refused("missing separate decommission confirmation")
        self.identity()
        self.require_empty("lab")
        self.require_empty("net")
        self.initialize("base")
        backup_dir.mkdir(parents=True, exist_ok=True)
        state = self.tf("base", "state", "pull")
        doc = json.loads(state)
        if not doc.get("resources"):
            raise Refused("base state backup is empty")
        path = backup_dir / "base-before-retirement.tfstate"
        if path.exists():
            raise Refused("choose a fresh backup directory; existing backups are never overwritten")
        path.write_text(state, encoding="utf-8", newline="\n")
        directory = backup_dir / "base-retirement"
        shutil.copytree(self.root / "infra/base", directory,
                        ignore=shutil.ignore_patterns(".terraform", "*.tfstate", "*.tfstate.*", "*_override.tf"))
        (directory / "terraform.tfstate").write_text(state, encoding="utf-8", newline="\n")
        (directory / "zz_backend_override.tf").write_text('terraform {\n backend "local" {}\n}\n', encoding="utf-8")
        overrides = "\n".join(f'resource "{kind}" "{name}" {{\n lifecycle {{ prevent_destroy = false }}\n}}'
            for kind, name in [("azurerm_storage_account", "state"), ("azurerm_storage_container", "state"),
                               ("azurerm_key_vault", "workload")])
        (directory / "zz_retirement_override.tf").write_text(overrides + "\n", encoding="utf-8")
        self.work.mkdir(exist_ok=True)
        (self.work / "decommission-backup.json").write_text(json.dumps({"path": str(path),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "working_dir": str(directory),
            "config": digest(self.config)}), encoding="utf-8")

    @staticmethod
    def retirement_digest(directory):
        return digest({p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(directory.glob("*.tf"))})

    def retirement_directory(self):
        backup = json.loads((self.work / "decommission-backup.json").read_text(encoding="utf-8"))
        if backup.get("config") != digest(self.config):
            raise Refused("retirement backup belongs to a different activation configuration")
        file, directory = Path(backup["path"]), Path(backup["working_dir"])
        if (not file.is_file() or hashlib.sha256(file.read_bytes()).hexdigest() != backup["sha256"]
                or not directory.is_dir() or self.root == directory.resolve() or self.root in directory.resolve().parents):
            raise Refused("external state backup missing or changed")
        return directory

    def verify_retirement_state(self):
        backup = json.loads((self.work / "decommission-backup.json").read_text(encoding="utf-8"))
        directory = self.retirement_directory()
        if backup.get("started"):
            initial = json.loads(Path(backup["path"]).read_text(encoding="utf-8"))
            working = json.loads((directory / "terraform.tfstate").read_text(encoding="utf-8"))
            if (not initial.get("lineage") or working.get("lineage") != initial["lineage"]
                    or not isinstance(working.get("serial"), int) or working["serial"] < initial.get("serial", 0)
                    or not isinstance(working.get("resources"), list)):
                raise Refused("retirement working state is not a descendant of the external backup")
            return
        self.initialize("base")
        if hashlib.sha256(self.tf("base", "state", "pull").encode()).hexdigest() != backup["sha256"]:
            raise Refused("base state changed since its retirement backup")

    def migrate_base(self, confirmation):
        if confirmation != f"MIGRATE base {self.config['azure']['subscription_id']}":
            raise Refused("missing state migration confirmation")
        self.identity()
        if (self.work / "base-migrated").exists():
            raise Refused("base migration is already recorded")
        self.initialize("base")
        self.work.mkdir(exist_ok=True)
        destination = json.loads(self.run(["az", "storage", "blob", "exists", "--auth-mode", "login",
            "--subscription", self.config["azure"]["subscription_id"],
            "--account-name", self.config["base"]["state_storage_account_name"],
            "--container-name", "tfstate", "--name", "base.tfstate", "-o", "json"]))
        if destination.get("exists") is not False:
            raise Refused("destination state exists or could not be checked; migration refuses overwrite")
        state = self.tf("base", "state", "pull")
        (self.work / f"base-before-migration-{uuid.uuid4().hex}.tfstate").write_text(state, encoding="utf-8")
        (self.root / "infra/base/zz_backend_override.tf").write_text('terraform {\n backend "azurerm" {}\n}\n', encoding="utf-8")
        self.tf("base", "init", "-input=false", "-migrate-state", "-force-copy",
                "-backend-config=resource_group_name=rg-base",
                f"-backend-config=storage_account_name={self.config['base']['state_storage_account_name']}",
                "-backend-config=container_name=tfstate", "-backend-config=key=base.tfstate",
                "-backend-config=use_azuread_auth=true")
        (self.work / "base-migrated").write_text("migrated\n", encoding="ascii")

    def application_values(self):
        base, net, lab = (self.output(stack) for stack in ("base", "net", "lab"))
        images = {"app": self.config["deployment"]["app_image"],
                  "postgres": self.config["deployment"]["postgres_image"],
                  "azureCli": self.config["deployment"]["azure_cli_image"]}
        for image in images.values():
            if not re.fullmatch(re.escape(base["acr_login_server"]) + r"/[^\s@:]+:[^\s@]+@sha256:[a-f0-9]{64}", image):
                raise Refused("every application/migration image needs a tag and real digest in the selected ACR")
            if image.endswith("0" * 64):
                raise Refused("placeholder image digest")
        model, console = self.config["model"], self.config["console"]
        values = {"registry": base["acr_login_server"] + "/", "images": images,
                  "db": {"host": lab["postgres_host"]},
                  "network": {"databaseCidr": net["spoke_subnet_address_prefixes"]["snet-pe"]},
                  "azure": {"tenantId": self.config["azure"]["tenant_id"],
                            "dbAdmin": lab["postgres_entra_admin"], "clientIds": lab["workload_client_ids"],
                            "keyVaults": lab["component_key_vaults"]},
                  "llm": {"backend": model["backend"], "model": model.get("model", "claude-haiku-5-5"),
                          "foundryEndpoint": model.get("foundry_endpoint", "")},
                  "console": {"authMode": "entra", "redirectUri": console["redirect_uri"],
                              "entra": {"tenantId": self.config["azure"]["tenant_id"], "clientId": console["client_id"]}},
                  "gateway": {"publicKeyPem": Path(self.config["deployment"]["gateway_public_key_file"]).read_text(encoding="ascii")},
                  "dbFiles": {"initSh": (self.root / "db/init/init.sh").read_text(encoding="utf-8"),
                              "sql": {p.name: p.read_text(encoding="utf-8") for p in (self.root / "db/sql").glob("*.sql")}}}
        self.work.mkdir(exist_ok=True)
        path = self.work / "application.values.json"
        path.write_text(json.dumps(values, indent=2) + "\n", encoding="utf-8")
        return path

    def app(self, confirmation, verify_only=False):
        verb = "VERIFY" if verify_only else "INSTALL"
        if confirmation != f"{verb} app {self.config['azure']['subscription_id']}":
            raise Refused("missing exact application confirmation")
        self.identity()
        self.work.mkdir(exist_ok=True)
        lab = self.output("lab")
        kubeconfig = self.work / "kubeconfig"
        self.run(["az", "aks", "get-credentials", "--subscription", self.config["azure"]["subscription_id"],
                  "-g", self.config["lab"].get("resource_group_name", "rg-lab"), "-n", lab["cluster_name"],
                  "--file", str(kubeconfig), "--overwrite-existing"])
        self.run(["kubelogin", "convert-kubeconfig", "-l", "azurecli", "--kubeconfig", str(kubeconfig)])
        if not verify_only:
            values = self.application_values()
            release = json.loads(self.run(["helm", "list", "--kubeconfig", str(kubeconfig), "-n", "default", "--all", "-o", "json"]))
            previous = [r for r in release if r.get("name") == "ah"]
            if previous and previous[0].get("status") != "deployed":
                raise Refused("existing release is not deployed; inspect migration failure before retrying")
            self.run(["helm", "upgrade", "--install", "ah", str(self.root / "deploy/helm/assume-hijacked"),
                      "--kubeconfig", str(kubeconfig), "-n", "default", "-f", str(self.root / "deploy/helm/assume-hijacked/values-azure.yaml"),
                      "-f", str(values), "--wait=hookOnly", "--timeout=10m", "--history-max=3"])
        for namespace in ("ah-intake", "ah-agent", "ah-gateway", "ah-core", "ah-staff", "ah-fakes", "ah-tools"):
            self.run(["kubectl", "--kubeconfig", str(kubeconfig), "-n", namespace, "rollout", "status", "deployment", "--timeout=180s"])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["preflight", "plan", "install", "verify", "teardown", "migrate-base", "decommission"])
    parser.add_argument("--config", type=Path, default=Path("activation.toml"))
    parser.add_argument("--stack", choices=["base", "net", "lab", "app"], default="lab")
    parser.add_argument("--destroy-plan", action="store_true")
    parser.add_argument("--approved-plan", default="")
    parser.add_argument("--confirm", default="")
    parser.add_argument("--backup-dir", type=Path)
    args = parser.parse_args(argv)
    try:
        config = tomllib.loads(args.config.read_text(encoding="utf-8"))
        op = Activation(Path(__file__).resolve().parents[1], config)
        if args.command == "preflight":
            op.preflight()
        elif args.command == "plan":
            print("Review the saved .txt plan. SHA256:", op.plan(args.stack, args.destroy_plan))
        elif args.command == "migrate-base":
            op.migrate_base(args.confirm)
        elif args.command == "decommission":
            if args.backup_dir is None:
                raise Refused("external --backup-dir is required")
            op.prepare_decommission(args.backup_dir, args.confirm)
        elif args.stack == "app" and args.command in ("install", "verify"):
            op.app(args.confirm, verify_only=args.command == "verify")
        elif args.command == "verify":
            op.identity()
            op.tf(args.stack, "state", "list")
        else:
            op.apply(args.stack, args.approved_plan, args.confirm, destroy=args.command == "teardown")
        print("Operator command completed.")
        return 0
    except (Refused, OSError, KeyError, json.JSONDecodeError, tomllib.TOMLDecodeError) as exc:
        print(f"activation refused: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
