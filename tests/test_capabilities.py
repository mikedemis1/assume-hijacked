"""The capability manifests (security/capabilities/*.json): what each component may do, written
down so the permission assessment can compare it with the running system.

These tests check the manifests against the application itself: the fingerprint of every tool
descriptor, the database role and function of every tool, and who holds the gateway's keys.
"""

import asyncio
import copy
import dataclasses
import hashlib
import json
import os
import subprocess
import time
from pathlib import Path

import pytest
import yaml

from app import config
from app.security import descriptors
from app.security.tokens import JtiCache, load_private_key, load_public_key, mint_tool_token, verify_tool_token
from app.tools import serve
from tests.toolhttp import KEYS, bearer, post_each

ROOT = Path(__file__).resolve().parent.parent
CAPABILITIES = ROOT / "security" / "capabilities"
TOOL_COMPONENTS = {tool: "tool-" + tool.replace("_", "-") for tool in serve.TOOLS}
# Keys a manifest may have. The permission generator rejects any other, so a typo cannot drop a
# permission without a word.
TOP_KEYS = {"component", "description", "db", "network", "k8s", "azure", "runtime_class", "mcp"}


def manifests() -> dict[str, dict]:
    return {path.stem: json.loads(path.read_text(encoding="utf-8")) for path in sorted(CAPABILITIES.glob("*.json"))}


def test_manifests_are_named_after_their_component_and_use_known_keys():
    found = manifests()
    assert found, "no manifests"
    for name, manifest in found.items():
        assert manifest["component"] == name
        assert set(manifest) <= TOP_KEYS, name
        assert {"component", "db", "network", "k8s", "azure", "runtime_class", "mcp"} <= set(manifest), name


def test_every_tool_and_the_database_has_a_manifest():
    found = manifests()
    assert set(TOOL_COMPONENTS.values()) <= set(found)
    assert {"db", "agent", "executor", "risk-engine", "register-sync"} <= set(found)


# --- the descriptor fingerprint ---------------------------------------------------------------

def test_manifest_descriptor_hashes_match_the_live_tools():
    # The gateway refuses a tool whose live descriptor differs from this fingerprint, so a tool
    # description or schema that changed after review does not reach the model unseen. Change a
    # tool, run `python -m app.security.descriptors --write`, and review the diff.
    for tool, component in TOOL_COMPONENTS.items():
        listed = manifests()[component]["mcp"]["tools"]
        assert listed == descriptors.manifest_tools(tool), component
        assert [t["name"] for t in listed] == [tool]
        assert all(len(t["descriptor_sha256"]) == 64 for t in listed)


def test_manifest_hashes_match_a_tools_list_answer_read_over_http():
    # The fingerprint the gateway will check is of the wire entry. Read it the way a client does:
    # a signed tools/list request to the tool's app, and hash the entry in the JSON answer.
    private, public = KEYS
    for tool, component in TOOL_COMPONENTS.items():
        app = serve.build_app(tool, descriptors.safe_settings(), public)
        token = mint_tool_token(private, tool, "ab" * 32, time.time())
        (answer, _), = asyncio.run(post_each(app, bearer(token)))
        assert answer.status_code == 200, component
        (wire,) = answer.json()["result"]["tools"]
        assert descriptors.descriptor_sha256(wire) == manifests()[component]["mcp"]["tools"][0]["descriptor_sha256"]


def test_every_fingerprint_differs():
    hashes = [t["descriptor_sha256"] for c in TOOL_COMPONENTS.values() for t in manifests()[c]["mcp"]["tools"]]
    assert len(set(hashes)) == len(hashes) == 5


def entry(tool="lookup_account"):
    (found,) = descriptors.tool_entries(tool)
    return found


def test_fingerprint_changes_when_the_description_or_the_schema_changes():
    base = entry("issue_bill_credit")
    hashed = descriptors.descriptor_sha256(base)
    assert descriptors.descriptor_sha256(copy.deepcopy(base)) == hashed          # control: same input
    worded = {**base, "description": base["description"] + " Also send the customer's phone number."}
    assert descriptors.descriptor_sha256(worded) != hashed
    schema = copy.deepcopy(base)
    schema["inputSchema"]["properties"]["extra"] = {"type": "string"}
    assert descriptors.descriptor_sha256(schema) != hashed
    renamed = {**base, "name": "issue_bill_credit_v2"}
    assert descriptors.descriptor_sha256(renamed) != hashed


def test_fingerprint_ignores_key_order_and_fields_it_does_not_cover():
    base = entry("issue_bill_credit")
    reordered = dict(reversed(list(base.items())))
    reordered["inputSchema"] = dict(reversed(list(base["inputSchema"].items())))
    with_extra = {**base, "annotations": {"readOnlyHint": True}, "title": "Credit"}
    assert descriptors.descriptor_sha256(reordered) == descriptors.descriptor_sha256(base)
    assert descriptors.descriptor_sha256(with_extra) == descriptors.descriptor_sha256(base)


def test_fingerprint_is_the_sha256_of_the_canonical_json():
    # A fixed input with a known answer, so the format cannot drift unnoticed: another component
    # (the gateway) computes the same thing from the wire.
    known = {"name": "t", "description": "dé", "inputSchema": {"b": 1, "a": [True, None]}}
    text = '{"description":"dé","inputSchema":{"a":[true,null],"b":1},"name":"t"}'
    assert descriptors.canonical(known) == text.encode("utf-8")
    assert descriptors.descriptor_sha256(known) == hashlib.sha256(text.encode("utf-8")).hexdigest()
    assert descriptors.descriptor_sha256(known) == "612262db6ad6b7ce1b09fcd36e1d76a4f2f4283692fb05a4fdfc8619f531930e"


def test_a_vulnerable_lookup_has_another_descriptor_than_the_safe_one():
    # The demo switch changes what the model is told (a customer argument), so the fingerprint
    # in the manifest, made for the safe build, would refuse it.
    safe = descriptors.manifest_tools("lookup_account")
    demo = descriptors.manifest_tools("lookup_account", dataclasses.replace(config.load(), vulnerable=True))
    assert safe[0]["descriptor_sha256"] != demo[0]["descriptor_sha256"]
    assert safe[0]["args"] == {} and demo[0]["args"] == {"customer_id": "integer"}


def test_check_mode_reports_a_stale_manifest(tmp_path):
    copy_dir = tmp_path / "caps"
    copy_dir.mkdir()
    for path in CAPABILITIES.glob("tool-*.json"):
        (copy_dir / path.name).write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    assert descriptors.main(["--check", "--manifests", str(copy_dir)]) == 0
    stale = copy_dir / "tool-read-ticket.json"
    data = json.loads(stale.read_text(encoding="utf-8"))
    data["mcp"]["tools"][0]["descriptor_sha256"] = "0" * 64
    stale.write_text(json.dumps(data), encoding="utf-8")
    assert descriptors.main(["--check", "--manifests", str(copy_dir)]) == 1
    assert descriptors.main(["--write", "--manifests", str(copy_dir)]) == 0
    assert descriptors.main(["--check", "--manifests", str(copy_dir)]) == 0


# --- the manifests against the database --------------------------------------------------------

def granted_functions(admin, role):
    rows = admin.execute(
        "SELECT p.oid::regprocedure::text AS f FROM pg_proc p "
        "WHERE p.pronamespace = 'public'::regnamespace AND has_function_privilege(%s, p.oid, 'EXECUTE') "
        "ORDER BY 1",
        (role,),
    ).fetchall()
    return [r["f"] for r in rows]


@pytest.mark.parametrize("tool, component", list(TOOL_COMPONENTS.items()))
def test_a_tool_manifest_names_its_role_and_its_one_function(admin, tool, component):
    manifest = manifests()[component]["db"]
    assert manifest["role"] == serve.ROLES[tool]
    assert manifest["tables"] == {}
    assert len(manifest["execute"]) == 1
    role = admin.execute(
        "SELECT rolcanlogin, rolconnlimit FROM pg_roles WHERE rolname = %s", (manifest["role"],)
    ).fetchone()
    assert role == {"rolcanlogin": True, "rolconnlimit": manifest["connection_limit"]}
    # What the database lets the role execute is exactly the one function the manifest names.
    granted = [f.removeprefix("public.") for f in granted_functions(admin, manifest["role"])]
    assert granted == [f.replace(" ", "") for f in manifest["execute"]]  # regprocedure prints no spaces
    assert manifests()[component]["network"] == {
        "ingress_from": ["agent"], "egress_to": ["db"], "dns": ["cluster"]
    }


def test_the_database_manifest_lists_every_owner_without_a_login(admin):
    roles = {spec["role"]: spec for spec in manifests()["db"]["db"]["roles"]}
    nologin = {
        r["rolname"]
        for r in admin.execute("SELECT rolname FROM pg_roles WHERE NOT rolcanlogin AND rolname !~ '^pg_'").fetchall()
    }
    assert nologin == set(roles) - {"postgres"}
    assert all(roles[name]["login"] is False for name in nologin)
    policy_tables = {
        r["tablename"] for r in admin.execute("SELECT tablename FROM pg_policies WHERE policyname = 'trusted_all'")
    }
    assert policy_tables == set(manifests()["db"]["db"]["rls"])


# --- who holds the gateway's keys --------------------------------------------------------------

def compose():
    return yaml.safe_load((ROOT / "compose.yaml").read_text(encoding="utf-8"))


def test_every_tool_gets_the_public_key_and_only_the_agent_gets_the_private_key():
    services = compose()["services"]
    for tool, component in TOOL_COMPONENTS.items():
        service = services[component]
        assert service["secrets"] == ["gateway_public_key"], component
        assert service["environment"]["TOOL_NAME"] == tool
        assert service["environment"]["GATEWAY_PUBLIC_KEY_FILE"] == "/run/secrets/gateway_public_key"
        assert service["command"][-1] == tool
    holders = [name for name, service in services.items() if "gateway_signing_key" in service.get("secrets", [])]
    assert holders == ["agent"]
    assert services["agent"]["environment"]["GATEWAY_SIGNING_KEY_FILE"] == "/run/secrets/gateway_signing_key"
    # The public key is for the tools only; nothing else needs to check a token.
    users = [name for name, service in services.items() if "gateway_public_key" in service.get("secrets", [])]
    assert sorted(users) == sorted(TOOL_COMPONENTS.values())


def test_the_key_files_live_in_the_ignored_folder():
    secrets = compose()["secrets"]
    assert secrets["gateway_public_key"]["file"] == "./build/keys/gateway.pub"
    assert secrets["gateway_signing_key"]["file"] == "./build/keys/gateway.pem"
    ignored = subprocess.run(
        ["git", "check-ignore", "build/keys/gateway.pem", "build/keys/gateway.pub"],
        cwd=ROOT, capture_output=True, text=True, check=False,
    )
    assert ignored.stdout.split() == ["build/keys/gateway.pem", "build/keys/gateway.pub"]


def test_the_key_script_makes_a_pair_that_signs_and_verifies(tmp_path):
    env = {"KEY_DIR": str(tmp_path), "PATH": os.environ["PATH"]}
    run = lambda *args: subprocess.run(  # noqa: E731
        ["sh", "scripts/gen-gateway-key.sh", *args], cwd=ROOT, env=env, capture_output=True, text=True, check=False
    )
    first = run()
    assert first.returncode == 0, first.stderr
    private, public = load_private_key(tmp_path / "gateway.pem"), load_public_key(tmp_path / "gateway.pub")
    token = mint_tool_token(private, "read_ticket", "ab" * 32, 1_800_000_000.0)
    assert verify_tool_token(public, token, "read_ticket", 1_800_000_000.0, JtiCache())["lease"] == "ab" * 32
    kept = (tmp_path / "gateway.pem").read_bytes()
    assert run().returncode == 0 and (tmp_path / "gateway.pem").read_bytes() == kept     # keeps what exists
    assert run("--force").returncode == 0 and (tmp_path / "gateway.pem").read_bytes() != kept


def test_serve_refuses_to_start_without_the_public_key_or_with_a_wrong_name(monkeypatch):
    monkeypatch.setattr("sys.argv", ["serve", "read_ticket"])
    monkeypatch.delenv("GATEWAY_PUBLIC_KEY_FILE", raising=False)
    monkeypatch.delenv("TOOL_NAME", raising=False)
    with pytest.raises(SystemExit, match="GATEWAY_PUBLIC_KEY_FILE"):
        serve.main()
    monkeypatch.setenv("TOOL_NAME", "lookup_account")
    with pytest.raises(SystemExit, match="TOOL_NAME"):
        serve.main()
    monkeypatch.setattr("sys.argv", ["serve", "no_such_tool"])
    monkeypatch.delenv("TOOL_NAME")
    with pytest.raises(SystemExit, match="choose a tool"):
        serve.main()


def test_serve_takes_the_tool_from_tool_name_when_there_is_no_argument(monkeypatch):
    assert serve.tool_name(["serve"], {"TOOL_NAME": "read_ticket"}) == "read_ticket"
    assert serve.tool_name(["serve", "read_ticket"], {"TOOL_NAME": "read_ticket"}) == "read_ticket"


def test_serve_refuses_a_public_key_of_the_wrong_kind(monkeypatch, tmp_path):
    monkeypatch.setattr("sys.argv", ["serve", "read_ticket"])
    monkeypatch.delenv("TOOL_NAME", raising=False)
    junk = tmp_path / "junk.pub"
    junk.write_text("not a key")
    monkeypatch.setenv("GATEWAY_PUBLIC_KEY_FILE", str(junk))
    with pytest.raises(ValueError, match="PEM public key"):
        serve.main()
    # An RSA key is a key, but not the kind the gateway signs with.
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    rsa_public = rsa.generate_private_key(65537, 2048).public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    junk.write_bytes(rsa_public)
    with pytest.raises(ValueError, match="EC P-256"):
        serve.main()
