"""The capability manifests (permissions/*.json): what each component may do, written
down so the tests below can compare it with the real database.

These tests check the manifests against the application itself: the fingerprint of every tool
descriptor, the grants of every database role, and who holds the gateway's keys.
"""

import asyncio
import copy
import hashlib
import json
import time
from pathlib import Path

import pytest

from app import config
from app.security import descriptors
from app.security.tokens import mint_tool_token
from app.tools import serve
from tests.toolhttp import KEYS, bearer, post_each

ROOT = Path(__file__).resolve().parent.parent
CAPABILITIES = ROOT / "permissions"
TOOL_COMPONENTS = {tool: "tool-" + tool.replace("_", "-") for tool in serve.TOOLS}
# Keys a manifest may have. The first test below rejects any other, so a typo cannot drop a
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


def test_the_database_setup_job_has_a_manifest_that_matches_its_chart_and_grants():
    """db-migrate runs only in Azure. Its manifest must agree with the chart (service account,
    namespace-independent name) and with the vault rule: Secrets Officer on the vault of every
    component that has a database role, and nothing else."""
    found = manifests()
    manifest = found["db-migrate"]
    assert manifest["k8s"]["service_account"] == "db-migrate"
    assert manifest["db"]["role"] is None  # it signs in as the Entra administrator
    granted = {r["scope"] for r in manifest["azure"]["roles"]}
    assert {r["role"] for r in manifest["azure"]["roles"]} == {"Key Vault Secrets Officer"}
    wanted = {"kv-" + name for name, m in found.items() if m["db"]["role"] and name != "db"}
    assert granted == wanted
    assert manifest["network"]["ingress_from"] == []
    assert set(manifest["network"]["egress_to"]) == {"db", "internet"}


def test_every_component_has_exactly_one_manifest():
    assert set(manifests()) == {
        "agent", "console", "db-migrate", "db", "dispatcher", "executor", "llm-gateway", "risk-engine",
        "tool-gateway", "tool-issue-bill-credit", "tool-lookup-account", "tool-read-ticket",
        "tool-request-disconnection", "tool-set-temp-protection",
    }


def test_every_tool_and_the_database_has_a_manifest():
    found = manifests()
    assert set(TOOL_COMPONENTS.values()) <= set(found)
    assert {"db", "agent", "executor", "risk-engine", "tool-gateway", "llm-gateway"} <= set(found)


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
        app = serve.build_app(tool, config.load(), public)
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
    # A tool is called by the gateway and by nothing else (the agent has no edge to it).
    assert manifests()[component]["network"] == {
        "ingress_from": ["tool-gateway"], "egress_to": ["db"], "dns": ["cluster"]
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


# --- every manifest against the real grants ---------------------------------------------------

TABLE_PRIVILEGES = ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")
SEQUENCE_PRIVILEGES = ("USAGE", "SELECT", "UPDATE")
SCHEMA_PRIVILEGES = ("USAGE", "CREATE")
ROLE_COMPONENTS = {m["db"]["role"]: name for name, m in manifests().items() if m["db"]["role"]}


def manifest_tables(grants: dict[str, list[str]]) -> tuple[set, set]:
    """What a manifest's "tables" says, as (whole-table grants, column grants):
    "SELECT" -> (table, SELECT); "INSERT (a, b)" -> (table, INSERT, a) and (table, INSERT, b)."""
    whole, columns = set(), set()
    for table, entries in grants.items():
        for entry in entries:
            privilege, _, cols = entry.partition(" (")
            if cols:
                columns |= {(table, privilege, c.strip()) for c in cols.rstrip(")").split(",")}
            else:
                whole.add((table, privilege))
    return whole, columns


def real_tables(admin, role: str) -> tuple[set, set]:
    """What the database lets the role do with the tables, views and sequences of schema public, as
    manifest_tables() reads a manifest. has_*_privilege counts what is inherited and what PUBLIC holds."""
    whole, columns = set(), set()
    relations = admin.execute(
        "SELECT oid, relname, relkind FROM pg_class WHERE relnamespace = 'public'::regnamespace "
        "AND relkind IN ('r', 'p', 'v', 'm', 'f', 'S')"
    ).fetchall()
    for rel in relations:
        if rel["relkind"] == "S":
            whole |= {
                (rel["relname"], privilege) for privilege in SEQUENCE_PRIVILEGES
                if admin.execute("SELECT has_sequence_privilege(%s, %s, %s) AS ok",
                                 (role, rel["oid"], privilege)).fetchone()["ok"]
            }
            continue
        held = {
            privilege for privilege in TABLE_PRIVILEGES
            if admin.execute("SELECT has_table_privilege(%s, %s, %s) AS ok",
                             (role, rel["oid"], privilege)).fetchone()["ok"]
        }
        whole |= {(rel["relname"], privilege) for privilege in held}
        for privilege in set(TABLE_PRIVILEGES) - held - {"DELETE", "TRUNCATE", "TRIGGER"}:
            rows = admin.execute(
                "SELECT a.attname FROM pg_attribute a WHERE a.attrelid = %s AND a.attnum > 0 "
                "AND NOT a.attisdropped AND has_column_privilege(%s, a.attrelid, a.attnum, %s)",
                (rel["oid"], role, privilege),
            ).fetchall()
            columns |= {(rel["relname"], privilege, r["attname"]) for r in rows}
    return whole, columns


def functions_the_role_can_run(admin, role: str) -> set[int]:
    """Oids of the functions of public the role can execute, and of the ones in pg_catalog that
    carry an explicit ACL (the advisory locks, which the schema closes to PUBLIC)."""
    rows = admin.execute(
        "SELECT p.oid FROM pg_proc p WHERE has_function_privilege(%s, p.oid, 'EXECUTE') AND "
        "(p.pronamespace = 'public'::regnamespace OR "
        " (p.pronamespace = 'pg_catalog'::regnamespace AND p.proacl IS NOT NULL))",
        (role,),
    ).fetchall()
    return {r["oid"] for r in rows}


def manifest_functions(admin, execute: list[str]) -> set[int]:
    """Oids of the functions a manifest names; the database reads the spelling (int, spaces, schema)."""
    oids = set()
    for text in execute:
        qualified = text if "." in text.split("(")[0] else f"public.{text}"
        row = admin.execute("SELECT to_regprocedure(%s)::oid AS oid", (qualified,)).fetchone()
        assert row["oid"], f"the manifest names a function the database does not have: {text}"
        oids.add(row["oid"])
    return oids


def function_names(admin, oids: set[int]) -> list[str]:
    return sorted(r["f"] for r in admin.execute(
        "SELECT oid::regprocedure::text AS f FROM pg_proc WHERE oid = ANY(%s)", (list(oids),)).fetchall())


@pytest.mark.parametrize("role", sorted(ROLE_COMPONENTS))
def test_db_grants_match_the_manifest_of_each_login_role(admin, role):
    manifest = manifests()[ROLE_COMPONENTS[role]]["db"]
    row = admin.execute("SELECT rolcanlogin, rolconnlimit FROM pg_roles WHERE rolname = %s", (role,)).fetchone()
    assert row == {"rolcanlogin": manifest["login"], "rolconnlimit": manifest["connection_limit"]}
    can_run, named = functions_the_role_can_run(admin, role), manifest_functions(admin, manifest["execute"])
    assert can_run == named, (
        "can run but not in the manifest:", function_names(admin, can_run - named),
        "in the manifest but cannot run:", function_names(admin, named - can_run))
    assert real_tables(admin, role) == manifest_tables(manifest["tables"])
    schemas = admin.execute(
        "SELECT nspname FROM pg_namespace WHERE nspname !~ '^pg_' AND nspname <> 'information_schema'"
    ).fetchall()
    for schema in (r["nspname"] for r in schemas):
        held = sorted(
            p for p in SCHEMA_PRIVILEGES
            if admin.execute("SELECT has_schema_privilege(%s, %s, %s) AS ok", (role, schema, p)).fetchone()["ok"]
        )
        assert held == sorted(manifest["schemas"].get(schema, [])), schema


def test_every_login_role_has_a_manifest(admin):
    logins = {
        r["rolname"] for r in admin.execute(
            "SELECT rolname FROM pg_roles WHERE rolcanlogin AND rolname !~ '^pg_'"
        ).fetchall()
    }
    assert logins - {"postgres"} == set(ROLE_COMPONENTS)


# --- who holds the gateway's keys --------------------------------------------------------------

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


# --- the tool gateway: its manifest, its edges, its key ---------------------------------------

def test_the_gateway_manifest_matches_its_database_role(admin):
    manifest = manifests()["tool-gateway"]["db"]
    role = admin.execute(
        "SELECT rolcanlogin, rolconnlimit FROM pg_roles WHERE rolname = %s", (manifest["role"],)
    ).fetchone()
    assert role == {"rolcanlogin": True, "rolconnlimit": manifest["connection_limit"]}
    granted = [f.removeprefix("public.") for f in granted_functions(admin, manifest["role"])]
    assert granted == [f.replace(" ", "") for f in manifest["execute"]]
    # Its table rights, read from the catalog: the stop switch (read), the record of calls (add rows).
    rows = admin.execute(
        "SELECT table_name, privilege_type FROM information_schema.role_table_grants "
        "WHERE grantee = %s AND table_schema = 'public' ORDER BY 1, 2",
        (manifest["role"],),
    ).fetchall()
    assert {(r["table_name"], r["privilege_type"]) for r in rows} == {("agent_control", "SELECT")}
    columns = admin.execute(
        "SELECT table_name, column_name, privilege_type FROM information_schema.column_privileges "
        "WHERE grantee = %s AND table_schema = 'public' AND privilege_type <> 'SELECT' ORDER BY 2",
        (manifest["role"],),
    ).fetchall()
    assert {(r["table_name"], r["privilege_type"]) for r in columns} == {("tool_calls", "INSERT")}
    assert sorted(r["column_name"] for r in columns) == sorted(
        ["arg_names", "dropped_args", "lease_hash", "outcome", "reason", "tool"]
    )


def test_the_agent_manifest_names_its_three_edges():
    assert manifests()["agent"]["network"]["egress_to"] == ["dispatcher", "llm-gateway", "tool-gateway"]


def test_a_tool_serves_healthz_on_9000_while_it_runs(monkeypatch, tmp_path):
    import urllib.request

    _, public = KEYS
    key = tmp_path / "gateway.pub"
    key.write_bytes(public)
    monkeypatch.setattr("sys.argv", ["serve", "read_ticket"])
    monkeypatch.delenv("TOOL_NAME", raising=False)
    monkeypatch.setenv("GATEWAY_PUBLIC_KEY_FILE", str(key))
    started = {}
    real = serve.start_ops_server
    monkeypatch.setattr(
        serve, "start_ops_server",
        lambda port, metrics, heartbeat: started.update(port=port, heartbeat=heartbeat, server=real(0, metrics, heartbeat)),
    )
    monkeypatch.setattr(serve.uvicorn, "run", lambda *args, **kwargs: started.update(run=kwargs))
    serve.main()
    try:
        assert started["port"] == 9000 and started["run"]["port"] == 8000
        url = f"http://127.0.0.1:{started['server'].port}/healthz"
        assert urllib.request.urlopen(url, timeout=5).status == 200
        # A tool has no loop to age: even a very late clock does not make the probe fail.
        assert started["heartbeat"].alive(started["heartbeat"].clock() + 10 ** 9)
    finally:
        started["server"].shutdown()


# --- the dispatcher: its manifest, its edges, its subnet ------------------------------------------

def test_the_dispatcher_manifest_names_its_edges_and_its_kubernetes_rights():
    manifest = manifests()["dispatcher"]
    assert manifest["network"] == {"ingress_from": ["agent"], "egress_to": ["db"], "dns": ["cluster"]}
    # Creating Jobs and reviewing tokens: nothing else in the cluster (the chart's Role and ClusterRole).
    assert manifest["k8s"] == {"service_account": "dispatcher",
                               "rbac": ["create jobs.batch in ah-agent", "create tokenreviews.authentication.k8s.io"]}
    assert manifest["db"]["role"] == "dispatcher"


# --- the LLM gateway: its manifest, its edge, its subnet, the only place a model key can be ---------------

def test_the_llm_gateway_manifest_names_its_edge_and_its_rights():
    manifest = manifests()["llm-gateway"]
    assert manifest["db"]["role"] is None and manifest["db"]["execute"] == [] and manifest["db"]["tables"] == {}
    # Only the agent calls it, and as shipped it calls nobody (a real provider is the cluster's
    # host-name policy; see the description).
    assert manifest["network"] == {"ingress_from": ["agent"], "egress_to": [], "dns": ["cluster"]}
    assert manifest["k8s"] == {"service_account": "llm-gateway", "rbac": ["create tokenreviews.authentication.k8s.io"]}
    assert manifest["azure"]["identity"] == "id-llm-gateway"
    assert {(r["role"], r["scope"]) for r in manifest["azure"]["roles"]} == {
        ("Key Vault Secrets User", "kv-llm-gateway")}
    assert manifest["runtime_class"] == "runc" and manifest["mcp"] == {"tools": []}
    assert "provider" in manifest["description"].lower()


def test_no_other_manifest_gives_a_component_a_model_role():
    for name, manifest in manifests().items():
        roles = {r["role"] for r in manifest["azure"]["roles"]}
        # The checked-in configuration is scripted. Activation derives paid-provider grants.
        assert "Cognitive Services User" not in roles, name
        assert ("kv-llm-gateway" in {r["scope"] for r in manifest["azure"]["roles"]}) == (name == "llm-gateway"), name
