"""Build the expected permission lines from the capability manifests.

    python -m secops.permassess.expected --capabilities security/capabilities \
        --out security/expected-permissions.json [--check]

One manifest per component, `<component>.json`. The keys this generator reads (any other key is
an error, so a typo cannot silently drop a permission):

    component        must equal the file name without .json
    description      free text
    db               the component's database role, as a role spec (below), plus optionally:
                       roles   more role specs: roles no component logs in as, such as the
                               NOLOGIN owners of SECURITY DEFINER functions
                       public  a role spec without `role`: what PUBLIC holds. Every role in the
                               expected file gets these lines, marked (via PUBLIC), the same way
                               the collector expands PUBLIC
                       rls     {"<table>": {"enabled": true, "forced": true, "policies": [
                                 {"name", "command", "roles", "using", "check", "permissive"}]}}
    network          ingress_from / egress_to: component names, `db`, or `internet`; dns
    k8s              service_account, rbac: ["<verb> <resource>", ...] as kubectl prints them
    azure            identity, roles: [{"role", "scope"}]; scope is the logical name
                     (the `workload` tag of the resource, else its name)
    runtime_class, mcp   read for the report and the unused-grant warning

A role spec:

    role                 role name (null: no database access)
    login                default true
    connection_limit     default -1 (none)
    attributes           any of SUPERUSER CREATEDB CREATEROLE REPLICATION BYPASSRLS NOINHERIT
    bootstrap_superuser  true for the role that runs the database scripts (postgres): its
                         attributes and PUBLIC lines are not checked, only what is listed
    member_of            ["<role>", "<role> WITH ADMIN OPTION"]
    database             ["CONNECT", "TEMPORARY", "CREATE"] on the assessed database
    schemas              {"<schema>": ["USAGE", "CREATE"]}
    tables               {"<table or sequence>": ["SELECT", "INSERT (a, b)", "USAGE"]},
                         `schema.table` or `table` (public)
    execute              ["<function>(<types>)"], `schema.f(int)` or `f(int)` (public)
    owns                 ["FUNCTION f(int) SECURITY DEFINER", "TABLE t", "SCHEMA s", ...]
    default_privileges   ["ON FUNCTIONS REVOKE EXECUTE FROM PUBLIC",
                          "IN SCHEMA s ON TABLES GRANT SELECT TO r"], as the collector prints
                         them: the difference from PostgreSQL's built-in defaults
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path, PurePosixPath
from typing import Any

from secops.permassess import canon

_TOP = {"component", "description", "db", "network", "k8s", "azure", "runtime_class", "mcp"}
_SPEC = {"role", "login", "connection_limit", "attributes", "bootstrap_superuser", "member_of",
         "database", "schemas", "tables", "execute", "owns", "default_privileges"}
_DB_EXTRA = {"roles", "public", "rls"}
_PUBLIC_SPEC = {"database", "schemas", "tables", "execute"}
_ATTRIBUTES = {"SUPERUSER", "CREATEDB", "CREATEROLE", "REPLICATION", "BYPASSRLS", "NOINHERIT"}
_OWN_KINDS = ("MATERIALIZED VIEW", "FOREIGN TABLE", "FUNCTION", "TABLE", "VIEW", "SEQUENCE",
              "SCHEMA")
_NETWORK = {"ingress_from", "egress_to", "dns"}
_RLS_TABLE = {"enabled", "forced", "policies"}
_POLICY = {"name", "command", "roles", "using", "check", "permissive"}


class ManifestError(ValueError):
    """A manifest that cannot be turned into expected lines."""


def _keys(where: str, data: Any, allowed: set[str]) -> dict:
    if not isinstance(data, dict):
        raise ManifestError(f"{where}: expected an object")
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise ManifestError(f"{where}: unknown key(s) {', '.join(unknown)}")
    return data


def _list(where: str, value: Any) -> list:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ManifestError(f"{where}: expected a list")
    return value


def load_manifests(directory: Path) -> list[dict]:
    if not directory.is_dir():
        raise ManifestError(f"{directory}: no such directory")
    manifests = []
    for path in sorted(directory.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ManifestError(f"{path.name}: not valid JSON ({exc})") from exc
        _keys(path.name, data, _TOP)
        if data.get("component") != path.stem:
            raise ManifestError(
                f"{path.name}: component is {data.get('component')!r}, the file name says "
                f"{path.stem!r}")
        manifests.append(data)
    if not manifests:
        raise ManifestError(f"{directory}: no *.json manifests")
    return manifests


def _grant_lines(where: str, spec: dict) -> list[str]:
    """The privilege part of a spec, without the role prefix."""
    out = []
    try:
        for priv in _list(f"{where}.database", spec.get("database")):
            word, cols, grantable = canon.privilege(priv)
            out.append(canon.grant_text(word, "DATABASE", None, grantable))
        schemas = _keys(f"{where}.schemas", spec.get("schemas") or {}, set(spec.get("schemas") or {}))
        for schema, privs in schemas.items():
            for priv in _list(f"{where}.schemas.{schema}", privs):
                word, cols, grantable = canon.privilege(priv)
                out.append(canon.grant_text(word, f"SCHEMA {schema}", None, grantable))
        tables = _keys(f"{where}.tables", spec.get("tables") or {}, set(spec.get("tables") or {}))
        for table, privs in tables.items():
            relation = canon.qualify(table)
            for priv in _list(f"{where}.tables.{table}", privs):
                word, cols, grantable = canon.privilege(priv)
                if cols is None:
                    out.append(canon.grant_text(word, relation, None, grantable))
                else:
                    out.extend(canon.grant_text(word, relation, c, grantable) for c in cols)
        for fn in _list(f"{where}.execute", spec.get("execute")):
            out.append(canon.grant_text("EXECUTE", f"FUNCTION {canon.signature(fn)}"))
    except canon.CanonError as exc:
        raise ManifestError(f"{where}: {exc}") from exc
    return out


def _owns(where: str, entry: str) -> str:
    text = canon.squash(entry)
    upper = text.upper()
    for kind in _OWN_KINDS:
        if upper.startswith(kind + " "):
            rest = text[len(kind) + 1:]
            definer = rest.upper().endswith(" SECURITY DEFINER")
            if definer:
                rest = rest[: -len(" SECURITY DEFINER")]
            try:
                if kind == "FUNCTION":
                    name = canon.signature(rest)
                elif kind == "SCHEMA":
                    name = rest.strip()
                else:
                    name = canon.qualify(rest)
            except canon.CanonError as exc:
                raise ManifestError(f"{where}: {exc}") from exc
            return f"OWNS {kind} {name}" + (" SECURITY DEFINER" if definer else "")
    raise ManifestError(f"{where}: cannot read owns entry {entry!r} (kind first, e.g. FUNCTION f(int))")


def _member(where: str, entry: str) -> str:
    text = canon.squash(entry)
    group, _, rest = text.partition(" ")
    if rest and rest.upper() not in {"WITH ADMIN OPTION", "WITH INHERIT FALSE", "WITH SET FALSE"}:
        raise ManifestError(f"{where}: cannot read member_of entry {entry!r}")
    return f"MEMBER OF {group}" + (f" {rest.upper()}" if rest else "")


def _spec_lines(where: str, spec: dict) -> tuple[str | None, list[str], bool]:
    """(role, lines, bootstrap) for one role spec."""
    _keys(where, spec, _SPEC)
    role = spec.get("role")
    if role is None:
        if any(spec.get(k) for k in _SPEC - {"role"}):
            raise ManifestError(f"{where}: privileges listed but role is null")
        return None, [], False
    bootstrap = bool(spec.get("bootstrap_superuser"))
    lines = []
    if not bootstrap:
        extra = [canon.squash(a).upper() for a in _list(f"{where}.attributes", spec.get("attributes"))]
        unknown = sorted(set(extra) - _ATTRIBUTES)
        if unknown:
            raise ManifestError(f"{where}: unknown attribute(s) {', '.join(unknown)}")
        limit = spec.get("connection_limit", -1)
        if not isinstance(limit, int):
            raise ManifestError(f"{where}.connection_limit: expected an integer")
        lines.append(canon.pg_role(role, canon.attributes(
            spec.get("login", True) is not False,
            superuser="SUPERUSER" in extra, createdb="CREATEDB" in extra,
            createrole="CREATEROLE" in extra, replication="REPLICATION" in extra,
            bypassrls="BYPASSRLS" in extra, inherit="NOINHERIT" not in extra,
            connection_limit=limit)))
    for entry in _list(f"{where}.member_of", spec.get("member_of")):
        lines.append(canon.pg_role(role, _member(where, entry)))
    lines.extend(canon.pg_role(role, g) for g in _grant_lines(where, spec))
    for entry in _list(f"{where}.owns", spec.get("owns")):
        lines.append(canon.pg_role(role, _owns(where, entry)))
    for entry in _list(f"{where}.default_privileges", spec.get("default_privileges")):
        lines.append(canon.pg_role(role, "DEFAULT PRIVILEGES " + canon.squash(entry)))
    return role, lines, bootstrap


def _rls(where: str, rls: dict) -> tuple[list[str], list[tuple[list[str], str]]]:
    """Table lines, and policy texts with the roles they apply to."""
    tables, policies = [], []
    for table, conf in _keys(where, rls, set(rls)).items():
        _keys(f"{where}.{table}", conf, _RLS_TABLE)
        relation = canon.qualify(table)
        tables.append(canon.pg_table(relation, canon.rls_text(conf.get("enabled", True) is not False,
                                                              bool(conf.get("forced")))))
        for i, pol in enumerate(_list(f"{where}.{table}.policies", conf.get("policies"))):
            _keys(f"{where}.{table}.policies[{i}]", pol, _POLICY)
            if not pol.get("name") or not pol.get("roles"):
                raise ManifestError(f"{where}.{table}.policies[{i}]: name and roles are required")
            text = canon.policy_text(pol["name"], relation, pol.get("command", "ALL"),
                                     pol.get("permissive", True) is not False,
                                     pol.get("using"), pol.get("check"))
            policies.append((list(pol["roles"]), text))
    return tables, policies


def build_expected(manifests: list[dict], source: str) -> dict:
    components: dict[str, dict] = {}
    pg: set[str] = set()
    public_grants: list[str] = []
    policies: list[tuple[list[str], str]] = []
    roles: dict[str, str] = {}  # role -> component that defines it
    expandable: set[str] = set()  # roles that PUBLIC lines expand to
    edges: set[str] = set()
    k8s: set[str] = set()
    azure: set[str] = set()

    for m in manifests:
        name = m["component"]
        db = m.get("db") or {}
        _keys(f"{name}.db", db, _SPEC | _DB_EXTRA)
        main = {k: v for k, v in db.items() if k in _SPEC}
        specs = [(f"{name}.db", main)] + [
            (f"{name}.db.roles[{i}]", s) for i, s in enumerate(_list(f"{name}.db.roles", db.get("roles")))]
        db_roles = []
        for where, spec in specs:
            role, lines, bootstrap = _spec_lines(where, spec)
            if role is None:
                continue
            if role in roles:
                raise ManifestError(f"{where}: role {role} is already defined by {roles[role]}")
            roles[role] = name
            db_roles.append(role)
            if not bootstrap:
                expandable.add(role)
            pg.update(lines)
        if db.get("public") is not None:
            _keys(f"{name}.db.public", db["public"], _PUBLIC_SPEC)
            public_grants.extend(_grant_lines(f"{name}.db.public", db["public"]))
        if db.get("rls") is not None:
            tables, pols = _rls(f"{name}.db.rls", db["rls"])
            pg.update(tables)
            policies.extend(pols)

        net = _keys(f"{name}.network", m.get("network") or {}, _NETWORK)
        for target in _list(f"{name}.network.egress_to", net.get("egress_to")):
            edges.add(canon.edge(name, target))
        for source_ in _list(f"{name}.network.ingress_from", net.get("ingress_from")):
            edges.add(canon.edge(source_, name))

        kube = _keys(f"{name}.k8s", m.get("k8s") or {}, {"service_account", "rbac"})
        sa = kube.get("service_account")
        for rule in _list(f"{name}.k8s.rbac", kube.get("rbac")):
            if not sa:
                raise ManifestError(f"{name}.k8s: rbac listed without a service_account")
            k8s.add(f"k8s serviceaccount {sa}: {canon.squash(rule)}")

        az = _keys(f"{name}.azure", m.get("azure") or {}, {"identity", "roles"})
        identity = az.get("identity")
        for i, r in enumerate(_list(f"{name}.azure.roles", az.get("roles"))):
            _keys(f"{name}.azure.roles[{i}]", r, {"role", "scope"})
            if not identity or not r.get("role") or not r.get("scope"):
                raise ManifestError(f"{name}.azure.roles[{i}]: identity, role and scope are required")
            azure.add(f"azure identity {identity}: {r['role']} on {r['scope']}")

        tools = [t.get("name") for t in _list(f"{name}.mcp.tools", (m.get("mcp") or {}).get("tools"))]
        components[name] = {
            "db_roles": db_roles,
            "service_account": sa,
            "azure_identity": identity,
            "runtime_class": m.get("runtime_class"),
            "mcp_tools": tools,
        }

    for grant in public_grants:
        pg.update(canon.pg_role(r, grant, via_public=True) for r in expandable)
    for policy_roles, text in policies:
        for r in policy_roles:
            if r.upper() == "PUBLIC":
                pg.update(canon.pg_role(x, text, via_public=True) for x in expandable)
            else:
                pg.add(canon.pg_role(r, text))

    return {
        "generated_by": f"python -m secops.permassess.expected --capabilities {source} "
                        "--out security/expected-permissions.json",
        "source": source,
        "components": dict(sorted(components.items())),
        "pg": sorted(pg),
        "edges": sorted(edges),
        "k8s": sorted(k8s),
        "azure": sorted(azure),
    }


def dumps(doc: dict) -> str:
    return json.dumps(doc, indent=1, sort_keys=False) + "\n"


def _source_name(directory: Path) -> str:
    try:
        rel = directory.resolve().relative_to(Path.cwd().resolve())
    except ValueError:
        rel = directory
    return str(PurePosixPath(*rel.parts)) if rel.parts else "."


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m secops.permassess.expected",
                                     description=__doc__.splitlines()[0])
    parser.add_argument("--capabilities", type=Path, default=Path("security/capabilities"))
    parser.add_argument("--out", type=Path, default=Path("security/expected-permissions.json"))
    parser.add_argument("--check", action="store_true",
                        help="do not write; exit 1 if the file differs from the manifests")
    args = parser.parse_args(argv)
    try:
        doc = build_expected(load_manifests(args.capabilities), _source_name(args.capabilities))
    except ManifestError as exc:
        print(f"expected: {exc}", file=sys.stderr)
        return 2
    text = dumps(doc)
    if args.check:
        current = args.out.read_text(encoding="utf-8") if args.out.exists() else ""
        if current != text:
            print(f"expected: {args.out} is not what {doc['source']} produces; run "
                  f"{doc['generated_by']}", file=sys.stderr)
            return 1
        print(f"expected: {args.out} matches {doc['source']}")
        return 0
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(text, encoding="utf-8", newline="\n")
    print(f"expected: wrote {args.out} from {doc['source']} ({len(doc['pg'])} pg lines, "
          f"{len(doc['edges'])} edges)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
