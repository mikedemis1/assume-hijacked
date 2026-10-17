"""PostgreSQL: who can do what in one database, read from the system catalogs.

Generic on purpose: nothing here names a table, role or function of this application, so new
objects show up without a code change. What is read (catalog docs:
https://www.postgresql.org/docs/17/catalogs.html, ACLs: https://www.postgresql.org/docs/17/ddl-priv.html):

  roles           every role except the built-in pg_* roles and the bootstrap superuser (the
                  role that runs the database scripts, oid 10): LOGIN, SUPERUSER, CREATEDB,
                  CREATEROLE, REPLICATION, BYPASSRLS, NOINHERIT, CONNECTION LIMIT
  memberships     GRANT <role> TO <role>, with ADMIN / INHERIT FALSE / SET FALSE
  privileges      database, schemas, tables / views / sequences, columns, functions. A NULL
                  ACL means the built-in default (acldefault), which for functions is EXECUTE
                  for PUBLIC. PUBLIC is expanded: each role gets its own line, marked
                  (via PUBLIC), so a PUBLIC grant shows as what it is, a grant to everyone.
                  pg_catalog functions are read only when their ACL was changed (the advisory
                  locks); grants an owner holds on its own object are implied, not listed.
  ownership       objects owned by anyone but the bootstrap superuser or a built-in role, and
                  every SECURITY DEFINER function with its owner, whoever that is: the function
                  runs with that owner's rights
  row security    ENABLE / FORCE ROW LEVEL SECURITY per table, and each policy per role it
                  applies to, with its USING and WITH CHECK expressions
  defaults        ALTER DEFAULT PRIVILEGES, as the difference from the built-in defaults

Read-only: plain SELECTs on the catalogs. Runs inside the caller's transaction, so a test can
GRANT in a transaction, collect, and roll back.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any

from psycopg.rows import tuple_row

from secops.permassess import canon

BOOTSTRAP_OID = 10
_USER_SCHEMA = "n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'"
_REL_KINDS = {"r": "TABLE", "p": "TABLE", "v": "VIEW", "m": "MATERIALIZED VIEW",
              "S": "SEQUENCE", "f": "FOREIGN TABLE"}
_DEFACL_KINDS = {"r": "TABLES", "S": "SEQUENCES", "f": "FUNCTIONS", "T": "TYPES",
                 "n": "SCHEMAS", "L": "LARGE OBJECTS"}
_POLCMD = {"*": "ALL", "r": "SELECT", "a": "INSERT", "w": "UPDATE", "d": "DELETE"}


def _rows(conn: Any, sql: str) -> list[tuple]:
    with conn.cursor(row_factory=tuple_row) as cur:
        cur.execute(sql)
        return list(cur.fetchall())


class _Roles:
    def __init__(self, conn: Any) -> None:
        self.names: dict[int, str] = dict(_rows(conn, "SELECT oid, rolname FROM pg_catalog.pg_roles"))
        self.bootstrap = self.names[BOOTSTRAP_OID]
        # The roles PUBLIC expands to, and the subjects of attribute lines.
        self.assessed = {oid: name for oid, name in self.names.items()
                         if oid != BOOTSTRAP_OID and not name.startswith("pg_")}

    def builtin(self, oid: int) -> bool:
        return oid == BOOTSTRAP_OID or self.names.get(oid, "").startswith("pg_")


def _attribute_lines(conn: Any, roles: _Roles) -> list[str]:
    out = []
    for (oid, name, sup, inherit, createrole, createdb, login, repl, bypass, limit) in _rows(conn, """
            SELECT oid, rolname, rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolcanlogin,
                   rolreplication, rolbypassrls, rolconnlimit
            FROM pg_catalog.pg_roles"""):
        if oid not in roles.assessed:
            continue
        out.append(canon.pg_role(name, canon.attributes(
            login, superuser=sup, createdb=createdb, createrole=createrole, replication=repl,
            bypassrls=bypass, inherit=inherit, connection_limit=limit)))
    return out


def _membership_lines(conn: Any, roles: _Roles) -> list[str]:
    out = []
    for member, group, admin, inherit, set_ in _rows(conn, """
            SELECT member, roleid, admin_option, inherit_option, set_option
            FROM pg_catalog.pg_auth_members"""):
        if member not in roles.assessed:
            continue
        text = f"MEMBER OF {roles.names[group]}"
        if admin:
            text += " WITH ADMIN OPTION"
        if not inherit:
            text += " WITH INHERIT FALSE"
        if not set_:
            text += " WITH SET FALSE"
        out.append(canon.pg_role(roles.names[member], text))
    return out


def _acl_lines(roles: _Roles, target: str, owner: int, entries: list[tuple],
               column: str | None = None, skip_builtin_grantees: bool = False) -> list[str]:
    """entries: (grantee oid, privilege, grantable). PUBLIC (oid 0) is expanded."""
    out = []
    for grantee, priv, grantable in entries:
        if grantee is None or grantee == owner or grantee == BOOTSTRAP_OID:
            continue
        text = canon.grant_text(priv, target, column, grantable)
        if grantee == 0:
            out.extend(canon.pg_role(r, text, via_public=True) for r in roles.assessed.values())
        elif skip_builtin_grantees and roles.builtin(grantee):
            continue
        else:
            out.append(canon.pg_role(roles.names.get(grantee, str(grantee)), text))
    return out


def _grouped(rows: list[tuple], key_len: int) -> dict[tuple, list[tuple]]:
    groups: dict[tuple, list[tuple]] = defaultdict(list)
    for row in rows:
        groups[row[:key_len]].append(row[key_len:])
    return groups


def _privilege_lines(conn: Any, roles: _Roles) -> list[str]:
    out: list[str] = []
    db = _rows(conn, """
        SELECT d.datdba, a.grantee, a.privilege_type, a.is_grantable
        FROM pg_catalog.pg_database d,
             aclexplode(coalesce(d.datacl, acldefault('d', d.datdba))) a
        WHERE d.datname = current_database()""")
    for (owner,), entries in _grouped(db, 1).items():
        out += _acl_lines(roles, "DATABASE", owner, entries)

    schemas = _rows(conn, f"""
        SELECT n.nspname, n.nspowner, a.grantee, a.privilege_type, a.is_grantable
        FROM pg_catalog.pg_namespace n,
             aclexplode(coalesce(n.nspacl, acldefault('n', n.nspowner))) a
        WHERE {_USER_SCHEMA}""")
    for (name, owner), entries in _grouped(schemas, 2).items():
        out += _acl_lines(roles, f"SCHEMA {name}", owner, entries)

    relations = _rows(conn, f"""
        SELECT n.nspname || '.' || c.relname, c.relowner, a.grantee, a.privilege_type, a.is_grantable
        FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace,
             aclexplode(coalesce(c.relacl,
                acldefault(CASE WHEN c.relkind = 'S' THEN 's' ELSE 'r' END::"char", c.relowner))) a
        WHERE c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f') AND {_USER_SCHEMA}""")
    for (name, owner), entries in _grouped(relations, 2).items():
        out += _acl_lines(roles, name, owner, entries)

    columns = _rows(conn, f"""
        SELECT n.nspname || '.' || c.relname, att.attname, c.relowner,
               a.grantee, a.privilege_type, a.is_grantable
        FROM pg_catalog.pg_attribute att
             JOIN pg_catalog.pg_class c ON c.oid = att.attrelid
             JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace,
             aclexplode(att.attacl) a
        WHERE att.attacl IS NOT NULL AND att.attnum > 0 AND NOT att.attisdropped
          AND {_USER_SCHEMA}""")
    for (name, column, owner), entries in _grouped(columns, 3).items():
        out += _acl_lines(roles, name, owner, entries, column=column)

    functions = _rows(conn, f"""
        SELECT n.nspname || '.' || p.proname || '(' || pg_catalog.oidvectortypes(p.proargtypes) || ')',
               p.proowner, n.nspname = 'pg_catalog', a.grantee, a.privilege_type, a.is_grantable
        FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace,
             aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
        WHERE ({_USER_SCHEMA}) OR (n.nspname = 'pg_catalog' AND p.proacl IS NOT NULL)""")
    for (name, owner, system), entries in _grouped(functions, 3).items():
        out += _acl_lines(roles, f"FUNCTION {name}", owner, entries, skip_builtin_grantees=system)
    return out


def _ownership_lines(conn: Any, roles: _Roles) -> list[str]:
    out = []
    for name, owner in _rows(conn, f"""
            SELECT n.nspname, n.nspowner FROM pg_catalog.pg_namespace n WHERE {_USER_SCHEMA}"""):
        if not roles.builtin(owner):
            out.append(canon.pg_role(roles.names[owner], f"OWNS SCHEMA {name}"))
    for name, kind, owner in _rows(conn, f"""
            SELECT n.nspname || '.' || c.relname, c.relkind, c.relowner
            FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
            WHERE c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f') AND {_USER_SCHEMA}"""):
        if not roles.builtin(owner):
            out.append(canon.pg_role(roles.names[owner], f"OWNS {_REL_KINDS[kind]} {name}"))
    for name, owner, definer in _rows(conn, f"""
            SELECT n.nspname || '.' || p.proname || '(' || pg_catalog.oidvectortypes(p.proargtypes) || ')',
                   p.proowner, p.prosecdef
            FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
            WHERE {_USER_SCHEMA}"""):
        if definer or not roles.builtin(owner):
            text = f"OWNS FUNCTION {name}" + (" SECURITY DEFINER" if definer else "")
            out.append(canon.pg_role(roles.names[owner], text))
    return out


def _rls_lines(conn: Any, roles: _Roles) -> list[str]:
    out = []
    for name, enabled, forced in _rows(conn, f"""
            SELECT n.nspname || '.' || c.relname, c.relrowsecurity, c.relforcerowsecurity
            FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
            WHERE (c.relrowsecurity OR c.relforcerowsecurity) AND {_USER_SCHEMA}"""):
        out.append(canon.pg_table(name, canon.rls_text(enabled, forced)))
    for relation, polname, cmd, permissive, polroles, using, check in _rows(conn, """
            SELECT n.nspname || '.' || c.relname, p.polname, p.polcmd, p.polpermissive,
                   p.polroles::oid[], pg_catalog.pg_get_expr(p.polqual, p.polrelid),
                   pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid)
            FROM pg_catalog.pg_policy p
                 JOIN pg_catalog.pg_class c ON c.oid = p.polrelid
                 JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace"""):
        text = canon.policy_text(polname, relation, _POLCMD.get(str(cmd), str(cmd)), permissive,
                                 using, check)
        for oid in polroles:
            if oid == 0:
                out.extend(canon.pg_role(r, text, via_public=True) for r in roles.assessed.values())
            else:
                out.append(canon.pg_role(roles.names.get(oid, str(oid)), text))
    return out


def _default_privilege_lines(conn: Any, roles: _Roles) -> list[str]:
    heads = {oid: (role, schema, kind) for oid, role, schema, kind in _rows(conn, """
        SELECT d.oid, d.defaclrole, n.nspname, d.defaclobjtype
        FROM pg_catalog.pg_default_acl d
             LEFT JOIN pg_catalog.pg_namespace n ON n.oid = d.defaclnamespace""")}
    granted = _grouped(_rows(conn, """
        SELECT d.oid, a.grantee, a.privilege_type, a.is_grantable
        FROM pg_catalog.pg_default_acl d, aclexplode(d.defaclacl) a"""), 1)
    # A global row (no schema) replaces the built-in default; compare with it.
    builtin = _grouped(_rows(conn, """
        SELECT d.oid, a.grantee, a.privilege_type, a.is_grantable
        FROM pg_catalog.pg_default_acl d,
             aclexplode(acldefault(CASE d.defaclobjtype WHEN 'S' THEN 's'
                                   ELSE d.defaclobjtype END::"char", d.defaclrole)) a
        WHERE d.defaclnamespace = 0"""), 1)
    out = []
    for oid, (role, schema, kind) in heads.items():
        prefix = "DEFAULT PRIVILEGES " + (f"IN SCHEMA {schema} " if schema else "")
        prefix += f"ON {_DEFACL_KINDS.get(str(kind), str(kind))} "
        now = set(granted.get((oid,), []))
        before = set(builtin.get((oid,), [])) if schema is None else set()

        def who(grantee: int) -> str:
            return "PUBLIC" if grantee == 0 else roles.names.get(grantee, str(grantee))

        for grantee, priv, grantable in now - before:
            if schema is None and grantee == role:
                continue  # the owner's own rights on what it creates
            text = f"GRANT {priv} TO {who(grantee)}" + (canon.GRANT_OPTION if grantable else "")
            out.append(canon.pg_role(roles.names[role], prefix + text))
        for grantee, priv, _ in before - now:
            if any(g == grantee and p == priv for g, p, _ in now):
                continue  # only the grant option changed; the GRANT line above says so
            out.append(canon.pg_role(roles.names[role], prefix + f"REVOKE {priv} FROM {who(grantee)}"))
    return out


def collect(conn: Any) -> list[str]:
    """Every permission line of the connected database, sorted, without duplicates."""
    roles = _Roles(conn)
    lines: set[str] = set()
    for part in (_attribute_lines, _membership_lines, _privilege_lines, _ownership_lines,
                 _rls_lines, _default_privilege_lines):
        lines.update(part(conn, roles))
    return sorted(lines)
