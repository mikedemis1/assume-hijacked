"""The one text form of a permission line, shared by the collectors and the generator.

A line names its subject first, so sorted lines group by role, table or component:

    pg role tool_read_ticket: ATTRIBUTES LOGIN, CONNECTION LIMIT 5
    pg role tool_read_ticket: SELECT (body) ON public.tickets
    pg role tool_read_ticket: EXECUTE ON FUNCTION public.f(integer) (via PUBLIC)
    pg role flags_writer: OWNS FUNCTION public.set_temp_protection(integer) SECURITY DEFINER
    pg table public.tickets: ROW LEVEL SECURITY, FORCED
    compose agent <-> tool-read-ticket
    k8s agent -> tool-gateway
    k8s serviceaccount dispatcher: create jobs.batch
    azure identity id-executor: Key Vault Secrets User on kv-executor

Function signatures are the argument types as PostgreSQL prints them (oidvectortypes), so a
manifest may write `f(int)` and the line says `public.f(integer)`.
"""
from __future__ import annotations

import re

VIA_PUBLIC = " (via PUBLIC)"
GRANT_OPTION = " WITH GRANT OPTION"

# PostgreSQL's own spelling of the common type aliases (format_type output).
_TYPE_ALIASES = {
    "int": "integer", "int4": "integer", "int8": "bigint", "int2": "smallint",
    "bool": "boolean", "varchar": "character varying", "char": "character",
    "float8": "double precision", "float4": "real", "float": "double precision",
    "decimal": "numeric", "timestamptz": "timestamp with time zone",
    "timestamp": "timestamp without time zone", "timetz": "time with time zone",
    "time": "time without time zone",
}
_SIGNATURE = re.compile(r"^\s*([A-Za-z_][\w$]*(?:\.[A-Za-z_][\w$]*)?)\s*\((.*)\)\s*$")
PRIVILEGES = ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER",
              "MAINTAIN", "USAGE", "EXECUTE", "CREATE", "CONNECT", "TEMPORARY")
_PRIVILEGE = re.compile(
    r"^\s*([A-Za-z]+)\s*(?:\(([^)]*)\))?\s*((?i:WITH\s+GRANT\s+OPTION))?\s*$")
_SPACES = re.compile(r"\s+")


class CanonError(ValueError):
    """A manifest value that has no canonical form (unknown privilege, bad signature)."""


def squash(text: str) -> str:
    return _SPACES.sub(" ", text).strip()


def qualify(name: str, schema: str = "public") -> str:
    """`tickets` -> `public.tickets`; a qualified name stays as it is."""
    name = name.strip()
    return name if "." in name else f"{schema}.{name}"


def _type(text: str) -> str:
    t = squash(text).lower()
    array = ""
    while t.endswith("[]"):
        array += "[]"
        t = t[:-2].strip()
    return _TYPE_ALIASES.get(t, t) + array


def signature(text: str) -> str:
    """`set_temp_protection(int)` -> `public.set_temp_protection(integer)`."""
    m = _SIGNATURE.match(text)
    if not m:
        raise CanonError(f"not a function signature: {text!r} (expected name(type, ...))")
    name, args = m.groups()
    types = [_type(a) for a in args.split(",")] if args.strip() else []
    return f"{qualify(name)}({', '.join(types)})"


def privilege(text: str) -> tuple[str, list[str] | None, bool]:
    """`INSERT (kind, detail)` -> ("INSERT", ["kind", "detail"], False)."""
    m = _PRIVILEGE.match(text)
    if not m:
        raise CanonError(f"not a privilege: {text!r} (expected e.g. SELECT or INSERT (a, b))")
    word = m.group(1).upper()
    word = "TEMPORARY" if word == "TEMP" else word
    if word not in PRIVILEGES:
        raise CanonError(f"unknown privilege {word!r} in {text!r}")
    columns = [c.strip() for c in m.group(2).split(",")] if m.group(2) is not None else None
    if columns is not None and (not columns or any(not c for c in columns)):
        raise CanonError(f"empty column list in {text!r}")
    return word, columns, m.group(3) is not None


def attributes(login: bool, *, superuser: bool = False, createdb: bool = False,
               createrole: bool = False, replication: bool = False, bypassrls: bool = False,
               inherit: bool = True, connection_limit: int = -1) -> str:
    parts = ["LOGIN" if login else "NOLOGIN"]
    for on, word in ((superuser, "SUPERUSER"), (createdb, "CREATEDB"),
                     (createrole, "CREATEROLE"), (replication, "REPLICATION"),
                     (bypassrls, "BYPASSRLS"), (not inherit, "NOINHERIT")):
        if on:
            parts.append(word)
    if connection_limit != -1:
        parts.append(f"CONNECTION LIMIT {connection_limit}")
    return "ATTRIBUTES " + ", ".join(parts)


def pg_role(role: str, what: str, via_public: bool = False) -> str:
    return f"pg role {role}: {what}{VIA_PUBLIC if via_public else ''}"


def pg_table(relation: str, what: str) -> str:
    return f"pg table {relation}: {what}"


def grant_text(priv: str, target: str, column: str | None = None, grantable: bool = False) -> str:
    """`SELECT (id) ON public.tickets`, `USAGE ON SCHEMA public`, `CONNECT ON DATABASE`."""
    col = f" ({column})" if column is not None else ""
    return f"{priv}{col} ON {target}{GRANT_OPTION if grantable else ''}"


def rls_text(enabled: bool, forced: bool) -> str:
    text = "ROW LEVEL SECURITY" if enabled else "ROW LEVEL SECURITY OFF"
    return text + (", FORCED" if forced else "")


def policy_text(name: str, relation: str, command: str, permissive: bool,
                using: str | None, check: str | None) -> str:
    text = f"POLICY {name} ON {relation}"
    if not permissive:
        text += " AS RESTRICTIVE"
    text += f" FOR {command.upper()}"
    if using is not None:
        text += f" USING ({using})"
    if check is not None:
        text += f" WITH CHECK ({check})"
    return text


def edge(source: str, target: str) -> str:
    return f"{source} -> {target}"


def split_edge(line: str) -> tuple[str, str]:
    source, _, target = line.partition(" -> ")
    return source, target
