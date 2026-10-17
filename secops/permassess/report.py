"""The permission matrix: per component, what it can read, write and execute, and where it can
connect. Its blast radius, if it were hijacked.

    python -m secops.permassess.report --expected security/expected-permissions.json \
        --out docs/permission-matrix.md [--check]

The same renderer writes reports/permissions/matrix.md from what the collectors found.
It counts what a role really reaches, not only what is granted to it by name:

  - a SECURITY DEFINER function runs with its owner's rights, so a role that may execute one,
    by name or through PUBLIC, also reaches whatever the owner can read and write; an owner
    that is a superuser reaches everything
  - a role inherits the privileges of the roles it is a member of (unless the membership is
    WITH INHERIT FALSE), and of their memberships in turn; pg_read_all_data and
    pg_write_all_data read or write every table
  - the owner of a table, view or sequence holds every privilege on it, and may execute the
    functions it owns
  - a superuser reaches everything
"""
from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from secops.permassess import canon

_LINE = re.compile(r"^pg role (?P<role>\S+): (?P<what>.*?)(?P<public> \(via PUBLIC\))?$")
_GRANT = re.compile(r"^(?P<priv>[A-Z]+)(?: \((?P<col>[^)]+)\))? ON (?P<target>.+?)"
                    r"(?P<opt> WITH GRANT OPTION)?$")
_WRITES = ("INSERT", "UPDATE", "DELETE", "TRUNCATE")
_OWNED_DATA = ("TABLE ", "VIEW ", "MATERIALIZED VIEW ", "FOREIGN TABLE ", "SEQUENCE ")
OWNER = "OWNER"  # the privilege key for an owned relation: every privilege
EVERYTHING = "everything (superuser)"
# Built-in roles whose membership reads or writes every table.
_PREDEFINED_READS = {"pg_read_all_data": "every table, view and sequence (pg_read_all_data)"}
_PREDEFINED_WRITES = {"pg_write_all_data": "every table, view and sequence (pg_write_all_data)"}


@dataclass
class RoleView:
    attributes: str = ""
    reads: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    writes: dict[tuple[str, str], set[str]] = field(default_factory=lambda: defaultdict(set))
    executes: set[str] = field(default_factory=set)
    public_executes: set[str] = field(default_factory=set)
    public: list[str] = field(default_factory=list)
    other: list[str] = field(default_factory=list)
    member_of: list[str] = field(default_factory=list)
    inherits: list[str] = field(default_factory=list)
    owns: list[str] = field(default_factory=list)
    policies: list[str] = field(default_factory=list)
    defaults: list[str] = field(default_factory=list)

    @property
    def superuser(self) -> bool:
        return "SUPERUSER" in self.attributes.replace("BOOTSTRAP ", "").split(", ")


@dataclass
class Reach:
    """What a role reaches with its own grants and the ones it inherits."""
    superuser: bool
    reads: list[str]
    writes: list[str]
    tables_read: set[str]
    tables_written: set[str]
    executes: set[str]
    public_executes: set[str]
    inherited_from: list[str]


def _short(name: str) -> str:
    return name[len("public."):] if name.startswith("public.") else name


def _cols(cols: set[str]) -> str:
    return "" if "*" in cols else f" ({', '.join(sorted(cols))})"


def parse_pg(lines: list[str]) -> tuple[dict[str, RoleView], dict[str, str], list[str]]:
    """(per-role view, SECURITY DEFINER function -> owner, table lines)."""
    roles: dict[str, RoleView] = defaultdict(RoleView)
    definers: dict[str, str] = {}
    tables = []
    for line in lines:
        if line.startswith("pg table "):
            tables.append(line[len("pg table "):])
            continue
        m = _LINE.match(line)
        if not m:
            continue
        role, what, via_public = m["role"], m["what"], bool(m["public"])
        view = roles[role]
        if what.startswith("ATTRIBUTES "):
            view.attributes = what[len("ATTRIBUTES "):]
        elif what.startswith("MEMBER OF "):
            membership = what[len("MEMBER OF "):]
            view.member_of.append(membership)
            if "WITH INHERIT FALSE" not in membership:
                view.inherits.append(membership.split(" ", 1)[0])
        elif what.startswith("OWNS "):
            _owned(view, role, what[len("OWNS "):], definers)
        elif what.startswith("POLICY "):
            (view.public if via_public else view.policies).append(what)
        elif what.startswith("DEFAULT PRIVILEGES "):
            view.defaults.append(what[len("DEFAULT PRIVILEGES "):])
        elif via_public:
            view.public.append(what)
            g = _GRANT.match(what)
            if g and g["priv"] == "EXECUTE" and g["target"].startswith("FUNCTION "):
                view.public_executes.add(g["target"][len("FUNCTION "):])
        elif g := _GRANT.match(what):
            priv, target, col = g["priv"], g["target"], g["col"] or "*"
            if target.startswith("FUNCTION "):
                view.executes.add(target[len("FUNCTION "):])
            elif target == "DATABASE" or target.startswith("SCHEMA "):
                view.other.append(f"{priv} on {target.lower() if target == 'DATABASE' else target}")
            elif priv == "SELECT":
                view.reads[target].add(col)
            elif priv in _WRITES:
                view.writes[(target, priv)].add(col)
            else:
                view.other.append(f"{priv}{'' if col == '*' else f' ({col})'} on {_short(target)}")
        else:
            view.other.append(what)
    return roles, definers, tables


def _owned(view: RoleView, role: str, owned: str, definers: dict[str, str]) -> None:
    """An owner holds every privilege on what it owns and may run the functions it owns."""
    view.owns.append(_short_owned(owned))
    if owned.startswith("FUNCTION "):
        fn = owned[len("FUNCTION "):].removesuffix(" SECURITY DEFINER")
        view.executes.add(fn)
        if owned.endswith(" SECURITY DEFINER"):
            definers[fn] = role
        return
    for kind in _OWNED_DATA:
        if owned.startswith(kind):
            target = owned[len(kind):]
            view.reads[target].add("*")
            view.writes[(target, OWNER)].add("*")
            return


def _short_owned(text: str) -> str:
    for kind in ("MATERIALIZED VIEW ", "FOREIGN TABLE "):
        if text.startswith(kind):
            return f"{kind.lower()}{_short(text[len(kind):])}"
    kind, _, rest = text.partition(" ")
    return f"{kind.lower()} {_short(rest)}".rstrip()


def _closure(role: str, roles: dict[str, RoleView]) -> list[str]:
    """The role and every role it inherits from, directly or through other memberships."""
    seen, todo = [role], [role]
    while todo:
        view = roles.get(todo.pop(), RoleView())
        for parent in view.inherits:
            if parent not in seen:
                seen.append(parent)
                todo.append(parent)
    return seen


def reach(role: str, roles: dict[str, RoleView]) -> Reach:
    own = roles.get(role, RoleView())
    chain = _closure(role, roles)
    reads: dict[str, set[str]] = defaultdict(set)
    writes: dict[tuple[str, str], set[str]] = defaultdict(set)
    executes: set[str] = set()
    public_executes: set[str] = set()
    extra_reads, extra_writes = [], []
    for name in chain:
        view = roles.get(name, RoleView())
        for t, cols in view.reads.items():
            reads[t] |= cols
        for key, cols in view.writes.items():
            writes[key] |= cols
        executes |= view.executes
        public_executes |= view.public_executes
        if name in _PREDEFINED_READS:
            extra_reads.append(_PREDEFINED_READS[name])
        if name in _PREDEFINED_WRITES:
            extra_writes.append(_PREDEFINED_WRITES[name])
    read_lines = extra_reads + [f"{_short(t)}{_cols(c)}" for t, c in sorted(reads.items())]
    write_lines = extra_writes + [
        f"{_short(t)} (owner: every privilege)" if p == OWNER else f"{p} {_short(t)}{_cols(c)}"
        for (t, p), c in sorted(writes.items())]
    return Reach(superuser=own.superuser, reads=read_lines, writes=write_lines,
                 tables_read={_short(t) for t in reads} | set(extra_reads),
                 tables_written={_short(t) for t, _ in writes} | set(extra_writes),
                 executes=executes, public_executes=public_executes,
                 inherited_from=chain[1:])


def _cell(items: list[str]) -> str:
    text = "; ".join(items) if items else "none"
    return text.replace("|", "\\|")


def _callable(r: Reach, definers: dict[str, str]) -> dict[str, bool]:
    """Functions a role may run -> True when only through PUBLIC. Of the PUBLIC ones only the
    SECURITY DEFINER functions count here: the others run with the caller's own rights."""
    found = {fn: False for fn in r.executes}
    for fn in r.public_executes:
        if fn in definers and fn not in found:
            found[fn] = True
    return found


def _role_rows(role: str, roles: dict[str, RoleView], definers: dict[str, str]) -> list[tuple[str, str]]:
    view = roles.get(role, RoleView())
    r = reach(role, roles)
    rows = [("Database role", f"`{role}`" + (f" ({view.attributes})" if view.attributes else "")),
            ("Reads", EVERYTHING if r.superuser else _cell(r.reads)),
            ("Writes", EVERYTHING if r.superuser else _cell(r.writes))]
    callable_ = _callable(r, definers)
    execs = []
    for fn in sorted(callable_):
        owner = definers.get(fn)
        execs.append(f"{_short(fn)}" + (" (via PUBLIC)" if callable_[fn] else "")
                     + (f", runs as {owner}" if owner else ""))
    rows.append(("Executes", _cell(execs)))
    for owner in sorted({definers[f] for f in callable_ if f in definers} - {role}):
        if roles.get(owner, RoleView()).superuser:
            rows.append((f"Through functions owned by {owner}", EVERYTHING))
            continue
        o = reach(owner, roles)
        rows.append((f"Through functions owned by {owner}",
                     _cell([f"reads {x}" for x in o.reads] + [f"writes {x}" for x in o.writes])))
    if view.member_of:
        member = sorted(view.member_of)
        if r.inherited_from:
            member.append("reads, writes and executes above include what it inherits from "
                          + ", ".join(r.inherited_from))
        rows.append(("Member of", _cell(member)))
    if view.owns:
        rows.append(("Owns", _cell(sorted(view.owns))))
    if view.policies:
        rows.append(("Row-level policies", _cell(sorted(view.policies))))
    if view.defaults:
        rows.append(("Default privileges", _cell(sorted(view.defaults))))
    if view.other:
        rows.append(("Other", _cell(sorted(view.other))))
    return rows


def _node(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", name)


def render(doc: dict, title: str, note: str) -> str:
    roles, definers, tables = parse_pg(doc.get("pg", []))
    edges = [canon.split_edge(e) for e in doc.get("edges", [])]
    out_edges: dict[str, set[str]] = defaultdict(set)
    in_edges: dict[str, set[str]] = defaultdict(set)
    for a, b in edges:
        out_edges[a].add(b)
        in_edges[b].add(a)
    k8s: dict[str, list[str]] = defaultdict(list)
    for line in doc.get("k8s", []):
        sa, _, rule = line[len("k8s serviceaccount "):].partition(": ")
        k8s[sa].append(rule)
    azure: dict[str, list[str]] = defaultdict(list)
    for line in doc.get("azure", []):
        ident, _, rule = line[len("azure identity "):].partition(": ")
        azure[ident].append(rule)
    components = doc.get("components", {})

    md = [f"# {title}", "", note, ""]
    md += ["## Summary", "",
           "| Component | Database roles | Reads | Writes | Executes | Connects to |",
           "|---|---|---|---|---|---|"]
    for name, comp in components.items():
        rs = comp.get("db_roles") or []
        reaches = [reach(r, roles) for r in rs]
        if any(x.superuser for x in reaches):
            reads = writes = [EVERYTHING]
        else:
            reads = sorted(set().union(*(x.tables_read for x in reaches)))
            writes = sorted(set().union(*(x.tables_written for x in reaches)))
        execs = sorted({_short(f).split("(")[0] + (" (via PUBLIC)" if public else "")
                        for x in reaches for f, public in _callable(x, definers).items()})
        md.append(f"| {name} | {_cell(rs)} | {_cell(reads)} | {_cell(writes)} | {_cell(execs)} | "
                  f"{_cell(sorted(out_edges.get(name, set())))} |")

    md += ["", "## Network edges", "",
           "Who may open a connection to whom (`a --> b`: a connects to b).", "", "```mermaid",
           "flowchart LR"]
    for a, b in sorted(edges):
        md.append(f"  {_node(a)}[{a}] --> {_node(b)}[{b}]")
    md += ["```", "", "## Blast radius per component", ""]
    for name, comp in components.items():
        md += [f"### {name}", "", "| | |", "|---|---|"]
        rows: list[tuple[str, str]] = []
        for role in comp.get("db_roles") or []:
            rows += _role_rows(role, roles, definers)
        if not comp.get("db_roles"):
            rows.append(("Database role", "none"))
        rows.append(("Connects to", _cell(sorted(out_edges.get(name, set())))))
        rows.append(("Accepts connections from", _cell(sorted(in_edges.get(name, set())))))
        sa = comp.get("service_account")
        rows.append(("Kubernetes API", _cell(sorted(k8s.get(sa, []))) if sa else "no service account"))
        ident = comp.get("azure_identity")
        rows.append(("Azure roles", _cell(sorted(azure.get(ident, []))) if ident else "no identity"))
        if comp.get("runtime_class"):
            rows.append(("Runtime class", f"`{comp['runtime_class']}`"))
        md += [f"| {k} | {v} |" for k, v in rows] + [""]

    known = {r for c in components.values() for r in c.get("db_roles") or []}
    public = sorted({w for v in roles.values() for w in v.public})
    if public:
        md += ["## Every role (PUBLIC)", "",
               "PUBLIC is every role, including any role created later. These lines are counted "
               "for each role in the comparison.", ""]
        md += [f"- {w}" for w in public] + [""]
    others = sorted(r for r in roles if r not in known and (roles[r].attributes or roles[r].owns
                                                             or roles[r].reads or roles[r].writes
                                                             or roles[r].executes))
    if others:
        md += ["## Roles no component declares", ""]
        for role in others:
            md += [f"### {role}", "", "| | |", "|---|---|"]
            md += [f"| {k} | {v} |" for k, v in _role_rows(role, roles, definers)] + [""]
    if tables:
        md += ["## Row-level security", ""] + [f"- {_short(t)}" for t in sorted(tables)] + [""]
    return "\n".join(md).rstrip() + "\n"


def render_expected(doc: dict, expected_path: str) -> str:
    command = f"python -m secops.permassess.report --expected {expected_path} --out docs/permission-matrix.md"
    note = ("Generated file, do not edit. Built from "
            f"`{expected_path}` (itself generated from the capability manifests in "
            f"`{doc.get('source', '?')}`). Regenerate with:\n\n"
            f"    {command}\n\n"
            "This is the intended state. `python -m secops.permassess` compares it with what "
            "PostgreSQL, Compose, Kubernetes and Azure really allow and fails on any difference.")
    return render(doc, "Permission matrix", note)


def main(argv: list[str] | None = None) -> int:
    import json

    parser = argparse.ArgumentParser(prog="python -m secops.permassess.report")
    parser.add_argument("--expected", type=Path, default=Path("security/expected-permissions.json"))
    parser.add_argument("--out", type=Path, default=Path("docs/permission-matrix.md"))
    parser.add_argument("--check", action="store_true",
                        help="do not write; exit 1 if the file is not what the expected file gives")
    args = parser.parse_args(argv)
    try:
        doc = json.loads(args.expected.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"report: cannot read {args.expected}: {exc}", file=sys.stderr)
        return 2
    text = render_expected(doc, args.expected.as_posix())
    if args.check:
        current = args.out.read_text(encoding="utf-8") if args.out.exists() else ""
        if current != text:
            print(f"report: {args.out} is out of date; regenerate it with "
                  f"python -m secops.permassess.report --expected {args.expected.as_posix()} "
                  f"--out {args.out.as_posix()}", file=sys.stderr)
            return 1
        print(f"report: {args.out} is up to date")
        return 0
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(text, encoding="utf-8", newline="\n")
    print(f"report: wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
