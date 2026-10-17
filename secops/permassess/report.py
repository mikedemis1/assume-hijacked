"""The permission matrix: per component, what it can read, write and execute, and where it can
connect. Its blast radius, if it were hijacked.

    python -m secops.permassess.report --expected security/expected-permissions.json \
        --out docs/permission-matrix.md [--check]

The same renderer writes reports/permissions/matrix.md from what the collectors found.
A SECURITY DEFINER function runs with its owner's rights, so the report follows it: a role that
may execute one also reaches whatever the owner can read and write.
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


@dataclass
class RoleView:
    attributes: str = ""
    reads: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    writes: dict[tuple[str, str], set[str]] = field(default_factory=lambda: defaultdict(set))
    executes: set[str] = field(default_factory=set)
    public: list[str] = field(default_factory=list)
    other: list[str] = field(default_factory=list)
    member_of: list[str] = field(default_factory=list)
    owns: list[str] = field(default_factory=list)
    policies: list[str] = field(default_factory=list)
    defaults: list[str] = field(default_factory=list)


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
            view.member_of.append(what[len("MEMBER OF "):])
        elif what.startswith("OWNS "):
            view.owns.append(_short_owned(what[len("OWNS "):]))
            if what.endswith(" SECURITY DEFINER") and what.startswith("OWNS FUNCTION "):
                definers[what[len("OWNS FUNCTION "):-len(" SECURITY DEFINER")]] = role
        elif what.startswith("POLICY "):
            (view.public if via_public else view.policies).append(what)
        elif what.startswith("DEFAULT PRIVILEGES "):
            view.defaults.append(what[len("DEFAULT PRIVILEGES "):])
        elif via_public:
            view.public.append(what)
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


def _short_owned(text: str) -> str:
    kind, _, rest = text.partition(" ")
    return f"{kind.lower()} {_short(rest)}"


def _reads(view: RoleView) -> list[str]:
    return [f"{_short(t)}{_cols(c)}" for t, c in sorted(view.reads.items())]


def _writes(view: RoleView) -> list[str]:
    return [f"{p} {_short(t)}{_cols(c)}" for (t, p), c in sorted(view.writes.items())]


def _cell(items: list[str]) -> str:
    text = "; ".join(items) if items else "none"
    return text.replace("|", "\\|")


def _role_rows(role: str, roles: dict[str, RoleView], definers: dict[str, str]) -> list[tuple[str, str]]:
    view = roles.get(role, RoleView())
    rows = [("Database role", f"`{role}`" + (f" ({view.attributes})" if view.attributes else "")),
            ("Reads", _cell(_reads(view))),
            ("Writes", _cell(_writes(view)))]
    execs = []
    for fn in sorted(view.executes):
        owner = definers.get(fn)
        execs.append(f"{_short(fn)}" + (f", runs as {owner}" if owner else ""))
    rows.append(("Executes", _cell(execs)))
    for owner in sorted({definers[f] for f in view.executes if f in definers}):
        reach = roles.get(owner, RoleView())
        rows.append((f"Through functions owned by {owner}",
                     _cell([f"reads {r}" for r in _reads(reach)] + [f"writes {w}" for w in _writes(reach)])))
    if view.member_of:
        rows.append(("Member of", _cell(sorted(view.member_of))))
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
        reads = sorted({_short(t) for r in rs for t in roles.get(r, RoleView()).reads})
        writes = sorted({_short(t) for r in rs for (t, _) in roles.get(r, RoleView()).writes})
        execs = sorted({_short(f).split("(")[0] for r in rs for f in roles.get(r, RoleView()).executes})
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
