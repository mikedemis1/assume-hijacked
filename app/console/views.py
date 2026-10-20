"""HTML contains operational categories and identifiers, never customer free text."""

from html import escape
from string import Template

PAGE = Template('<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Staff approvals</title></head><body><h1>Staff approvals</h1>$body</body></html>')


def text(value):
    return escape(str(value), quote=True)


def form(path, csrf, label, fields=""):
    return f'<form method="post" action="{text(path)}"><input type="hidden" name="csrf" value="{text(csrf)}">{fields}<button>{text(label)}</button></form>'


def queue(data, session):
    csrf = session.csrf
    body = f'<p>Signed in: {text(session.identity.oid)} ({text(session.identity.role)})</p>'
    body += form("/logout", csrf, "Sign out")
    body += "<h2>Requests</h2>"
    for row in data["requests"]:
        tier = row["tier"] or "UNKNOWN"
        body += f'<article><h3>Request {text(row["id"])}</h3><p>{text(row["kind"])} | {text(row["status"])} | {text(tier)}</p>'
        # Only codes emitted by the rules are displayed; never arbitrary text from a new writer.
        reasons = {"invalid_amount","protected_or_unknown_home","above_auto_limit","above_200","no_auto_evidence","evidence_unconfirmed","recent_refusals","blocked_calls"}
        body += "<p>"+text(", ".join(r for r in (row["reasons"] or []) if r in reasons))+"</p>"
        if tier in {"HUMAN_ONLY", "UNKNOWN"}:
            body += "<p>⚠ Protected customer: call the registered number first</p>"
        if row["status"] == "pending":
            if tier in {"T0","T1","T2"}:
                body += form(f'/approve/{row["id"]}', csrf, "Approve")
            body += form(f'/reject/{row["id"]}', csrf, "Reject")
        body += "</article>"
    body += "<h2>Agents</h2><p>"+("Paused" if data["paused"] else "Running")+"</p>"
    if session.identity.role == "SeniorApprover":
        body += form("/agents/resume",csrf,"Resume agents")
    body += "<h2>Component heartbeats</h2>"
    for row in data["heartbeats"]:
        body += f'<p>{text(row["component"])} | {text(row["last_beat"])}</p>'
    body += "<h2>Alerts</h2>"
    for row in data["alerts"]:
        body += f'<p>ALERT {text(row["id"])} | {text(row["created_at"])} | {text(row["actor"])}</p>'
    return PAGE.substitute(body=body)
