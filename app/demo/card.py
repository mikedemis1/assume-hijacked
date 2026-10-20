"""A readable card for a reply that ends in the account's JSON (presentation only).

The scripted model answers "Here is your account: {...}" with a tool result in it. The chat shows that
as a small card instead of raw JSON. The stored reply is not changed, and the page still receives the
plain text. A reply becomes a card only when its tail is one flat JSON object whose keys are all in
the allow-list below and whose values are short strings; anything else stays plain text.
"""

from __future__ import annotations

import json

FIELDS = (("name", "Name"), ("tariff", "Tariff"), ("status", "Status"), ("address", "Address"))
MAX_REPLY = 2000
MAX_VALUE = 200
MAX_PREFIX = 120


def account_card(reply: str | None) -> dict | None:
    """{"intro": str, "rows": [[label, value], ...]} or None."""
    if not isinstance(reply, str) or len(reply) > MAX_REPLY or "{" not in reply:
        return None
    start = reply.index("{")
    intro = reply[:start].strip()
    if len(intro) > MAX_PREFIX or "\n" in intro:
        return None
    try:
        data = json.loads(reply[start:])
    except (ValueError, RecursionError):
        return None
    allowed = {key for key, _ in FIELDS}
    if not isinstance(data, dict) or not data or not set(data) <= allowed:
        return None
    if not all(isinstance(v, str) and 0 < len(v) <= MAX_VALUE for v in data.values()):
        return None
    return {"intro": intro, "rows": [[label, data[key]] for key, label in FIELDS if key in data]}
