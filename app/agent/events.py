"""Security events: one JSON line per event on the `assume_hijacked.security` logger.

Fields are names and categories only. Never pass a ticket body, a tool result or an argument
value here: they can hold health data or text the attacker chose.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

LOGGER = logging.getLogger("assume_hijacked.security")


def security_event(kind: str, **fields) -> None:
    record = {"ts": datetime.now(timezone.utc).isoformat(), "kind": kind}
    record.update((key, value) for key, value in fields.items() if key not in record)
    # WARNING, so the line still appears when nobody has configured the logger.
    LOGGER.warning(json.dumps(record, ensure_ascii=False, default=str))
