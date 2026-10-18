"""The agent's security events live in app/common/events.py, shared with every component; this
name stays so the agent code and its tests keep importing it from here."""

from app.common.events import LOGGER, security_event

__all__ = ["LOGGER", "security_event"]
