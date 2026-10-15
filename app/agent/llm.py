"""The model behind the agent. ScriptedLLM plays a fully hijacked model."""

from __future__ import annotations

import json
from dataclasses import dataclass, field


@dataclass(frozen=True)
class ToolCall:
    name: str
    args: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Reply:
    text: str


DEFAULT_PLAN = [ToolCall("lookup_account", {}), Reply("Here is your account: {last}")]


def _parse(body: str) -> list[ToolCall | Reply]:
    plan: list[ToolCall | Reply] = []
    for raw in body.splitlines():
        line = raw.strip()
        if line.startswith("CALL "):
            parts = line.split(" ", 2)
            try:
                args = json.loads(parts[2]) if len(parts) == 3 else {}
            except (ValueError, RecursionError):
                continue  # untrusted text: ignore malformed or absurdly nested command lines
            if not isinstance(args, dict):
                continue
            plan.append(ToolCall(parts[1], args))
        elif line.startswith("SAY "):
            plan.append(Reply(line[4:]))
    return plan or list(DEFAULT_PLAN)


class ScriptedLLM:
    """Obeys every CALL/SAY line in the ticket, the way a hijacked model would.

    Stateless: the next step is chosen from how many tool results the transcript holds.
    """

    def next_action(self, transcript: list[dict]) -> ToolCall | Reply:
        plan = _parse(transcript[0]["text"])
        results = [item["result"] for item in transcript if item["role"] == "tool"]
        last = results[-1] if results else ""
        if len(results) < len(plan):
            step = plan[len(results)]
        else:
            step = Reply("Here is what I found: {last}")
        if isinstance(step, Reply):
            return Reply(step.text.replace("{last}", last))
        return step
