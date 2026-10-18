"""What the dispatcher does to a reply before it is stored, outside the agent.

The agent has its own reply guard (app/agent/core.py), but the agent is the component a hijacked
model can reach: a guard that only runs there can be skipped by whoever controls it. So the
dispatcher, which the agent cannot reach except through POST /reply, runs the same guard again on
the text it is given, and adds the two notices itself.

    1. block_reason (app/agent/guard.py) on the text. The numbers a reply may repeat are the ones in
       the ticket owner's account (tariff, status, address): what lookup_account can have shown the
       model. They come from the database (reply_facts), not from the agent. A reply the guard
       blocks is replaced by SAFE_REPLY, a text that claims nothing.
    2. CREDIT_NOTICE is added when issue_bill_credit was called on the lease, whether the call worked
       or not; MEDICAL_QUESTION when a move-out request went in. Same rules as the agent's own
       `_finish`, but the facts are read from the gateway's record of calls (tool_calls), so an agent
       that "forgets" them changes nothing. Both go on after the guard, because the credit notice
       names a credit, which the guard would block.

The agent sends the reply text only, without these notices. (An agent that adds them itself would
have them twice; the agent that talks to this dispatcher does not.)

Nothing here logs or returns the text: only the category that blocked it.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.agent.core import CREDIT_NOTICE, MEDICAL_QUESTION
from app.agent.guard import SAFE_REPLY, block_reason, numbers_in

# The longest reply that is taken, in characters. The longest text the agent sends is far shorter.
MAX_TEXT_CHARS = 4000


@dataclass(frozen=True)
class Finished:
    text: str  # what is stored and sent to the customer
    blocked: str | None  # the guard's category when the agent's own text was replaced


def finish(text: str, account_text: str, credit_asked: bool, moveout_submitted: bool) -> Finished:
    allowed = numbers_in(account_text)
    reason = block_reason(text, allowed)
    parts = [SAFE_REPLY if reason else text]
    if credit_asked:
        parts.append(CREDIT_NOTICE)
    if moveout_submitted:
        parts.append(MEDICAL_QUESTION)
    return Finished("\n\n".join(parts), reason)
