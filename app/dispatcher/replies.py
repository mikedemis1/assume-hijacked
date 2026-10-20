"""What the dispatcher does to a reply before it is stored, outside the agent.

The agent has its own reply guard (app/agent/core.py), but the agent is the component a hijacked
model can reach: a guard that only runs there can be skipped by whoever controls it. So the
dispatcher, which the agent cannot reach except through POST /reply, runs the same guard again on
the text it is given, and adds the two notices itself.

    1. block_reason (app/agent/guard.py) on the text. The numbers a reply may repeat are the ones in
       the ticket owner's account (tariff, status, address): what lookup_account can have shown the
       model. They come from the database (finish_reply_facts), not from the agent. A reply the guard
       blocks is replaced by SAFE_REPLY, a text that claims nothing.
    2. On a ticket where a credit or move-out request was filed or attempted, the model's text is not
       stored at all: a fixed template is (effect_template). The facts come from the database, never
       from the agent. A word filter can be talked round by a paraphrase nobody listed, so the one
       place where a promise costs money gets no free text.
    3. CREDIT_NOTICE is added when issue_bill_credit was called on the lease, whether the call worked
       or not; MEDICAL_QUESTION when a move-out request went in. The facts are read from the
       gateway's record of calls (tool_calls), so an agent that "forgets" them changes nothing. Both
       go on after the guard, because the credit notice names a credit, which the guard would block.

The agent sends the reply text only, without these notices (app/agent/core.py). An agent that added
the credit notice itself would have its whole reply replaced by SAFE_REPLY here.

Nothing here logs or returns the text: only the category that blocked it.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.agent.guard import SAFE_REPLY, block_reason, numbers_in

# Added by this code, not the model, after a move-out request went in: a protected home may be
# behind it and the customer is the only one who can say so.
# No digits and no money words, so it would pass the reply guard anyway.
MEDICAL_QUESTION = (
    "Does anyone at the property use medical equipment that needs electricity? "
    "If so, please tell us and we will protect the supply.\n"
    "Χρησιμοποιεί κάποιος στο ακίνητο ιατρικό εξοπλισμό που χρειάζεται ρεύμα; "
    "Αν ναι, πείτε μας και θα προστατεύσουμε την παροχή."
)
# Added by this code, not the model, whenever issue_bill_credit was called, whether the call worked
# or not: the model's reply may still suggest that money is coming. It names a credit, so the reply
# guard would block it; that is why it goes on after the guard.
CREDIT_NOTICE = (
    "No credit is confirmed until it has been checked.\n"
    "Καμία πίστωση δεν επιβεβαιώνεται πριν ελεγχθεί."
)

# Stored instead of the model's text when an effect tool was called on the lease. Fixed text: no amount,
# no date, no promise. The only variable part is the numbers of the requests the database holds.
# With no request filed (the call was refused or failed) it promises nothing at all.
NO_REQUEST = "We have received your message.\nΛάβαμε το μήνυμά σας."
ONE_REQUEST = (
    "We have received your request ({numbers}). A member of staff will review it and you will hear from us.\n"
    "Λάβαμε το αίτημά σας ({numbers}). Μέλος του προσωπικού θα το εξετάσει και θα ενημερωθείτε."
)
SEVERAL_REQUESTS = (
    "We have received your requests ({numbers}). A member of staff will review them and you will hear from us.\n"
    "Λάβαμε τα αιτήματά σας ({numbers}). Μέλος του προσωπικού θα τα εξετάσει και θα ενημερωθείτε."
)


def effect_template(request_ids: tuple[int, ...]) -> str:
    """The fixed reply for an effect ticket. `request_ids` are the ids of the requests filed on the
    ticket (action_requests), or none when the effect was attempted and nothing was filed."""
    if not request_ids:
        return NO_REQUEST
    numbers = ", ".join(f"#{i}" for i in request_ids)
    return (ONE_REQUEST if len(request_ids) == 1 else SEVERAL_REQUESTS).format(numbers=numbers)


# The longest reply that is taken, in characters. The longest text the agent sends is far shorter.
MAX_TEXT_CHARS = 4000


@dataclass(frozen=True)
class Finished:
    text: str  # what is stored and sent to the customer
    blocked: str | None  # the guard's category when the agent's own text was replaced
    kind: str  # stored in replies.kind: "agent" (the model's text passed), "safe" (guard replaced it), "template"


def finish(text: str, account_text: str, credit_asked: bool, moveout_submitted: bool,
           effect_attempted: bool, request_ids: tuple[int, ...]) -> Finished:
    if effect_attempted or credit_asked or moveout_submitted or request_ids:
        parts, reason, kind = [effect_template(request_ids)], None, "template"
    else:
        reason = block_reason(text, numbers_in(account_text))
        parts, kind = [SAFE_REPLY if reason else text], "safe" if reason else "agent"
    if credit_asked:
        parts.append(CREDIT_NOTICE)
    if moveout_submitted:
        parts.append(MEDICAL_QUESTION)
    return Finished("\n\n".join(parts), reason, kind)
