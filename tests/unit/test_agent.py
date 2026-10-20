import json
from decimal import Decimal

import pytest
from hypothesis import example, given, settings as hypothesis_settings, strategies as st

from app.agent.core import ALLOWED_ARGS, GIVE_UP, Agent
from app.agent.guard import SAFE_REPLY, guard_reply, numbers_in
from app.agent.llm import ScriptedLLM
from tests.conftest import admin_connect
from tests.dispatcherharness import Harness, post
from tests.gatewayharness import AppGatewayClient, build


# Properties run the same cases on every run (derandomize), so a red CI run can be repeated on a PC.
PROPERTY = hypothesis_settings(max_examples=200, deadline=None, derandomize=True)

LEASE = "lease-of-ticket-7"  # what the agent was given; RecordingGateway never checks it
UNKNOWN_LEASE = "0" * 64


class LeasedAgent:
    """The agent with real in-memory tool servers and the real dispatcher. A lease is opened for the
    ticket as the dispatcher's claim would, the agent works under it, and its text goes to the
    dispatcher's reply endpoint, which runs the guard again and adds the notices. Two answers are
    kept apart on purpose: `sent_text` is what the agent sends, `handle_ticket` is what the
    customer is sent."""

    def __init__(self, agent, settings, as_role):
        self.agent = agent
        self.settings = settings
        self.dispatcher = Harness(settings, as_role)
        self.lease = None
        self.sent = None

    def sent_text(self, ticket_id):
        """What the agent sends to the dispatcher for this ticket (no notices: those are added there)."""
        with admin_connect(self.settings) as admin:
            self.lease = self.dispatcher.lease_for(admin, ticket_id)
        self.sent = self.agent.handle_ticket(ticket_id, self.lease)
        return self.sent

    def post_reply(self):
        return post(self.dispatcher.app, "/reply", lease=self.lease, headers=self.dispatcher.owner(self.lease), body={"text": self.sent})

    def handle_ticket(self, ticket_id):
        """What is stored and sent to the customer after the dispatcher has run its checks."""
        self.sent_text(ticket_id)
        answer = self.post_reply()
        assert answer.status_code == 200, answer.text
        with admin_connect(self.settings) as admin:
            return admin.execute("SELECT text FROM replies WHERE ticket_id = %s", (ticket_id,)).fetchone()["text"]


def make_agent(settings, as_role):
    """The agent with the real tool gateway and tool apps in this process: the agent's tool client
    (header X-Lease) -> the gateway (every wall, the risk engine allowing) -> the tools (token check)."""
    gw = AppGatewayClient(build(settings, as_role))
    return LeasedAgent(Agent(ScriptedLLM(), gw), settings, as_role)


class RecordingGateway:
    """Stands in for the tools: records what the agent sends and answers with canned JSON."""

    def __init__(self, body, results=None):
        self.body = body
        self.results = results or {}
        self.calls = []

    def call(self, name, args):
        self.calls.append((name, dict(args)))
        if name == "read_ticket":
            return json.dumps({"ticket_id": 7, "body": self.body})
        return self.results.get(name, json.dumps({"name": "Canned"}))


# Events the tool gateway writes. In the container it is another process with its own log; the tests
# run it in this one, so the agent's events are what is left when these are taken out.
GATEWAY_EVENTS = ("dropped_args", "tool_call_not_recorded", "caller_refused")


def security_events(caplog):
    events = [json.loads(r.getMessage()) for r in caplog.records if r.name == "assume_hijacked.security"]
    return [e for e in events if not e["kind"].startswith("gateway_") and e["kind"] not in GATEWAY_EVENTS]


def add_ticket(admin, ticket_id, customer_id, body):
    admin.execute(
        "INSERT INTO tickets (id, customer_id, body) VALUES (%s, %s, %s)",
        (ticket_id, customer_id, body),
    )




def test_agent_stops_after_max_steps(settings, admin, as_role):
    add_ticket(admin, 104, 1001, "\n".join(["CALL lookup_account {}"] * 30))
    assert make_agent(settings, as_role).handle_ticket(104) == GIVE_UP


# --- security events (gap I6) ---


class TranscriptSpy(ScriptedLLM):
    """The scripted model, keeping a copy of every transcript it is shown."""

    def __init__(self):
        self.seen = []

    def next_action(self, transcript):
        self.seen.append(json.dumps(transcript, ensure_ascii=False))
        return super().next_action(transcript)


@pytest.mark.parametrize(
    "result",
    [
        # What an MCP argument validation error looks like: it repeats the arguments sent.
        f"ERROR: 1 validation error for lookup_accountArguments input_value={{'lease': '{LEASE}'}}",
        json.dumps({"name": "Canned", "note": LEASE}),
    ],
    ids=["error", "result"],
)
def test_lease_never_reaches_the_transcript_or_the_reply(result):
    # The lease is a credential: the model must never see it, nor be able to repeat it.
    gw = RecordingGateway("CALL lookup_account {}\nCALL lookup_account {}\nSAY {last}", {"lookup_account": result})
    llm = TranscriptSpy()
    reply = Agent(llm, gw).handle_ticket(7, LEASE)
    assert gw.calls[1] == ("lookup_account", {"lease": LEASE})  # the tools still get it
    assert len(llm.seen) == 3
    assert all(LEASE not in seen for seen in llm.seen)
    assert LEASE not in reply


# --- the model is the LLM gateway (it can fail, and it sees the calls it made) ---


def test_the_agent_holds_no_key_and_knows_no_tool_address():
    # The agent's only edges are the dispatcher, the LLM gateway and the tool gateway: no signing
    # key to read, no TOOL_URL_* to call a tool by, no database, no provider.
    from pathlib import Path

    import app.agent as agent_package

    source = "\n".join(p.read_text(encoding="utf-8") for p in Path(agent_package.__file__).parent.glob("*.py"))
    for word in ("SIGNING_KEY", "TOOL_URL", "load_private_key", "mint_tool_token", "app.tools", "psycopg", "app.db"):
        assert word not in source.replace("tool client", ""), word


def test_asi01_agent_drops_customer_id():
    # One readable example of the rule; the property below holds it for any tool and any arguments.
    agent = Agent(ScriptedLLM(), RecordingGateway(""))
    sent = {"amount_eur": 1, "reason": "duplicate_charge", "evidence_ref": 2, "customer_id": 1002}
    assert agent._safe_args("issue_bill_credit", sent, LEASE) == (
        {"amount_eur": 1, "reason": "duplicate_charge", "evidence_ref": 2, "lease": LEASE}, ["customer_id"])


# Names the model might send: the real ones, the ones it must not set, and any text.
_ARG_NAMES = sorted({n for names in ALLOWED_ARGS.values() for n in names}
                    | {"customer_id", "ticket_id", "lease", "account_id", "id", ""})


def _fullwidth(text: str) -> str:
    return "".join(chr(ord(c) + 0xFEE0) if "!" <= c <= "~" else c for c in text)


# The same names written a little differently. A tool that matched names loosely (case, spaces,
# full-width letters) would let one of these through.
_NEAR_MISS = [str.upper, str.title, lambda n: f" {n}", lambda n: f"{n} ", lambda n: n + "\n", _fullwidth]


def _with_near_misses(names):
    return st.one_of(st.sampled_from(names),
                     st.builds(lambda n, f: f(n), st.sampled_from(names), st.sampled_from(_NEAR_MISS)))


_arg_name = st.one_of(_with_near_misses(_ARG_NAMES), st.text(max_size=12))
_arg_value = st.one_of(st.none(), st.booleans(), st.integers(), st.text(max_size=12), st.lists(st.integers(), max_size=3))
_arguments = st.one_of(st.dictionaries(_arg_name, _arg_value, max_size=8),
                       st.none(), st.text(max_size=8), st.lists(st.integers(), max_size=3))


@given(tool=st.sampled_from(sorted(ALLOWED_ARGS)), sent=_arguments)
@example(tool="issue_bill_credit", sent={"amount_eur": 1, "customer_id": 1002, "lease": "mine"})
@PROPERTY
def test_asi01_property_agent_sends_only_the_tools_arguments_and_its_own_lease(tool, sent):
    agent = Agent(ScriptedLLM(), RecordingGateway(""))
    clean, dropped = agent._safe_args(tool, sent, LEASE)
    sent_names = list(sent) if isinstance(sent, dict) else []
    allowed = ALLOWED_ARGS[tool]
    # Only this tool's argument names go on, plus the lease, and the lease is the agent's own.
    assert set(clean) == (allowed & set(sent_names)) | {"lease"}
    assert clean["lease"] == LEASE
    assert "customer_id" not in clean
    assert all(clean[name] == sent[name] for name in allowed & set(sent_names))
    # Every other name the model sent is reported, in the order sent, none twice.
    assert dropped == [name for name in sent_names if name not in allowed]


@given(tool=st.one_of(st.text(max_size=20), _with_near_misses(sorted(ALLOWED_ARGS))).filter(lambda name: name not in ALLOWED_ARGS),
       sent=_arguments)
@PROPERTY
def test_asi01_property_agent_sends_nothing_for_a_tool_not_in_the_table(tool, sent):
    assert Agent(ScriptedLLM(), RecordingGateway(""))._safe_args(tool, sent, LEASE) == (None, [])


# One readable example per rule; the properties below hold each rule for any amount.
@pytest.mark.parametrize("text", ["We credited €49", "We knocked 49 off your bill",
                                  "Your meter number is forty-nine"])
def test_asi09_guard_blocks_money_promises(text):
    assert guard_reply(text, set()) == SAFE_REPLY


# Ways to write an amount into a reply: symbol, code, word, wording without a currency, Greek.
_PROMISES = [
    "We credited €{a}", "You get {a} euros", "EUR {a} refunded", "€ {a} back", "a refund of {a} Euro",
    "EUR{a} back", "{a}EUR", "refund of ${a}", "{a} dollars", "{a} ευρώ", "We credited {a} to your account",
    "Η πίστωση {a} έγινε", "You will get {a} back on your next bill", "We knocked {a} off your bill",
    "We added {a} to your balance", "Rebate of {a} done", "We will pay you back {a}", "{a} quid back",
    "Θα πάρετε {a} πίσω",
]
_amounts = st.one_of(
    st.integers(0, 999_999).map(str),
    st.tuples(st.integers(0, 9_999), st.integers(0, 99), st.sampled_from(".,")).map(lambda t: f"{t[0]}{t[2]}{t[1]:02d}"),
)
_filler = st.text(alphabet="abcdefghijklmnopqrstuvwxyz ", max_size=20)


@given(amount=_amounts, before=_filler, after=_filler)
@example(amount="49", before="", after="")
@example(amount="49.00", before="", after="")
@PROPERTY
def test_asi09_property_money_wording_and_currency_block_a_reply_even_for_a_returned_amount(amount, before, after):
    # The amount is one a tool returned, so the number rule would let it through: it is the currency
    # and the money wording that block the reply. Every shape runs every time.
    returned = numbers_in(amount)
    for template in _PROMISES:
        text = f"{before} {template.format(a=amount)} {after}"
        assert guard_reply(text, returned) == SAFE_REPLY, template


_NUMBER_WORDS = st.builds(
    lambda tens, joiner, unit: tens + joiner + unit,
    st.sampled_from(["twenty", "thirty", "forty", "fifty", "sixty", "seventy", "eighty", "ninety"]),
    st.sampled_from(["", " ", "-"]), st.sampled_from(["", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine"]))


@given(words=_NUMBER_WORDS, before=_filler)
@example(words="forty nine", before="")
@example(words="fortynine", before="")
@PROPERTY
def test_asi09_property_guard_blocks_an_amount_written_in_words(words, before):
    assert guard_reply(f"{before} Your meter number is {words}", set()) == SAFE_REPLY


# The phrases the old word lists let through (context/gap-review-2026-10-20.md, H1). "10" is the street
# number of the account, so it is a number the reply may repeat.
GAP_PHRASES = [
    "Good news: you will not be charged next month.",
    "Your next bill is free.",
    "Approved: 10 will be removed from your bill.",
    "We will cover the cost of the duplicate charge.",
    "10% less on the next invoice",
    "Το επόμενο μήνα δεν θα χρεωθείτε.",
]


@pytest.mark.parametrize("text", GAP_PHRASES)
def test_asi09_guard_blocks_the_gap_review_phrases(text):
    assert guard_reply(text, numbers_in("G1 residential active Patision 10, Athens")) == SAFE_REPLY


# Billing outcomes written in ways no list was built from: a subject about the bill, an outcome, filler.
_BILL_SUBJECTS = ["Your next bill", "Next month's invoice", "The statement for March",
                  "Ο επόμενος λογαριασμός σας", "Το τιμολόγιο του μήνα", "Your electricity bill"]
_OUTCOMES = ["is free", "will be free of charge", "will not be charged", "is waived", "is cancelled", "is reduced",
             "will be 20% lower", "will be lower by 10", "is on us", "will be written off", "has been forgiven",
             "will come to nothing", "will be covered by us", "will carry no cost", "is removed",
             "δεν θα χρεωθεί", "θα είναι δωρεάν", "θα μειωθεί", "θα ακυρωθεί", "θα διαγραφεί", "θα καλυφθεί από εμάς"]
_ADDRESS_NUMBER = {"10"}   # a number the account returned: the number rule alone would let a "10" through


@given(subject=st.sampled_from(_BILL_SUBJECTS), outcome=st.sampled_from(_OUTCOMES), before=_filler, after=_filler)
@example(subject="Your next bill", outcome="is free", before="", after="")
@PROPERTY
def test_asi09_property_guard_blocks_billing_outcome_paraphrases(subject, outcome, before, after):
    text = f"{before} {subject} {outcome}. {after}"
    assert guard_reply(text, _ADDRESS_NUMBER) == SAFE_REPLY


@given(tariff=st.sampled_from(["G1 residential", "G1 commercial"]), status=st.sampled_from(["active", "suspended"]))
@PROPERTY
def test_asi09_property_honest_account_replies_still_pass(tariff, status):
    text = f"Your tariff is {tariff} and your account is {status}."
    assert guard_reply(text, numbers_in(f"{tariff} {status} Patision 10, Athens")) == text


def _value(number: Decimal) -> str:
    """How the guard writes a number it compares: no trailing zeros, no exponent."""
    return format(number.normalize(), "f")


@st.composite
def _written_numbers(draw):
    """(the number as a reply writes it, every value it can mean). "1,000" can mean 1 or 1000."""
    kind = draw(st.sampled_from(["integer", "decimal", "long_decimal", "grouped", "grouped_decimal"]))
    whole, thousands, cents = draw(st.integers(1, 999)), draw(st.integers(0, 999)), draw(st.integers(0, 99))
    if kind == "integer":
        text, values = str(whole * 1000 + thousands), {Decimal(whole * 1000 + thousands)}
    elif kind == "decimal":
        sep = draw(st.sampled_from(".,"))
        text, values = f"{whole}{sep}{cents:02d}", {Decimal(f"{whole}.{cents:02d}")}
    elif kind == "long_decimal":  # four decimals: one value, but its canonical form "1.001" looks grouped
        text, values = f"{whole}.{thousands:03d}0", {Decimal(f"{whole}.{thousands:03d}")}
    elif kind == "grouped":
        sep = draw(st.sampled_from(".,"))
        text, values = f"{whole}{sep}{thousands:03d}", {Decimal(f"{whole}.{thousands:03d}"), Decimal(whole * 1000 + thousands)}
    else:
        text, values = f"{whole}.{thousands:03d},{cents:02d}", {Decimal(f"{whole * 1000 + thousands}.{cents:02d}")}
    # The same number in other characters: full-width or Arabic-Indic digits (and full-width
    # separators), or a zero-width space inside it.
    style = draw(st.sampled_from(["ascii", "fullwidth", "arabic_indic", "zero_width"]))
    if style == "fullwidth":
        text = "".join(chr(ord(c) + 0xFEE0) for c in text)
    elif style == "arabic_indic":
        text = "".join(chr(0x660 + int(c)) if c.isdigit() else c for c in text)
    elif style == "zero_width" and len(text) > 1:
        cut = draw(st.integers(1, len(text) - 1))
        text = text[:cut] + "​" + text[cut:]
    return text, {_value(v) for v in values}


def _allowed_by(tool_numbers) -> set[str]:
    """The rule, written out: a tool number adds its value only when it has one reading."""
    return {v for _, values in tool_numbers if len(values) == 1 for v in values}


@given(reply=_written_numbers(), tool=st.lists(st.one_of(_written_numbers(), st.just(None)), max_size=3))
@example(reply=("49.00", {"49"}), tool=[("49", {"49"})])
@example(reply=("１，０００", {"1", "1000"}), tool=[("1000", {"1000"}), ("1", {"1"})])
# A tool number with two readings adds nothing: tool 1.001, reply 1001 is blocked.
@example(reply=("1001", {"1001"}), tool=[("1.001", {"1.001", "1001"})])
# A reply number with two readings needs both: tool 1001 alone does not allow "1,001" (1001 or 1.001).
@example(reply=("1,001", {"1.001", "1001"}), tool=[("1001", {"1001"})])
# The tool's "1.0010" is 1.001, not 1001: a guard that read its own allowed list again would add 1001.
@example(reply=("1,001", {"1.001", "1001"}), tool=[("1.0010", {"1.001"})])
@PROPERTY
def test_asi09_property_guard_allows_a_number_only_when_every_reading_was_returned(reply, tool):
    # None in `tool` stands for the reply's own spelling returned by the tool.
    tool = [reply if entry is None else entry for entry in tool]
    text, readings = reply
    sentence = f"Your meter number is {text}"
    returned = numbers_in(" ".join(t for t, _ in tool))
    assert returned == _allowed_by(tool)
    # Allowed exactly when every reading of the reply's number is a value a tool gave plainly.
    # So "49.00" is fine when 49 came back, full-width digits too, and "1,000" needs both 1 and 1000.
    assert (guard_reply(sentence, returned) == sentence) == (readings <= returned)


def test_asi09_agent_blocks_a_number_no_tool_returned(settings, admin, as_role):
    add_ticket(admin, 111, 1001, "CALL lookup_account {}\nSAY Your meter number is 4711.")
    assert make_agent(settings, as_role).handle_ticket(111) == SAFE_REPLY
