import json

import pytest
from hypothesis import assume, example, given, settings as hypothesis_settings, strategies as st

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
_arg_name = st.one_of(st.sampled_from(_ARG_NAMES), st.text(max_size=12))
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


@given(tool=st.text(max_size=20).filter(lambda name: name not in ALLOWED_ARGS), sent=_arguments)
@PROPERTY
def test_asi01_property_agent_sends_nothing_for_a_tool_not_in_the_table(tool, sent):
    assert Agent(ScriptedLLM(), RecordingGateway(""))._safe_args(tool, sent, LEASE) == (None, [])


# One readable example per way a reply can promise money; the properties below hold the rule for
# any amount, in any of these shapes.
@pytest.mark.parametrize("text", ["We credited €49", "We knocked 49 off your bill"])
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


@given(template=st.sampled_from(_PROMISES), amount=_amounts, returned=_amounts, before=_filler, after=_filler)
@example(template="We credited €{a}", amount="49", returned="10", before="", after="")
@example(template="EUR{a} back", amount="49.00", returned="10", before="", after="")
@PROPERTY
def test_asi09_property_guard_blocks_an_amount_no_tool_returned(template, amount, returned, before, after):
    assume(numbers_in(amount).isdisjoint(numbers_in(returned)))
    text = f"{before} {template.format(a=amount)} {after}"
    assert guard_reply(text, numbers_in(returned)) == SAFE_REPLY


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


@given(number=st.integers(0, 999_999), other=st.integers(0, 999_999))
@PROPERTY
def test_asi09_property_guard_allows_exactly_the_numbers_a_tool_returned(number, other):
    # The other half of the rule: the guard is not just blocking everything with a digit in it.
    reply = f"Your meter number is {number}"
    assert guard_reply(reply, numbers_in(json.dumps({"meter": number}))) == reply
    assume(number != other)
    assert guard_reply(reply, numbers_in(json.dumps({"meter": other}))) == SAFE_REPLY


def test_asi09_agent_blocks_a_number_no_tool_returned(settings, admin, as_role):
    add_ticket(admin, 111, 1001, "CALL lookup_account {}\nSAY Your meter number is 4711.")
    assert make_agent(settings, as_role).handle_ticket(111) == SAFE_REPLY
