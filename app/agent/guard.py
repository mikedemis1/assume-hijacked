"""Replies must not promise money (Moffatt v. Air Canada, 2024 BCCRT 149).

The rule is "numbers only from data". A reply may contain a digit number only if a tool returned it in
this conversation. Anything else is replaced by SAFE_REPLY (fail closed). A reply is blocked when:

1. it has a letter that is not Latin or Greek, or a word that mixes Latin and Greek letters
   (lookalikes: Cyrillic "е", Greek "ε" inside "Credit"). Category: script_mix.
2. it has a currency symbol (any Unicode category Sc: $ € £ ¥ ₹ ₽ ¢ ₠ ...) or a currency word as a
   substring (eur, ευρ, usd, dollar, buck, quid, pound, gbp, cent, λεπτ), so EUR49 and 49EUR count.
   Category: currency.
3. it has an English or Greek number word for 2-100 (always, with or without a verb; one-word
   compounds like "fortynine" and "σαρανταεννιά" too). "one", "ένα", "μία" and zero are left alone.
   Category: number_word.
4. it has money wording (credit, refund, back, off, pay, balance, πίσω, επιστροφ ...), with or without
   a number: "your credit has been approved" is a promise too. Category: money_wording.
5. it has a number (digits) that is not in `allowed_numbers`. Category: unapproved_number.

How text is compared. Before any matching the text is folded: Unicode NFKC (full-width digits and
ligatures become plain), zero-width and other format characters removed, accents removed, case folded,
and a space put between a digit and a letter ("10off" -> "10 off"). So "ΠΊΣΩ", "Πίσω" and "πισω" are
the same word. The original text is what goes out when the reply is allowed.

How numbers are compared. A number token is digits with optional "." or "," separators. Its value is
compared as a number, not as text, so "49", "49.00" and "49,00" are the same. A single separator
followed by exactly three digits ("1,000") is ambiguous (1 or 1000): the reply is only allowed if
BOTH readings are allowed. Several separators are a thousands grouping only when every group after
the first has three digits ("1.000,50"); otherwise each part is its own number (dates, versions).

Fail closed on the tool side too. The numbers a reply may repeat come from `numbers_in` on a tool
result, and a tool number that is ambiguous ("1.001", "1,000") adds NOTHING: we cannot know which
value the tool meant, and adding both would let the reply say a value the tool never returned
(tool "1.001", reply "1001"). `block_reason` uses the allowed set as it is and does not read it again.
So a reply is allowed only if every reading of each number in it is a value some tool number
unambiguously gave, and an honest reply that repeats an ambiguous tool number gets SAFE_REPLY.

Limits. Word lists (number words, currency words, money verbs) can never be complete: a spelling or
word nobody listed gets through. The robust fix is structured or template replies, not a better list.
The guard also cannot tell what an allowed number means: if a tool returned "10" (Patision 10), a
reply may still repeat "10" in a misleading way ("reduced by 10") unless it matches a rule above.
The word lists block some harmless text (central, recently, "σε 5 λεπτά", "call us back", "your
balance"); that is the price of failing closed. A reply about money is for a person to write.
"""

from __future__ import annotations

import re
import unicodedata

CURRENCY_WORD = re.compile(r"eur|ευρ|usd|dollar|buck|quid|pound|gbp|cent|λεπτ")
MONEY_WORD = re.compile(
    r"credit|refund|rebate|reimburs|compensat|discount|deduct|waive|knock|balance|back|"
    r"payment|payout|\b(?:off|pay|paid|owe|owed|add|added)\b|"
    r"πισω|επιστρ|πιστωσ|αποζημ|εκπτωσ|εξοφλ|χρεωσ|υπολοιπ|πληρω"
)
# 2-100 and a bit beyond. Folded forms: no accents, final sigma is plain sigma (τρεισ, not τρεις).
_EN_SMALL = (
    "two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen sixteen "
    "seventeen eighteen nineteen"
).split()
_GR_SMALL = (
    "δυο τρια τρεισ τεσσερα τεσσερισ τεσσαρα τεσσαρισ πεντε εξι επτα εφτα οκτω οχτω εννια εννεα "
    "ενδεκα δωδεκα"
).split()
NUMBER_WORD = re.compile(
    r"\b(?:" + "|".join(_EN_SMALL + _GR_SMALL) + r")\b"
    # Tens, hundreds and thousands match as prefixes: fortynine, σαρανταεννια, δεκαπεντε.
    r"|\b(?:twenty|thirty|forty|fourty|fifty|sixty|seventy|eighty|ninety|hundred|thousand|million)\w*"
    r"|\b(?:δεκα|εικοσ|τριαντ|σαραντ|πενηντ|εξηντ|εβδομηντ|ογδοντ|ενενηντ|εκατο|διακοσ|τριακοσ"
    r"|τετρακοσ|πεντακοσ|εξακοσ|επτακοσ|οκτακοσ|εννιακοσ|χιλι)\w*"
)
NUMBER = re.compile(r"\d+(?:[.,]\d+)*")
WORD = re.compile(r"[^\W\d_]+")
# Claims nothing: the blocked reply may have been about an action that never happened.
SAFE_REPLY = "Thank you. A colleague will check this and reply to you."


def _fold(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = "".join(c for c in text if unicodedata.category(c) != "Cf")
    text = unicodedata.normalize("NFD", text)
    text = "".join(c for c in text if unicodedata.category(c) != "Mn").casefold()
    return re.sub(r"(?<=\d)(?=[^\W\d_])|(?<=[^\W\d_])(?=\d)", " ", text)


def _script(char: str) -> str:
    name = unicodedata.name(char, "")
    return "latin" if name.startswith("LATIN") else "greek" if name.startswith("GREEK") else "other"


def _odd_script(folded: str) -> bool:
    """A letter that is not Latin or Greek, or one word with both (lookalike letters)."""
    for word in WORD.findall(folded):
        scripts = {_script(c) for c in word}
        if "other" in scripts or len(scripts) > 1:
            return True
    return False


def _canon(integer: str, fraction: str = "") -> str:
    """'049' + '50' -> '49.5'. String based, so there is no precision limit."""
    integer = "".join(str(unicodedata.digit(c)) for c in integer).lstrip("0") or "0"
    fraction = "".join(str(unicodedata.digit(c)) for c in fraction).rstrip("0")
    return integer + ("." + fraction if fraction else "")


def _grouped(parts: list[str]) -> bool:
    return 1 <= len(parts[0]) <= 3 and all(len(p) == 3 for p in parts[1:])


def _readings(token: str) -> frozenset[str]:
    """The values a number token can mean. A reply is allowed only if all of them are allowed."""
    seps = re.findall(r"[.,]", token)
    parts = re.split(r"[.,]", token)
    if not seps:
        return frozenset({_canon(token)})
    if len(seps) == 1:
        values = {_canon(parts[0], parts[1])}
        if _grouped(parts) and parts[0][0] != "0":
            values.add(_canon(parts[0] + parts[1]))
        return frozenset(values)
    if len(set(seps)) == 1 and _grouped(parts):
        return frozenset({_canon("".join(parts))})
    if len(set(seps[:-1])) == 1 and seps[-1] != seps[0] and _grouped(parts[:-1]):
        return frozenset({_canon("".join(parts[:-1]), parts[-1])})
    return frozenset(_canon(p) for p in parts)


def _ambiguous(token: str) -> bool:
    """One separator and exactly three digits after it ("1,000"): two values, 1 and 1000."""
    return len(re.findall(r"[.,]", token)) == 1 and len(_readings(token)) == 2


def numbers_in(text: str) -> set[str]:
    """The values of the numbers in `text` that mean one thing, as canonical strings ('49.00' -> '49').
    A number with two readings ("1,000") is left out: see "Fail closed on the tool side" above."""
    return {value for token in NUMBER.findall(_fold(text)) if not _ambiguous(token) for value in _readings(token)}


def block_reason(text: str, allowed_numbers: set[str]) -> str | None:
    """None if the reply may go out, else the category that blocked it (see the module docstring)."""
    folded = _fold(text)
    if _odd_script(folded):
        return "script_mix"
    if CURRENCY_WORD.search(folded) or any(unicodedata.category(c) == "Sc" for c in folded):
        return "currency"
    if NUMBER_WORD.search(folded):
        return "number_word"
    if MONEY_WORD.search(folded):
        return "money_wording"
    for token in NUMBER.findall(folded):
        if not _readings(token) <= allowed_numbers:
            return "unapproved_number"
    return None


def guard_reply(text: str, allowed_numbers: set[str]) -> str:
    return SAFE_REPLY if block_reason(text, allowed_numbers) else text
