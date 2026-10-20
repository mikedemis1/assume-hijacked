"""The account card (app/demo/card.py): presentation of a reply only; odd input stays plain text."""

import json

import pytest

from app.demo.card import account_card

FULL = {"name": "Eleni Papadopoulou", "tariff": "G1 residential", "status": "active", "address": "Patision 10, Athens"}


def test_a_reply_with_a_flat_account_object_becomes_a_card_in_field_order():
    card = account_card("Here is your account: " + json.dumps(FULL, indent=2))
    assert card["intro"] == "Here is your account:"
    assert card["rows"] == [["Name", "Eleni Papadopoulou"], ["Tariff", "G1 residential"], ["Status", "active"],
                            ["Address", "Patision 10, Athens"]]


def test_a_bare_object_is_a_card_without_an_intro():
    assert account_card(json.dumps({"tariff": "G1"})) == {"intro": "", "rows": [["Tariff", "G1"]]}


@pytest.mark.parametrize("reply", [
    None, "", "Your tariff is G1.", "Here you go {not json", "{}", "[1, 2]", '{"name": 5}', '{"name": ""}',
    '{"name": "x", "phone": "+30 690 000 1001"}',            # a key outside the allow-list
    '{"name": {"first": "x"}}', '{"name": ["x"]}',            # nested
    "Hello {\"name\": \"x\"} and more",                    # text after the object
    "[" * 5000 + "]" * 5000,
    '{"name": "' + "x" * 201 + '"}',
    "x" * 3000 + '{"name": "x"}',
    "a long first line of talk " * 10 + '{"name": "x"}',
    "line one\nline two {\"name\": \"x\"}",
    '{"name": "x"' + ', "name": "y"' * 3 + ", \"zzz\": 1}",
    5, ["{}"],
])
def test_anything_else_stays_plain_text(reply):
    assert account_card(reply) is None


def test_values_are_strings_kept_as_they_are_for_textcontent():
    card = account_card('{"name": "<b>x</b>"}')
    assert card["rows"] == [["Name", "<b>x</b>"]]    # the page puts it in with textContent, never as HTML


# A guard-evading promise spelled with \\u escapes: the guard saw the raw text, the card must not decode it.
@pytest.mark.parametrize("reply", [
    'Here is your account: {"name": "Maria Ioannou", "status": "r\\u1ebdfund of 20 \\u20ac approv\\u1ebdd, cr\\u1ebbdit on your n\\u1ebdxt b\\u1ecbll"}',
    '{"status": "r\\u1ebdfund approv\\u1ebdd"}',
    '{"name": "Eleni \\"quoted\\""}',                    # any backslash, even a harmless one
    '{"name": "a\\u0041", "status": "aA"}',                   # decodes to text that also appears raw: still an escape
    '{"name": "a", "name": "b"}',                            # a repeated key
    '{"tariff": "G1", "status": "active", "tariff": "G2"}',
])
def test_escapes_and_repeated_keys_are_no_card(reply):
    assert account_card(reply) is None


def test_the_honest_card_still_renders():
    assert account_card('Here is your account: {"name": "Maria Ioannou", "status": "active"}') == {
        "intro": "Here is your account:", "rows": [["Name", "Maria Ioannou"], ["Status", "active"]]}
